import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { PolicyInsightsClient } from "@azure/arm-policyinsights";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { ToolResponse, ComplianceSummary, ComplianceFailure } from "../../types/findings.js";

async function withRetry<T>(fn: () => Promise<T>, retries = 5): Promise<T> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try { return await fn(); } catch (error: unknown) {
      const err = error as { statusCode?: number };
      if (attempt < retries && err.statusCode === 429) {
        await new Promise((r) => setTimeout(r, Math.min(100 * Math.pow(2, attempt) + Math.random() * 100, 10000)));
        continue;
      }
      throw error;
    }
  }
  throw new Error("Retry exhausted");
}

export function register(server: McpServer): void {
  server.tool(
    "azure_check_policy_compliance",
    "Check Azure Policy compliance for CIS, NIST, ISO27001 initiatives per subscription",
    {
      subscriptionId: z.string().describe("Azure subscription ID"),
      initiativeName: z.enum(["CIS", "NIST", "ISO27001"]).describe("Compliance initiative"),
      resourceGroup: z.string().optional().describe("Filter by resource group"),
    },
    async ({ subscriptionId, initiativeName, resourceGroup }) => {
      const requestId = uuidv4();
      logger.info("azure_check_policy_compliance invoked", { requestId, initiativeName });
      try {
        const client = new PolicyInsightsClient(new DefaultAzureCredential(), subscriptionId);
        let passed = 0, failed = 0, total = 0;
        const failures: ComplianceFailure[] = [];

        const iterator = resourceGroup
          ? client.policyStates.listQueryResultsForResourceGroup("latest", subscriptionId, resourceGroup)
          : client.policyStates.listQueryResultsForSubscription("latest", subscriptionId);

        for await (const state of iterator) {
          total++;
          if (state.complianceState === "Compliant") {
            passed++;
          } else if (state.complianceState === "NonCompliant") {
            failed++;
            failures.push({
              ruleId: state.policyDefinitionName ?? "",
              ruleName: state.policyDefinitionAction ?? "",
              resourceId: state.resourceId ?? "",
              resourceType: state.resourceType ?? "",
              region: state.resourceLocation ?? undefined,
            });
          }
        }

        const summary: ComplianceSummary = {
          cloud: "azure",
          framework: initiativeName,
          totalChecks: total,
          passedChecks: passed,
          failedChecks: failed,
          unknownChecks: total - passed - failed,
          failingResources: failures.slice(0, 100),
          evaluatedAt: new Date(),
        };

        const response: ToolResponse<ComplianceSummary> = { success: true, requestId, data: summary };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("azure_check_policy_compliance failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
