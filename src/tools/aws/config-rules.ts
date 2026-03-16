import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import {
  ConfigServiceClient,
  GetComplianceDetailsByConfigRuleCommand,
  DescribeComplianceByConfigRuleCommand,
} from "@aws-sdk/client-config-service";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

async function withRetry<T>(fn: () => Promise<T>, retries = 5): Promise<T> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try { return await fn(); } catch (error: unknown) {
      const err = error as { name?: string };
      if (attempt < retries && (err.name === "ThrottlingException" || err.name === "TooManyRequestsException")) {
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
    "aws_list_config_violations",
    "List AWS Config rule violations with compliance details per resource",
    {
      region: z.string().default("us-east-1").describe("AWS region"),
      ruleNames: z.array(z.string()).describe("Config rule names to check"),
      compliancePack: z.string().optional().describe("Conformance pack name"),
    },
    async ({ region, ruleNames, compliancePack }) => {
      const requestId = uuidv4();
      logger.info("aws_list_config_violations invoked", { requestId, ruleNames });
      try {
        const client = new ConfigServiceClient({ region });
        const violations: NormalizedFinding[] = [];

        for (const ruleName of ruleNames) {
          const resp = await withRetry(() => client.send(new GetComplianceDetailsByConfigRuleCommand({
            ConfigRuleName: ruleName,
            ComplianceTypes: ["NON_COMPLIANT"],
            Limit: 100,
          })));

          for (const result of resp.EvaluationResults ?? []) {
            const finding: NormalizedFinding = {
              id: `config-${ruleName}-${result.EvaluationResultIdentifier?.EvaluationResultQualifier?.ResourceId ?? ""}`,
              cloud: "aws",
              service: "config-rules",
              category: "COMPLIANCE_VIOLATION",
              severity: "MEDIUM",
              title: `Config Rule Violation: ${ruleName}`,
              description: `Resource ${result.EvaluationResultIdentifier?.EvaluationResultQualifier?.ResourceId} is non-compliant with rule ${ruleName}`,
              resourceId: result.EvaluationResultIdentifier?.EvaluationResultQualifier?.ResourceId ?? "",
              resourceType: result.EvaluationResultIdentifier?.EvaluationResultQualifier?.ResourceType ?? "",
              region,
              remediationSteps: ["Review the Config rule and remediate the resource"],
              complianceFrameworks: compliancePack ? [compliancePack] : ["CIS"],
              riskScore: 0,
              firstDetected: result.ConfigRuleInvokedTime ?? new Date(),
              lastSeen: result.ResultRecordedTime ?? new Date(),
              rawFinding: result,
            };
            finding.riskScore = computeRiskScore(finding);
            violations.push(finding);
          }
        }

        const response: ToolResponse<NormalizedFinding[]> = { success: true, requestId, data: violations };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("aws_list_config_violations failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
