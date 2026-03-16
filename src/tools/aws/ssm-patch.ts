import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { SSMClient, DescribePatchGroupStateCommand, DescribeInstancePatchStatesForPatchGroupCommand } from "@aws-sdk/client-ssm";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

async function withRetry<T>(fn: () => Promise<T>, retries = 5): Promise<T> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try { return await fn(); } catch (error: unknown) {
      const err = error as { name?: string };
      if (attempt < retries && (err.name === "ThrottlingException")) {
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
    "aws_get_ssm_patch_compliance",
    "Get SSM patch compliance status for EC2 instances, including missing critical patches",
    {
      region: z.string().default("us-east-1").describe("AWS region"),
      patchGroup: z.string().optional().describe("Patch group filter"),
      complianceType: z.enum(["COMPLIANT", "NON_COMPLIANT"]).default("NON_COMPLIANT").describe("Compliance type to filter"),
    },
    async ({ region, patchGroup, complianceType }) => {
      const requestId = uuidv4();
      logger.info("aws_get_ssm_patch_compliance invoked", { requestId });
      try {
        const client = new SSMClient({ region });

        const resp = await withRetry(() => client.send(new DescribeInstancePatchStatesForPatchGroupCommand({
          PatchGroup: patchGroup ?? "default",
          MaxResults: 50,
        })));

        const findings: NormalizedFinding[] = (resp.InstancePatchStates ?? [])
          .filter(state => {
            if (complianceType === "NON_COMPLIANT") {
              return (state.MissingCount ?? 0) > 0 || (state.FailedCount ?? 0) > 0;
            }
            return (state.MissingCount ?? 0) === 0 && (state.FailedCount ?? 0) === 0;
          })
          .map(state => {
            const criticalMissing = state.UnreportedNotApplicableCount ?? 0;
            const severity = (state.MissingCount ?? 0) > 5 ? "HIGH" : (state.MissingCount ?? 0) > 0 ? "MEDIUM" : "LOW";

            const finding: NormalizedFinding = {
              id: `ssm-patch-${state.InstanceId}`,
              cloud: "aws",
              service: "ssm-patch",
              category: "VULNERABILITY",
              severity: severity as any,
              title: `Patch Non-Compliance: ${state.InstanceId}`,
              description: `Instance ${state.InstanceId} has ${state.MissingCount ?? 0} missing patches, ${state.FailedCount ?? 0} failed patches`,
              resourceId: state.InstanceId ?? "",
              resourceType: "AWS::EC2::Instance",
              region,
              remediationSteps: ["Run SSM Patch Manager to apply missing patches", "Review patch baseline configuration"],
              complianceFrameworks: ["CIS", "NIST"],
              riskScore: 0,
              firstDetected: state.OperationStartTime ?? new Date(),
              lastSeen: state.OperationEndTime ?? new Date(),
              rawFinding: {
                instanceId: state.InstanceId,
                patchGroup: state.PatchGroup,
                installedCount: state.InstalledCount,
                missingCount: state.MissingCount,
                failedCount: state.FailedCount,
                installedOtherCount: state.InstalledOtherCount,
                operation: state.Operation,
                operationStartTime: state.OperationStartTime,
                operationEndTime: state.OperationEndTime,
              },
            };
            finding.riskScore = computeRiskScore(finding);
            return finding;
          });

        const summary = {
          totalInstances: resp.InstancePatchStates?.length ?? 0,
          nonCompliant: findings.length,
          totalMissingPatches: findings.reduce((sum, f) => sum + ((f.rawFinding as any)?.missingCount ?? 0), 0),
          totalFailedPatches: findings.reduce((sum, f) => sum + ((f.rawFinding as any)?.failedCount ?? 0), 0),
        };

        const response: ToolResponse = { success: true, requestId, data: { summary, findings } };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("aws_get_ssm_patch_compliance failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
