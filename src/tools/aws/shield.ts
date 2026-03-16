import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { ShieldClient, ListAttacksCommand } from "@aws-sdk/client-shield";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { NetworkFinding } from "../../types/network.js";
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
    "aws_get_shield_attacks",
    "Get AWS Shield Advanced DDoS attack events with attack vectors, peak traffic, and mitigations",
    {
      resourceArn: z.string().optional().describe("Resource ARN to filter attacks"),
      startTime: z.string().describe("Start time (ISO 8601)"),
      endTime: z.string().describe("End time (ISO 8601)"),
    },
    async ({ resourceArn, startTime, endTime }) => {
      const requestId = uuidv4();
      logger.info("aws_get_shield_attacks invoked", { requestId });
      try {
        const client = new ShieldClient({ region: "us-east-1" });

        const params: Record<string, unknown> = {
          StartTime: { FromInclusive: new Date(startTime), ToExclusive: new Date(endTime) },
          EndTime: { FromInclusive: new Date(startTime), ToExclusive: new Date(endTime) },
        };
        if (resourceArn) {
          params["ResourceArns"] = [resourceArn];
        }

        const resp = await withRetry(() => client.send(new ListAttacksCommand(params as any)));

        const findings: NetworkFinding[] = (resp.AttackSummaries ?? []).map(attack => {
          const finding: NetworkFinding = {
            id: attack.AttackId ?? "",
            cloud: "aws",
            service: "shield",
            category: "NETWORK_EXPOSURE",
            severity: "HIGH",
            title: `DDoS Attack: ${attack.AttackId}`,
            description: `DDoS attack on ${attack.ResourceArn ?? "unknown resource"} with ${attack.AttackVectors?.map(v => v.VectorType).join(", ") ?? "unknown"} vectors`,
            resourceId: attack.ResourceArn ?? "",
            resourceType: "Shield Protected Resource",
            remediationSteps: ["Review Shield Advanced protection", "Verify WAF rules", "Contact AWS Shield Response Team"],
            complianceFrameworks: [],
            riskScore: 0,
            firstDetected: attack.StartTime ?? new Date(),
            lastSeen: attack.EndTime ?? new Date(),
            rawFinding: attack,
            ddosAttackType: attack.AttackVectors?.map(v => v.VectorType).join(", "),
          };
          finding.riskScore = computeRiskScore(finding);
          return finding;
        });

        const response: ToolResponse<NetworkFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("aws_get_shield_attacks failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
