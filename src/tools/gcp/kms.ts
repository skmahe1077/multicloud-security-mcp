import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { KeyManagementServiceClient } from "@google-cloud/kms";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_audit_kms_keys",
    "Audit GCP Cloud KMS keys for rotation, public IAM bindings, and pending destruction",
    {
      projectId: z.string().describe("GCP project ID"),
      location: z.string().optional().describe("KMS location (default: global)"),
      checkRotation: z.boolean().default(true).describe("Check key rotation status"),
      maxRotationPeriodDays: z.number().default(90).describe("Maximum rotation period in days"),
    },
    async ({ projectId, location, checkRotation, maxRotationPeriodDays }) => {
      const requestId = uuidv4();
      logger.info("gcp_audit_kms_keys invoked", { requestId });
      try {
        const client = new KeyManagementServiceClient();
        const findings: NormalizedFinding[] = [];
        const loc = location ?? "global";

        // List key rings
        const [keyRings] = await client.listKeyRings({ parent: `projects/${projectId}/locations/${loc}` });

        for (const ring of keyRings ?? []) {
          const [keys] = await client.listCryptoKeys({ parent: ring.name ?? "" });

          for (const key of keys ?? []) {
            const issues: string[] = [];

            if (checkRotation) {
              if (!key.rotationPeriod) {
                issues.push("No rotation period configured");
              } else {
                const periodSeconds = parseInt(key.rotationPeriod.seconds?.toString() ?? "0");
                const periodDays = periodSeconds / 86400;
                if (periodDays > maxRotationPeriodDays) {
                  issues.push(`Rotation period (${Math.round(periodDays)} days) exceeds maximum (${maxRotationPeriodDays} days)`);
                }
              }
            }

            if (key.primary?.state === "DESTROY_SCHEDULED") {
              issues.push("Primary key version scheduled for destruction");
            }

            // Check IAM policy for public access
            try {
              const [policy] = await client.getIamPolicy({ resource: key.name ?? "" } as any);
              for (const binding of policy.bindings ?? []) {
                if (binding.members?.some(m => m === "allUsers" || m === "allAuthenticatedUsers")) {
                  issues.push(`Public IAM binding: ${binding.role} granted to ${binding.members.join(", ")}`);
                }
              }
            } catch { /* IAM policy read may fail */ }

            if (issues.length > 0) {
              const finding: NormalizedFinding = {
                id: `gcp-kms-${key.name}`,
                cloud: "gcp",
                service: "kms",
                category: "SECRET_RISK",
                severity: issues.some(i => i.includes("Public")) ? "CRITICAL" : "MEDIUM",
                title: `KMS Key Issue: ${key.name?.split("/").pop() ?? "Unknown"}`,
                description: issues.join("; "),
                resourceId: key.name ?? "",
                resourceType: "cloudkms.cryptoKey",
                accountId: projectId,
                remediationSteps: issues.map(i => {
                  if (i.includes("rotation")) return "Configure automatic key rotation";
                  if (i.includes("Public")) return "Remove public IAM bindings immediately";
                  return "Review key configuration";
                }),
                complianceFrameworks: ["CIS", "NIST", "SOC2"],
                riskScore: 0,
                firstDetected: new Date(key.createTime as string ?? Date.now()),
                lastSeen: new Date(),
                rawFinding: { key: key.name, issues },
              };
              finding.riskScore = computeRiskScore(finding);
              findings.push(finding);
            }
          }
        }

        const response: ToolResponse<NormalizedFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("gcp_audit_kms_keys failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
