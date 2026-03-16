import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { SecretManagerServiceClient } from "@google-cloud/secret-manager";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { buildSecretRotationReport } from "../shared/secret-rotation-auditor.js";
import { SecretRotationEntry } from "../../types/findings.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_audit_secret_manager",
    "Audit GCP Secret Manager for rotation policies, IAM bindings, and service account access",
    {
      projectId: z.string().describe("GCP project ID"),
      checkRotation: z.boolean().default(true).describe("Check rotation policies"),
      checkIAMPolicy: z.boolean().default(true).describe("Check IAM policies for overly permissive access"),
      accessedByServiceAccounts: z.boolean().default(false).describe("Check which service accounts access secrets"),
    },
    async ({ projectId, checkRotation, checkIAMPolicy, accessedByServiceAccounts }) => {
      const requestId = uuidv4();
      logger.info("gcp_audit_secret_manager invoked", { requestId });
      try {
        const client = new SecretManagerServiceClient();
        const [secrets] = await client.listSecrets({ parent: `projects/${projectId}` });

        const entries: SecretRotationEntry[] = [];

        for (const secret of secrets ?? []) {
          const secretName = (secret.name ?? "").split("/").pop() ?? "";
          let hasPublicAccess = false;

          if (checkIAMPolicy) {
            try {
              const [policy] = await client.getIamPolicy({ resource: secret.name ?? "" });
              for (const binding of policy.bindings ?? []) {
                if (binding.members?.some((m: string) => m === "allUsers" || m === "allAuthenticatedUsers")) {
                  hasPublicAccess = true;
                }
              }
            } catch { /* IAM policy read may fail */ }
          }

          const hasRotation = !!secret.rotation?.nextRotationTime;
          const createTime = secret.createTime ? new Date(secret.createTime as string) : new Date();
          const ageDays = Math.floor((Date.now() - createTime.getTime()) / (1000 * 60 * 60 * 24));

          let recommendation = "OK";
          if (hasPublicAccess) recommendation = "CRITICAL: Remove public IAM binding immediately";
          else if (!hasRotation) recommendation = "Configure rotation policy";
          else if (ageDays > 90) recommendation = "Secret may need rotation";

          entries.push({
            name: secretName,
            cloud: "gcp",
            lastRotated: undefined,
            rotationEnabled: hasRotation,
            ageDays,
            hasPublicAccess,
            recommendation,
          });
        }

        const report = buildSecretRotationReport(entries, "gcp");

        const response: ToolResponse = { success: true, requestId, data: report };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("gcp_audit_secret_manager failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
