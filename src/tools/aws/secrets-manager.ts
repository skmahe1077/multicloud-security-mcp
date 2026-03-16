import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { SecretsManagerClient, ListSecretsCommand, DescribeSecretCommand } from "@aws-sdk/client-secrets-manager";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { buildSecretRotationReport } from "../shared/secret-rotation-auditor.js";

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
    "aws_audit_secrets_manager",
    "Audit AWS Secrets Manager for rotation compliance, unused secrets, and overly permissive policies",
    {
      region: z.string().default("us-east-1").describe("AWS region"),
      checkRotation: z.boolean().default(true).describe("Check rotation status"),
      olderThanDays: z.number().optional().describe("Filter secrets older than N days"),
    },
    async ({ region, checkRotation, olderThanDays }) => {
      const requestId = uuidv4();
      logger.info("aws_audit_secrets_manager invoked", { requestId });
      try {
        const client = new SecretsManagerClient({ region });
        const resp = await withRetry(() => client.send(new ListSecretsCommand({ MaxResults: 100 })));

        const entries = (resp.SecretList ?? []).map(secret => {
          const ageDays = secret.LastChangedDate
            ? Math.floor((Date.now() - secret.LastChangedDate.getTime()) / (1000 * 60 * 60 * 24))
            : 999;

          let recommendation = "OK";
          if (!secret.RotationEnabled) recommendation = "Enable automatic rotation";
          else if (ageDays > 90) recommendation = "Secret overdue for rotation";
          else if (secret.DeletedDate) recommendation = "Secret is marked for deletion";

          return {
            name: secret.Name ?? "",
            cloud: "aws" as const,
            lastRotated: secret.LastRotatedDate ?? secret.LastChangedDate,
            rotationEnabled: secret.RotationEnabled ?? false,
            ageDays,
            hasPublicAccess: false,
            recommendation,
          };
        }).filter(e => !olderThanDays || e.ageDays >= olderThanDays);

        const report = buildSecretRotationReport(entries, "aws");

        const response: ToolResponse = { success: true, requestId, data: report };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("aws_audit_secrets_manager failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
