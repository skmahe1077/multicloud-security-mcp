import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import {
  KMSClient,
  ListKeysCommand,
  DescribeKeyCommand,
  GetKeyRotationStatusCommand,
  GetKeyPolicyCommand,
} from "@aws-sdk/client-kms";
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
    "aws_audit_kms_keys",
    "Audit AWS KMS keys for rotation, public policies, and pending deletion status",
    {
      region: z.string().default("us-east-1").describe("AWS region"),
      checkRotation: z.boolean().default(true).describe("Check key rotation status"),
      checkPublicPolicy: z.boolean().default(true).describe("Check for public key policies"),
    },
    async ({ region, checkRotation, checkPublicPolicy }) => {
      const requestId = uuidv4();
      logger.info("aws_audit_kms_keys invoked", { requestId });
      try {
        const client = new KMSClient({ region });
        const keysResp = await withRetry(() => client.send(new ListKeysCommand({ Limit: 100 })));
        const findings: NormalizedFinding[] = [];

        for (const key of keysResp.Keys ?? []) {
          const keyId = key.KeyId ?? "";
          const desc = await withRetry(() => client.send(new DescribeKeyCommand({ KeyId: keyId })));
          const meta = desc.KeyMetadata;
          if (!meta || meta.KeyManager === "AWS") continue;

          const issues: string[] = [];

          if (checkRotation) {
            try {
              const rotation = await withRetry(() => client.send(new GetKeyRotationStatusCommand({ KeyId: keyId })));
              if (!rotation.KeyRotationEnabled) issues.push("Key rotation not enabled");
            } catch { /* some key types don't support rotation check */ }
          }

          if (checkPublicPolicy) {
            try {
              const policy = await withRetry(() => client.send(new GetKeyPolicyCommand({ KeyId: keyId, PolicyName: "default" })));
              const policyDoc = policy.Policy ?? "";
              if (policyDoc.includes('"*"') && policyDoc.includes('"AWS"')) {
                issues.push("Key policy may allow public access");
              }
            } catch { /* policy read may fail */ }
          }

          if (meta.KeyState === "PendingDeletion") {
            issues.push("Key is pending deletion — verify no resources depend on it");
          }

          if (issues.length > 0) {
            const finding: NormalizedFinding = {
              id: `kms-${keyId}`,
              cloud: "aws",
              service: "kms",
              category: "SECRET_RISK",
              severity: issues.some(i => i.includes("public")) ? "HIGH" : "MEDIUM",
              title: `KMS Key Issue: ${meta.Description ?? keyId}`,
              description: issues.join("; "),
              resourceId: meta.Arn ?? keyId,
              resourceType: "AWS::KMS::Key",
              region,
              remediationSteps: issues.map(i => i.includes("rotation") ? "Enable automatic key rotation" : i.includes("public") ? "Restrict the key policy" : "Review key usage"),
              complianceFrameworks: ["CIS", "NIST"],
              riskScore: 0,
              firstDetected: meta.CreationDate ?? new Date(),
              lastSeen: new Date(),
              rawFinding: { keyMetadata: meta, issues },
            };
            finding.riskScore = computeRiskScore(finding);
            findings.push(finding);
          }
        }

        const response: ToolResponse<NormalizedFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("aws_audit_kms_keys failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
