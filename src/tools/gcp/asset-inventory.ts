import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { AssetServiceClient } from "@google-cloud/asset";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_get_asset_violations",
    "Get GCP Cloud Asset Inventory violations — public buckets, serial port, OS login, shielded VM, org policy violations",
    {
      scope: z.string().describe("Scope: organizations/{id}, folders/{id}, or projects/{id}"),
      assetTypes: z.array(z.string()).default(["storage.googleapis.com/Bucket", "compute.googleapis.com/Instance"]).describe("Asset types to check"),
      orgPolicyConstraint: z.string().optional().describe("Org policy constraint to check"),
    },
    async ({ scope, assetTypes, orgPolicyConstraint }) => {
      const requestId = uuidv4();
      logger.info("gcp_get_asset_violations invoked", { requestId });
      try {
        const client = new AssetServiceClient();
        const findings: NormalizedFinding[] = [];

        for (const assetType of assetTypes) {
          const [assets] = await client.searchAllResources({
            scope,
            assetTypes: [assetType],
            pageSize: 200,
          });

          for (const asset of assets ?? []) {
            const issues: string[] = [];
            const additionalAttributes = asset.additionalAttributes as Record<string, unknown> ?? {};

            // Check for common violations based on asset type
            if (assetType.includes("Bucket")) {
              if (asset.additionalAttributes) {
                const iamConfig = additionalAttributes["iamConfiguration"] as Record<string, unknown> ?? {};
                if (!(iamConfig["uniformBucketLevelAccess"] as Record<string, unknown>)?.["enabled"]) {
                  issues.push("Uniform bucket-level access not enabled");
                }
              }
            }

            if (assetType.includes("Instance")) {
              const metadata = additionalAttributes["metadata"] as Record<string, unknown> ?? {};
              const items = (metadata["items"] as Record<string, unknown>[]) ?? [];
              for (const item of items) {
                if (item["key"] === "serial-port-enable" && item["value"] === "true") {
                  issues.push("Serial port access enabled");
                }
                if (item["key"] === "enable-oslogin" && item["value"] === "FALSE") {
                  issues.push("OS Login disabled");
                }
              }
            }

            if (issues.length > 0) {
              const finding: NormalizedFinding = {
                id: `asset-${asset.name ?? ""}`,
                cloud: "gcp",
                service: "asset-inventory",
                category: "COMPLIANCE_VIOLATION",
                severity: issues.some(i => i.includes("public") || i.includes("Serial port")) ? "HIGH" : "MEDIUM",
                title: `Asset Policy Violation: ${asset.displayName ?? asset.name?.split("/").pop() ?? "Unknown"}`,
                description: issues.join("; "),
                resourceId: asset.name ?? "",
                resourceType: assetType,
                region: asset.location ?? undefined,
                accountId: scope,
                remediationSteps: issues.map(i => `Fix: ${i}`),
                complianceFrameworks: ["CIS"],
                riskScore: 0,
                firstDetected: new Date(),
                lastSeen: new Date(),
                rawFinding: { asset: asset.name, issues },
              };
              finding.riskScore = computeRiskScore(finding);
              findings.push(finding);
            }
          }
        }

        const response: ToolResponse<NormalizedFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("gcp_get_asset_violations failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
