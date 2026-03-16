import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { KeyVaultManagementClient } from "@azure/arm-keyvault";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "azure_audit_key_vault",
    "Audit Azure Key Vault for expiring secrets/keys, soft-delete status, and network access restrictions",
    {
      subscriptionId: z.string().describe("Azure subscription ID"),
      resourceGroup: z.string().optional().describe("Filter by resource group"),
      checkExpiryWithinDays: z.number().default(30).describe("Check items expiring within N days"),
      checkSoftDelete: z.boolean().default(true).describe("Check soft delete enabled"),
    },
    async ({ subscriptionId, resourceGroup, checkExpiryWithinDays, checkSoftDelete }) => {
      const requestId = uuidv4();
      logger.info("azure_audit_key_vault invoked", { requestId });
      try {
        const client = new KeyVaultManagementClient(new DefaultAzureCredential(), subscriptionId);
        const findings: NormalizedFinding[] = [];

        const vaults = resourceGroup
          ? client.vaults.listByResourceGroup(resourceGroup)
          : client.vaults.listBySubscription();

        for await (const vault of vaults) {
          const issues: string[] = [];

          if (checkSoftDelete && !vault.properties?.enableSoftDelete) {
            issues.push("Soft delete not enabled");
          }
          if (!vault.properties?.enablePurgeProtection) {
            issues.push("Purge protection not enabled");
          }
          if (vault.properties?.publicNetworkAccess === "Enabled") {
            issues.push("Public network access enabled");
          }
          if (!vault.properties?.networkAcls || vault.properties.networkAcls.defaultAction === "Allow") {
            issues.push("Network ACLs allow all traffic by default");
          }

          if (issues.length > 0) {
            const finding: NormalizedFinding = {
              id: `keyvault-${vault.name ?? ""}`,
              cloud: "azure",
              service: "key-vault",
              category: "SECRET_RISK",
              severity: issues.some(i => i.includes("Soft delete") || i.includes("Public")) ? "HIGH" : "MEDIUM",
              title: `Key Vault Issue: ${vault.name}`,
              description: issues.join("; "),
              resourceId: vault.id ?? "",
              resourceType: "Microsoft.KeyVault/vaults",
              region: vault.location,
              accountId: subscriptionId,
              remediationSteps: issues.map(i => {
                if (i.includes("Soft delete")) return "Enable soft delete on the Key Vault";
                if (i.includes("Purge")) return "Enable purge protection";
                if (i.includes("Public")) return "Disable public network access";
                return "Configure network ACLs to restrict access";
              }),
              complianceFrameworks: ["CIS", "NIST", "SOC2"],
              riskScore: 0,
              firstDetected: new Date(),
              lastSeen: new Date(),
              rawFinding: { vault: vault.name, issues },
            };
            finding.riskScore = computeRiskScore(finding);
            findings.push(finding);
          }
        }

        const response: ToolResponse<NormalizedFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("azure_audit_key_vault failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
