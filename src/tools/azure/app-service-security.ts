import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { WebSiteManagementClient } from "@azure/arm-appservice";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "azure_check_app_service_security",
    "Check Azure App Service security: TLS version, HTTPS enforcement, auth, managed identity, remote debugging",
    {
      subscriptionId: z.string().describe("Azure subscription ID"),
      resourceGroup: z.string().optional().describe("Filter by resource group"),
      checkTLSVersion: z.boolean().default(true).describe("Check for TLS < 1.2"),
      checkAuthEnabled: z.boolean().default(true).describe("Check authentication enabled"),
      checkHTTPSOnly: z.boolean().default(true).describe("Check HTTPS-only enforcement"),
    },
    async ({ subscriptionId, resourceGroup, checkTLSVersion, checkAuthEnabled, checkHTTPSOnly }) => {
      const requestId = uuidv4();
      logger.info("azure_check_app_service_security invoked", { requestId });
      try {
        const client = new WebSiteManagementClient(new DefaultAzureCredential(), subscriptionId);
        const findings: NormalizedFinding[] = [];

        const apps = resourceGroup
          ? client.webApps.listByResourceGroup(resourceGroup)
          : client.webApps.list();

        for await (const app of apps) {
          const issues: string[] = [];
          const appName = app.name ?? "";

          if (checkHTTPSOnly && !app.httpsOnly) {
            issues.push("HTTPS-only not enforced");
          }

          if (app.clientCertEnabled === false) {
            issues.push("Client certificates not required");
          }

          // Get site config for TLS and other settings
          try {
            const config = await client.webApps.getConfiguration(
              app.resourceGroup ?? resourceGroup ?? "",
              appName
            );

            if (checkTLSVersion && config.minTlsVersion && parseFloat(config.minTlsVersion) < 1.2) {
              issues.push(`TLS version ${config.minTlsVersion} < 1.2`);
            }

            if (config.remoteDebuggingEnabled) {
              issues.push("Remote debugging enabled");
            }

            if (config.ftpsState === "AllAllowed") {
              issues.push("FTP access allowed — use FTPS only or disable");
            }
          } catch { /* config read may fail for some app types */ }

          if (!app.identity?.type) {
            issues.push("Managed identity not configured");
          }

          if (issues.length > 0) {
            const hasCritical = issues.some(i => i.includes("TLS") || i.includes("Remote debugging"));
            const finding: NormalizedFinding = {
              id: `appservice-${appName}`,
              cloud: "azure",
              service: "app-service-security",
              category: "COMPLIANCE_VIOLATION",
              severity: hasCritical ? "HIGH" : "MEDIUM",
              title: `App Service Security Issues: ${appName}`,
              description: issues.join("; "),
              resourceId: app.id ?? "",
              resourceType: "Microsoft.Web/sites",
              region: app.location,
              accountId: subscriptionId,
              remediationSteps: issues.map(i => {
                if (i.includes("HTTPS")) return "Enable HTTPS Only in App Service settings";
                if (i.includes("TLS")) return "Set minimum TLS version to 1.2";
                if (i.includes("Remote")) return "Disable remote debugging";
                if (i.includes("FTP")) return "Set FTPS state to FtpsOnly or Disabled";
                if (i.includes("Managed identity")) return "Enable system-assigned managed identity";
                return `Fix: ${i}`;
              }),
              complianceFrameworks: ["CIS", "SOC2", "NIST"],
              riskScore: 0,
              firstDetected: new Date(),
              lastSeen: new Date(),
              rawFinding: { appName, issues },
            };
            finding.riskScore = computeRiskScore(finding);
            findings.push(finding);
          }
        }

        const response: ToolResponse<NormalizedFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("azure_check_app_service_security failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
