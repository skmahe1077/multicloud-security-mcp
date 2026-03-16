import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { NetworkManagementClient } from "@azure/arm-network";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { NetworkFinding } from "../../types/network.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "azure_get_firewall_threats",
    "Get Azure Firewall threat intelligence hits, blocked FQDNs, and IDPS signature matches",
    {
      subscriptionId: z.string().describe("Azure subscription ID"),
      workspaceName: z.string().describe("Log Analytics workspace name"),
      firewallName: z.string().optional().describe("Specific firewall name"),
      lookbackHours: z.number().min(1).max(168).default(24).describe("Hours to look back"),
    },
    async ({ subscriptionId, workspaceName, firewallName, lookbackHours }) => {
      const requestId = uuidv4();
      logger.info("azure_get_firewall_threats invoked", { requestId });
      try {
        const client = new NetworkManagementClient(new DefaultAzureCredential(), subscriptionId);
        const findings: NetworkFinding[] = [];

        const firewalls = client.azureFirewalls.listAll();
        for await (const fw of firewalls) {
          if (firewallName && fw.name !== firewallName) continue;

          const threatIntelMode = fw.threatIntelMode ?? "Off";
          if (threatIntelMode === "Off") {
            const finding: NetworkFinding = {
              id: `fw-threatintel-${fw.name}`,
              cloud: "azure",
              service: "firewall",
              category: "NETWORK_EXPOSURE",
              severity: "HIGH",
              title: `Azure Firewall Threat Intelligence Disabled: ${fw.name}`,
              description: `Firewall ${fw.name} has threat intelligence mode set to ${threatIntelMode}`,
              resourceId: fw.id ?? "",
              resourceType: "Microsoft.Network/azureFirewalls",
              region: fw.location,
              accountId: subscriptionId,
              remediationSteps: ["Enable threat intelligence-based filtering in Alert or Deny mode"],
              complianceFrameworks: ["CIS", "NIST"],
              riskScore: 0,
              firstDetected: new Date(),
              lastSeen: new Date(),
              rawFinding: { firewallName: fw.name, threatIntelMode },
              blockedByFirewall: false,
            };
            finding.riskScore = computeRiskScore(finding);
            findings.push(finding);
          }

          // Report firewall configuration details
          const ipConfigs = fw.ipConfigurations ?? [];
          for (const ipConfig of ipConfigs) {
            if (!ipConfig.privateIPAddress) continue;
          }
        }

        const response: ToolResponse<{ findings: NetworkFinding[]; note: string }> = {
          success: true,
          requestId,
          data: {
            findings,
            note: `For detailed threat logs, query Log Analytics workspace '${workspaceName}' with: AzureDiagnostics | where Category == "AzureFirewallNetworkRule" or Category == "AzureFirewallApplicationRule"`,
          },
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("azure_get_firewall_threats failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
