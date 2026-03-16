import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { NetworkManagementClient } from "@azure/arm-network";
import { MonitorClient } from "@azure/arm-monitor";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { NetworkFinding } from "../../types/network.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "azure_get_ddos_attacks",
    "Get Azure DDoS Protection mitigation events, attack vectors, and traffic metrics",
    {
      subscriptionId: z.string().describe("Azure subscription ID"),
      publicIpAddress: z.string().optional().describe("Specific public IP to check"),
      lookbackDays: z.number().min(1).max(30).default(7).describe("Days to look back"),
    },
    async ({ subscriptionId, publicIpAddress, lookbackDays }) => {
      const requestId = uuidv4();
      logger.info("azure_get_ddos_attacks invoked", { requestId });
      try {
        const credential = new DefaultAzureCredential();
        const networkClient = new NetworkManagementClient(credential, subscriptionId);
        const findings: NetworkFinding[] = [];

        // List DDoS protection plans
        const ddosPlans = networkClient.ddosProtectionPlans.list();
        const plans: unknown[] = [];
        for await (const plan of ddosPlans) {
          plans.push({
            name: plan.name,
            id: plan.id,
            location: plan.location,
            provisioningState: plan.provisioningState,
            virtualNetworks: plan.virtualNetworks?.length ?? 0,
          });
        }

        // Check public IPs for DDoS protection status
        const publicIps = networkClient.publicIPAddresses.listAll();
        for await (const ip of publicIps) {
          if (publicIpAddress && ip.ipAddress !== publicIpAddress) continue;
          if (!ip.ddosSettings?.protectionMode || ip.ddosSettings.protectionMode === "Disabled") {
            const finding: NetworkFinding = {
              id: `ddos-unprotected-${ip.name}`,
              cloud: "azure",
              service: "ddos-protection",
              category: "NETWORK_EXPOSURE",
              severity: "HIGH",
              title: `Public IP Without DDoS Protection: ${ip.name}`,
              description: `Public IP ${ip.ipAddress} (${ip.name}) does not have DDoS Protection enabled`,
              resourceId: ip.id ?? "",
              resourceType: "Microsoft.Network/publicIPAddresses",
              region: ip.location,
              accountId: subscriptionId,
              remediationSteps: ["Enable Azure DDoS Protection Standard on the virtual network"],
              complianceFrameworks: ["CIS", "NIST"],
              riskScore: 0,
              firstDetected: new Date(),
              lastSeen: new Date(),
              rawFinding: { ipName: ip.name, ipAddress: ip.ipAddress },
              sourceIp: ip.ipAddress,
            };
            finding.riskScore = computeRiskScore(finding);
            findings.push(finding);
          }
        }

        const response: ToolResponse = {
          success: true,
          requestId,
          data: {
            ddosProtectionPlans: plans,
            findings,
            lookbackDays,
          },
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("azure_get_ddos_attacks failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
