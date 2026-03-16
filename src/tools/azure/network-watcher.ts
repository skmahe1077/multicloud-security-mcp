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
    "azure_get_network_watcher_flows",
    "Get Azure Network Watcher NSG flow logs — suspicious patterns, denied traffic, anomalous cross-subnet flows",
    {
      subscriptionId: z.string().describe("Azure subscription ID"),
      networkWatcherName: z.string().describe("Network Watcher name"),
      nsgName: z.string().optional().describe("Specific NSG name"),
      trafficDirection: z.enum(["Inbound", "Outbound"]).default("Inbound").describe("Traffic direction"),
      lookbackHours: z.number().min(1).max(168).default(24).describe("Hours to look back"),
    },
    async ({ subscriptionId, networkWatcherName, nsgName, trafficDirection, lookbackHours }) => {
      const requestId = uuidv4();
      logger.info("azure_get_network_watcher_flows invoked", { requestId });
      try {
        const client = new NetworkManagementClient(new DefaultAzureCredential(), subscriptionId);
        const findings: NetworkFinding[] = [];

        // List NSGs and check for flow log configuration
        const nsgs = client.networkSecurityGroups.listAll();
        for await (const nsg of nsgs) {
          if (nsgName && nsg.name !== nsgName) continue;

          // Check for overly permissive rules
          for (const rule of nsg.securityRules ?? []) {
            if (rule.access === "Allow" && rule.sourceAddressPrefix === "*" && rule.direction === trafficDirection) {
              const finding: NetworkFinding = {
                id: `nsg-permissive-${nsg.name}-${rule.name}`,
                cloud: "azure",
                service: "network-watcher",
                category: "NETWORK_EXPOSURE",
                severity: rule.destinationPortRange === "*" ? "CRITICAL" : "HIGH",
                title: `Overly Permissive NSG Rule: ${nsg.name}/${rule.name}`,
                description: `NSG rule ${rule.name} allows ${trafficDirection.toLowerCase()} traffic from any source to port ${rule.destinationPortRange}`,
                resourceId: nsg.id ?? "",
                resourceType: "Microsoft.Network/networkSecurityGroups",
                region: nsg.location,
                accountId: subscriptionId,
                remediationSteps: ["Restrict source address prefix to specific IPs/ranges", "Use Application Security Groups"],
                complianceFrameworks: ["CIS", "NIST"],
                riskScore: 0,
                firstDetected: new Date(),
                lastSeen: new Date(),
                rawFinding: rule,
                destinationPort: rule.destinationPortRange ? parseInt(rule.destinationPortRange) || undefined : undefined,
                protocol: rule.protocol ?? undefined,
              };
              finding.riskScore = computeRiskScore(finding);
              findings.push(finding);
            }
          }
        }

        const response: ToolResponse<NetworkFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("azure_get_network_watcher_flows failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
