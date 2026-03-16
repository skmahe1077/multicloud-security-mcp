import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { NetworkFirewallClient, DescribeFirewallCommand } from "@aws-sdk/client-network-firewall";
import { CloudWatchLogsClient, StartQueryCommand, GetQueryResultsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { NetworkFinding } from "../../types/network.js";
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
    "aws_get_network_firewall_alerts",
    "Get AWS Network Firewall alert logs with source/dest IPs, blocked domains, and threat categories",
    {
      firewallArn: z.string().describe("Network Firewall ARN"),
      region: z.string().default("us-east-1").describe("AWS region"),
      alertType: z.enum(["DROP", "ALERT", "PASS"]).optional().describe("Filter by alert type"),
    },
    async ({ firewallArn, region, alertType }) => {
      const requestId = uuidv4();
      logger.info("aws_get_network_firewall_alerts invoked", { requestId });
      try {
        const nfClient = new NetworkFirewallClient({ region });
        const cwClient = new CloudWatchLogsClient({ region });

        const firewallName = firewallArn.split("/").pop() ?? "";
        const firewall = await withRetry(() => nfClient.send(new DescribeFirewallCommand({
          FirewallArn: firewallArn,
        })));

        const logGroupName = `/aws/network-firewall/alert/${firewallName}`;
        const endTime = Date.now();
        const startTime = endTime - 24 * 60 * 60 * 1000;

        let query = `fields @timestamp, event.src_ip, event.dest_ip, event.dest_port, event.proto, event.alert.action, event.alert.signature
          | sort @timestamp desc | limit 100`;
        if (alertType) {
          query = `filter event.alert.action = "${alertType.toLowerCase()}" | ${query}`;
        }

        let alerts: NetworkFinding[] = [];
        try {
          const queryResp = await cwClient.send(new StartQueryCommand({
            logGroupName,
            startTime: Math.floor(startTime / 1000),
            endTime: Math.floor(endTime / 1000),
            queryString: query,
          }));

          if (queryResp.queryId) {
            await new Promise((r) => setTimeout(r, 3000));
            const results = await cwClient.send(new GetQueryResultsCommand({ queryId: queryResp.queryId }));
            alerts = (results.results ?? []).map(row => {
              const fields: Record<string, string> = {};
              for (const f of row) {
                if (f.field && f.value) fields[f.field] = f.value;
              }
              const finding: NetworkFinding = {
                id: `nf-${fields["@timestamp"] ?? Date.now()}`,
                cloud: "aws",
                service: "network-firewall",
                category: "NETWORK_EXPOSURE",
                severity: "MEDIUM",
                title: `Network Firewall Alert: ${fields["event.alert.signature"] ?? "Unknown"}`,
                description: `${fields["event.alert.action"] ?? "alert"} from ${fields["event.src_ip"] ?? "?"} to ${fields["event.dest_ip"] ?? "?"}:${fields["event.dest_port"] ?? "?"}`,
                resourceId: firewallArn,
                resourceType: "AWS::NetworkFirewall::Firewall",
                region,
                remediationSteps: ["Review firewall rules", "Block malicious IPs"],
                complianceFrameworks: [],
                riskScore: 0,
                firstDetected: new Date(fields["@timestamp"] ?? Date.now()),
                lastSeen: new Date(fields["@timestamp"] ?? Date.now()),
                rawFinding: fields,
                sourceIp: fields["event.src_ip"],
                destinationPort: fields["event.dest_port"] ? parseInt(fields["event.dest_port"]) : undefined,
                protocol: fields["event.proto"],
                blockedByFirewall: fields["event.alert.action"] === "blocked",
              };
              finding.riskScore = computeRiskScore(finding);
              return finding;
            });
          }
        } catch {
          logger.warn("Could not query CloudWatch Logs for firewall alerts", { requestId });
        }

        const response: ToolResponse = {
          success: true,
          requestId,
          data: {
            firewall: {
              name: firewall.Firewall?.FirewallName,
              arn: firewall.Firewall?.FirewallArn,
              status: firewall.FirewallStatus?.Status,
              vpcId: firewall.Firewall?.VpcId,
              subnetMappings: firewall.Firewall?.SubnetMappings,
            },
            alerts,
          },
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("aws_get_network_firewall_alerts failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
