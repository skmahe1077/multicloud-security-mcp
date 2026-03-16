import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { google } from "googleapis";
import { Logging } from "@google-cloud/logging";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { NetworkFinding } from "../../types/network.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_get_cloud_armor_events",
    "Get GCP Cloud Armor WAF events — blocked IPs, rule hits, rate limiting, adaptive protection, DDoS mitigations",
    {
      projectId: z.string().describe("GCP project ID"),
      backendServiceName: z.string().optional().describe("Backend service name"),
      securityPolicyName: z.string().optional().describe("Security policy name"),
      lookbackHours: z.number().min(1).max(168).default(24).describe("Hours to look back"),
      requestDecision: z.enum(["DENY", "THROTTLE"]).optional().describe("Filter by decision"),
    },
    async ({ projectId, backendServiceName, securityPolicyName, lookbackHours, requestDecision }) => {
      const requestId = uuidv4();
      logger.info("gcp_get_cloud_armor_events invoked", { requestId });
      try {
        const logging = new Logging({ projectId });
        const since = new Date(Date.now() - lookbackHours * 60 * 60 * 1000);

        let filter = `timestamp>="${since.toISOString()}" AND resource.type="http_load_balancer"`;
        if (requestDecision) {
          filter += ` AND jsonPayload.enforcedSecurityPolicy.outcome="${requestDecision}"`;
        }
        if (securityPolicyName) {
          filter += ` AND jsonPayload.enforcedSecurityPolicy.name="${securityPolicyName}"`;
        }

        const [entries] = await logging.getEntries({
          filter,
          pageSize: 100,
          orderBy: "timestamp desc",
        });

        const findings: NetworkFinding[] = (entries ?? []).map(entry => {
          const data = entry.data as Record<string, unknown> ?? {};
          const policy = data["enforcedSecurityPolicy"] as Record<string, unknown> ?? {};
          const httpRequest = data["httpRequest"] as Record<string, unknown> ?? {};

          const finding: NetworkFinding = {
            id: `cloud-armor-${entry.metadata?.insertId ?? ""}`,
            cloud: "gcp",
            service: "cloud-armor",
            category: "NETWORK_EXPOSURE",
            severity: policy["outcome"] === "DENY" ? "HIGH" : "MEDIUM",
            title: `Cloud Armor: ${policy["name"] ?? "Unknown Policy"} - ${policy["outcome"] ?? "BLOCKED"}`,
            description: `Request from ${httpRequest["remoteIp"] ?? "?"} to ${httpRequest["requestUrl"] ?? "?"} matched rule ${policy["matchedFieldValue"] ?? "unknown"}`,
            resourceId: (policy["name"] as string) ?? "",
            resourceType: "compute.securityPolicy",
            accountId: projectId,
            remediationSteps: ["Review security policy rules", "Monitor for attack pattern changes"],
            complianceFrameworks: [],
            riskScore: 0,
            firstDetected: new Date(entry.metadata?.timestamp as string ?? Date.now()),
            lastSeen: new Date(entry.metadata?.timestamp as string ?? Date.now()),
            rawFinding: data,
            sourceIp: httpRequest["remoteIp"] as string ?? undefined,
            protocol: "HTTPS",
            blockedByFirewall: policy["outcome"] === "DENY",
          };
          finding.riskScore = computeRiskScore(finding);
          return finding;
        });

        const response: ToolResponse<NetworkFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("gcp_get_cloud_armor_events failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
