import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { Logging } from "@google-cloud/logging";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_get_vpc_sc_violations",
    "Get GCP VPC Service Controls violation logs — perimeter violations, caller identity, and access errors",
    {
      organizationId: z.string().describe("GCP organization ID"),
      accessPolicyName: z.string().describe("Access policy name"),
      perimeterName: z.string().optional().describe("Specific perimeter name"),
      lookbackHours: z.number().min(1).max(168).default(24).describe("Hours to look back"),
    },
    async ({ organizationId, accessPolicyName, perimeterName, lookbackHours }) => {
      const requestId = uuidv4();
      logger.info("gcp_get_vpc_sc_violations invoked", { requestId });
      try {
        const logging = new Logging();
        const since = new Date(Date.now() - lookbackHours * 60 * 60 * 1000);

        let filter = `timestamp>="${since.toISOString()}" AND protoPayload.metadata.@type="type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata"`;
        if (perimeterName) {
          filter += ` AND protoPayload.metadata.violationReason="${perimeterName}"`;
        }

        const [entries] = await logging.getEntries({
          filter,
          pageSize: 100,
          orderBy: "timestamp desc",
        });

        const findings: NormalizedFinding[] = (entries ?? []).map(entry => {
          const data = entry.data as Record<string, unknown> ?? {};
          const payload = data["protoPayload"] as Record<string, unknown> ?? data;
          const metadata = (payload["metadata"] as Record<string, unknown>) ?? {};
          const authInfo = (payload["authenticationInfo"] as Record<string, unknown>) ?? {};

          const finding: NormalizedFinding = {
            id: `vpcsc-${entry.metadata?.insertId ?? ""}`,
            cloud: "gcp",
            service: "vpc-service-controls",
            category: "NETWORK_EXPOSURE",
            severity: "HIGH",
            title: `VPC SC Violation: ${metadata["violationReason"] ?? "Access Denied"}`,
            description: `${authInfo["principalEmail"] ?? "Unknown caller"} violated perimeter accessing ${payload["resourceName"] ?? "unknown resource"}`,
            resourceId: (payload["resourceName"] as string) ?? "",
            resourceType: (payload["serviceName"] as string) ?? "Unknown",
            accountId: organizationId,
            remediationSteps: [
              "Review VPC Service Controls perimeter configuration",
              "Add authorized access levels if legitimate",
              "Investigate unauthorized access attempts",
            ],
            complianceFrameworks: ["CIS", "NIST"],
            riskScore: 0,
            firstDetected: new Date(entry.metadata?.timestamp as string ?? Date.now()),
            lastSeen: new Date(entry.metadata?.timestamp as string ?? Date.now()),
            rawFinding: data,
          };
          finding.riskScore = computeRiskScore(finding);
          return finding;
        });

        const response: ToolResponse<NormalizedFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("gcp_get_vpc_sc_violations failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
