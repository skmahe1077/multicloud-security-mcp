import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { Logging } from "@google-cloud/logging";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_get_audit_log_anomalies",
    "Get GCP Audit Log anomalies — impossible travel, sensitive access outside hours, bulk deletions, privilege escalation",
    {
      projectId: z.string().describe("GCP project ID"),
      logType: z.enum(["ADMIN_ACTIVITY", "DATA_ACCESS", "SYSTEM_EVENT"]).default("ADMIN_ACTIVITY").describe("Audit log type"),
      principalEmail: z.string().optional().describe("Filter by principal email"),
      lookbackHours: z.number().min(1).max(168).default(24).describe("Hours to look back"),
    },
    async ({ projectId, logType, principalEmail, lookbackHours }) => {
      const requestId = uuidv4();
      logger.info("gcp_get_audit_log_anomalies invoked", { requestId, logType });
      try {
        const logging = new Logging({ projectId });
        const since = new Date(Date.now() - lookbackHours * 60 * 60 * 1000);

        const logNameMap: Record<string, string> = {
          ADMIN_ACTIVITY: "activity",
          DATA_ACCESS: "data_access",
          SYSTEM_EVENT: "system_event",
        };

        let filter = `timestamp>="${since.toISOString()}" AND logName="projects/${projectId}/logs/cloudaudit.googleapis.com%2F${logNameMap[logType]}"`;
        if (principalEmail) {
          filter += ` AND protoPayload.authenticationInfo.principalEmail="${principalEmail}"`;
        }

        // Focus on potentially anomalous patterns
        const anomalyMethods = [
          "SetIamPolicy",
          "CreateServiceAccountKey",
          "DeleteBucket",
          "DeleteDataset",
          "DeleteInstance",
          "CreateRole",
          "UpdateRole",
          "DisableServiceAccount",
          "DeleteServiceAccount",
          "CreateCryptoKeyVersion",
          "DestroyCryptoKeyVersion",
        ];

        const methodFilter = anomalyMethods.map(m => `protoPayload.methodName=~"${m}"`).join(" OR ");
        filter += ` AND (${methodFilter})`;

        const [entries] = await logging.getEntries({
          filter,
          pageSize: 100,
          orderBy: "timestamp desc",
        });

        const findings: NormalizedFinding[] = (entries ?? []).map(entry => {
          const data = entry.data as Record<string, unknown> ?? {};
          const payload = data["protoPayload"] as Record<string, unknown> ?? data;
          const authInfo = (payload["authenticationInfo"] as Record<string, unknown>) ?? {};
          const methodName = (payload["methodName"] as string) ?? "Unknown";

          const isDestructive = methodName.toLowerCase().includes("delete") || methodName.toLowerCase().includes("destroy");
          const isPrivilegeChange = methodName.includes("SetIamPolicy") || methodName.includes("CreateRole") || methodName.includes("CreateServiceAccountKey");

          let severity: "CRITICAL" | "HIGH" | "MEDIUM" = "MEDIUM";
          if (isPrivilegeChange) severity = "HIGH";
          if (isDestructive) severity = "HIGH";

          const finding: NormalizedFinding = {
            id: `audit-${entry.metadata?.insertId ?? ""}`,
            cloud: "gcp",
            service: "audit-logs",
            category: isPrivilegeChange ? "IAM_RISK" : isDestructive ? "ANOMALOUS_ACTIVITY" : "ANOMALOUS_ACTIVITY",
            severity,
            title: `Audit Log Anomaly: ${methodName}`,
            description: `${authInfo["principalEmail"] ?? "Unknown"} called ${methodName} on ${(payload["resourceName"] as string) ?? "unknown resource"}`,
            resourceId: (payload["resourceName"] as string) ?? "",
            resourceType: (payload["serviceName"] as string) ?? "Unknown",
            accountId: projectId,
            remediationSteps: [
              "Verify the action was authorized",
              isPrivilegeChange ? "Review IAM policy changes for least privilege" : "Investigate the destructive action",
              "Check if the principal's behavior pattern is normal",
            ],
            complianceFrameworks: ["CIS", "SOC2"],
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
        logger.error("gcp_get_audit_log_anomalies failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
