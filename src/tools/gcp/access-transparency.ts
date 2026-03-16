import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { Logging } from "@google-cloud/logging";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_get_access_transparency_logs",
    "Get GCP Access Transparency logs — Google admin accesses to your data with reason codes and justifications",
    {
      projectId: z.string().describe("GCP project ID"),
      lookbackDays: z.number().min(1).max(90).default(7).describe("Days to look back"),
      productName: z.string().optional().describe("Filter by GCP product name"),
      accessReason: z.string().optional().describe("Filter by access reason"),
    },
    async ({ projectId, lookbackDays, productName, accessReason }) => {
      const requestId = uuidv4();
      logger.info("gcp_get_access_transparency_logs invoked", { requestId });
      try {
        const logging = new Logging({ projectId });
        const since = new Date(Date.now() - lookbackDays * 24 * 60 * 60 * 1000);

        let filter = `timestamp>="${since.toISOString()}" AND logName="projects/${projectId}/logs/cloudaudit.googleapis.com%2Faccess_transparency"`;
        if (productName) {
          filter += ` AND protoPayload.serviceData.accessApprovalServiceData.productName="${productName}"`;
        }
        if (accessReason) {
          filter += ` AND protoPayload.serviceData.accessApprovalServiceData.reason="${accessReason}"`;
        }

        const [entries] = await logging.getEntries({
          filter,
          pageSize: 100,
          orderBy: "timestamp desc",
        });

        const findings: NormalizedFinding[] = (entries ?? []).map(entry => {
          const data = entry.data as Record<string, unknown> ?? {};
          const payload = data["protoPayload"] as Record<string, unknown> ?? data;
          const serviceData = (payload["serviceData"] as Record<string, unknown>) ?? {};
          const atData = (serviceData["accessApprovalServiceData"] as Record<string, unknown>) ?? {};

          const finding: NormalizedFinding = {
            id: `at-${entry.metadata?.insertId ?? ""}`,
            cloud: "gcp",
            service: "access-transparency",
            category: "DATA_EXPOSURE",
            severity: "INFO",
            title: `Access Transparency: ${atData["reason"] ?? "Google Admin Access"}`,
            description: `Google personnel accessed ${payload["resourceName"] ?? "your data"}. Reason: ${atData["reason"] ?? "not specified"}. Justification: ${atData["justification"] ?? "none provided"}`,
            resourceId: (payload["resourceName"] as string) ?? "",
            resourceType: (payload["serviceName"] as string) ?? "Unknown",
            accountId: projectId,
            remediationSteps: ["Review access transparency log for legitimacy", "Contact Google support if access is unexpected"],
            complianceFrameworks: ["SOC2", "ISO27001"],
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
        logger.error("gcp_get_access_transparency_logs failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
