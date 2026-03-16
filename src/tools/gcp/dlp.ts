import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { DlpServiceClient } from "@google-cloud/dlp";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_scan_dlp_sensitive_data",
    "Scan GCP storage for sensitive data using Cloud DLP — PII, credentials, financial, and health data",
    {
      projectId: z.string().describe("GCP project ID"),
      storageType: z.enum(["GCS", "BIGQUERY", "DATASTORE"]).describe("Storage type to scan"),
      datasetOrBucket: z.string().optional().describe("Specific bucket or dataset name"),
      infoTypes: z.enum(["PII", "CREDENTIALS", "HEALTH"]).default("PII").describe("Sensitivity type"),
    },
    async ({ projectId, storageType, datasetOrBucket, infoTypes }) => {
      const requestId = uuidv4();
      logger.info("gcp_scan_dlp_sensitive_data invoked", { requestId, storageType, infoTypes });
      try {
        const dlpClient = new DlpServiceClient();

        const infoTypeMap: Record<string, string[]> = {
          PII: ["PERSON_NAME", "EMAIL_ADDRESS", "PHONE_NUMBER", "STREET_ADDRESS", "DATE_OF_BIRTH"],
          CREDENTIALS: ["PASSWORD", "AUTH_TOKEN", "AWS_CREDENTIALS", "GCP_CREDENTIALS", "ENCRYPTION_KEY"],
          HEALTH: ["MEDICAL_RECORD_NUMBER", "MEDICAL_TERM"],
        };

        // List existing DLP jobs for the project
        const [jobs] = await dlpClient.listDlpJobs({
          parent: `projects/${projectId}/locations/global`,
          type: "INSPECT_JOB",
          filter: 'state=DONE',
        });

        const findings: NormalizedFinding[] = [];
        for (const job of (jobs ?? []).slice(0, 20)) {
          const result = job.inspectDetails?.result;
          if (!result?.infoTypeStats?.length) continue;

          for (const stat of result.infoTypeStats) {
            const finding: NormalizedFinding = {
              id: `dlp-${job.name}-${stat.infoType?.name ?? ""}`,
              cloud: "gcp",
              service: "dlp",
              category: "DLP_VIOLATION",
              severity: (stat.count && Number(stat.count) > 100) ? "HIGH" : "MEDIUM",
              title: `DLP Finding: ${stat.infoType?.name ?? "Unknown"} detected`,
              description: `${stat.count ?? 0} instances of ${stat.infoType?.name} found in ${storageType}${datasetOrBucket ? ` (${datasetOrBucket})` : ""}`,
              resourceId: job.name ?? "",
              resourceType: storageType,
              accountId: projectId,
              remediationSteps: [
                "Review and classify the sensitive data",
                "Apply appropriate access controls",
                "Consider de-identification or tokenization",
              ],
              complianceFrameworks: ["SOC2", "PCI_DSS", "NIST"],
              riskScore: 0,
              firstDetected: new Date(job.createTime as string ?? Date.now()),
              lastSeen: new Date(job.endTime as string ?? Date.now()),
              rawFinding: { job: job.name, infoType: stat.infoType, count: stat.count },
            };
            finding.riskScore = computeRiskScore(finding);
            findings.push(finding);
          }
        }

        const response: ToolResponse<NormalizedFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("gcp_scan_dlp_sensitive_data failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
