import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { google } from "googleapis";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { VulnerabilityFinding } from "../../types/vulnerabilities.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_scan_artifact_registry",
    "Scan GCP Artifact Registry for container image vulnerabilities with CVE, CVSS, and fix versions",
    {
      projectId: z.string().describe("GCP project ID"),
      location: z.string().default("us-central1").describe("Artifact Registry location"),
      repositoryName: z.string().optional().describe("Repository name"),
      packageName: z.string().optional().describe("Package/image name"),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).default("HIGH").describe("Minimum severity"),
    },
    async ({ projectId, location, repositoryName, packageName, severity }) => {
      const requestId = uuidv4();
      logger.info("gcp_scan_artifact_registry invoked", { requestId });
      try {
        const auth = new google.auth.GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform"] });
        const containerAnalysis = google.containeranalysis({ version: "v1", auth });

        const filter = `kind="VULNERABILITY" AND resourceUrl="https://${location}-docker.pkg.dev/${projectId}${repositoryName ? `/${repositoryName}` : ""}${packageName ? `/${packageName}` : ""}"`;

        const resp = await containerAnalysis.projects.occurrences.list({
          parent: `projects/${projectId}`,
          filter: `kind="VULNERABILITY"`,
          pageSize: 100,
        });

        const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"];
        const minIdx = severityOrder.indexOf(severity === "INFO" ? "MINIMAL" : severity);

        const findings: VulnerabilityFinding[] = (resp.data.occurrences ?? [])
          .filter(occ => {
            const vulnSev = occ.vulnerability?.severity ?? "MINIMAL";
            return severityOrder.indexOf(vulnSev) <= minIdx;
          })
          .map(occ => {
            const vuln = occ.vulnerability ?? {};
            const pkg = vuln.packageIssue?.[0];

            const finding: VulnerabilityFinding = {
              id: occ.name ?? "",
              cloud: "gcp",
              service: "artifact-registry",
              category: "CONTAINER_RISK",
              severity: (vuln.severity === "MINIMAL" ? "INFO" : vuln.severity ?? "INFO") as any,
              title: `Artifact Vulnerability: ${vuln.shortDescription ?? pkg?.affectedCpeUri ?? "Unknown"}`,
              description: vuln.longDescription ?? vuln.shortDescription ?? "",
              resourceId: occ.resourceUri ?? "",
              resourceType: "Artifact Registry Image",
              accountId: projectId,
              remediationSteps: [pkg?.fixedVersion?.fullName ? `Update to ${pkg.fixedVersion.fullName}` : "Update the affected package"],
              complianceFrameworks: [],
              riskScore: 0,
              firstDetected: new Date(occ.createTime ?? Date.now()),
              lastSeen: new Date(occ.updateTime ?? Date.now()),
              rawFinding: occ,
              cveId: vuln.shortDescription ?? undefined,
              cvssScore: vuln.cvssScore ?? undefined,
              packageName: pkg?.affectedPackage ?? undefined,
              packageVersion: pkg?.affectedVersion?.fullName ?? undefined,
              fixedVersion: pkg?.fixedVersion?.fullName ?? undefined,
              affectedResource: occ.resourceUri ?? "",
            };
            finding.riskScore = computeRiskScore(finding);
            return finding;
          });

        const response: ToolResponse<VulnerabilityFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("gcp_scan_artifact_registry failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
