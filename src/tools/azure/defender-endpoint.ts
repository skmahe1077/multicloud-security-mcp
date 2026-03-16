import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { Client } from "@microsoft/microsoft-graph-client";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { VulnerabilityFinding } from "../../types/vulnerabilities.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

function getGraphClient(): Client {
  const credential = new DefaultAzureCredential();
  return Client.initWithMiddleware({
    authProvider: {
      getAccessToken: async () => {
        const token = await credential.getToken("https://graph.microsoft.com/.default");
        return token.token;
      },
    },
  });
}

export function register(server: McpServer): void {
  server.tool(
    "azure_get_defender_endpoint_vulns",
    "Get Microsoft Defender for Endpoint vulnerability findings per device with CVE and exploitability details",
    {
      tenantId: z.string().describe("Azure AD tenant ID"),
      deviceName: z.string().optional().describe("Filter by device name"),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).default("HIGH").describe("Minimum severity"),
      cvssScoreMin: z.number().optional().describe("Minimum CVSS score filter"),
    },
    async ({ tenantId, deviceName, severity, cvssScoreMin }) => {
      const requestId = uuidv4();
      logger.info("azure_get_defender_endpoint_vulns invoked", { requestId });
      try {
        const client = getGraphClient();

        let url = "/security/vulnerabilities";
        const resp = await client.api(url).top(100).get();
        const vulns = resp.value ?? [];

        const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
        const minIdx = severityOrder.indexOf(severity);

        const findings: VulnerabilityFinding[] = vulns
          .filter((v: Record<string, unknown>) => {
            const sev = ((v["severity"] as string) ?? "medium").toUpperCase();
            const mapped = sev === "INFORMATIONAL" ? "INFO" : sev;
            if (severityOrder.indexOf(mapped) > minIdx) return false;
            if (cvssScoreMin && (v["cvssScore"] as number ?? 0) < cvssScoreMin) return false;
            return true;
          })
          .map((v: Record<string, unknown>) => {
            const sev = ((v["severity"] as string) ?? "medium").toUpperCase();
            const finding: VulnerabilityFinding = {
              id: (v["id"] as string) ?? "",
              cloud: "azure",
              service: "defender-endpoint",
              category: "VULNERABILITY",
              severity: (sev === "INFORMATIONAL" ? "INFO" : sev) as any,
              title: (v["displayName"] as string) ?? (v["id"] as string) ?? "Endpoint Vulnerability",
              description: (v["description"] as string) ?? "",
              resourceId: (v["machineId"] as string) ?? "",
              resourceType: "Device",
              accountId: tenantId,
              remediationSteps: [(v["recommendedAction"] as string) ?? "Apply the security update"],
              complianceFrameworks: [],
              riskScore: 0,
              firstDetected: new Date((v["publishedOn"] as string) ?? Date.now()),
              lastSeen: new Date((v["updatedOn"] as string) ?? Date.now()),
              rawFinding: v,
              cveId: (v["cveId"] as string) ?? (v["id"] as string),
              cvssScore: v["cvssScore"] as number | undefined,
              affectedResource: (v["machineName"] as string) ?? "",
            };
            finding.riskScore = computeRiskScore(finding);
            return finding;
          });

        const response: ToolResponse<VulnerabilityFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("azure_get_defender_endpoint_vulns failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
