import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { ECRClient, DescribeImageScanFindingsCommand } from "@aws-sdk/client-ecr";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { VulnerabilityFinding } from "../../types/vulnerabilities.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

async function withRetry<T>(fn: () => Promise<T>, retries = 5): Promise<T> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try { return await fn(); } catch (error: unknown) {
      const err = error as { name?: string };
      if (attempt < retries && (err.name === "ThrottlingException" || err.name === "LimitExceededException")) {
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
    "aws_get_ecr_vulnerabilities",
    "Get ECR container image scan findings with CVE IDs, CVSS scores, and fix versions",
    {
      registryId: z.string().optional().describe("ECR registry ID"),
      repositoryName: z.string().describe("ECR repository name"),
      imageTag: z.string().default("latest").describe("Image tag to scan"),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).default("HIGH").describe("Minimum severity"),
    },
    async ({ registryId, repositoryName, imageTag, severity }) => {
      const requestId = uuidv4();
      logger.info("aws_get_ecr_vulnerabilities invoked", { requestId, repositoryName, imageTag });
      try {
        const client = new ECRClient({ region: process.env["AWS_DEFAULT_REGION"] ?? "us-east-1" });

        const params: Record<string, unknown> = {
          repositoryName,
          imageId: { imageTag },
          maxResults: 100,
        };
        if (registryId) params["registryId"] = registryId;

        const resp = await withRetry(() => client.send(new DescribeImageScanFindingsCommand(params as any)));

        const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNDEFINED"];
        const minIdx = severityOrder.indexOf(severity);

        const findings: VulnerabilityFinding[] = (resp.imageScanFindings?.findings ?? [])
          .filter(f => severityOrder.indexOf(f.severity ?? "UNDEFINED") <= minIdx)
          .map(f => {
            const finding: VulnerabilityFinding = {
              id: `ecr-${repositoryName}-${f.name ?? ""}`,
              cloud: "aws",
              service: "ecr",
              category: "CONTAINER_RISK",
              severity: f.severity === "INFORMATIONAL" ? "INFO" : (f.severity as any) ?? "INFO",
              title: f.name ?? "ECR Vulnerability",
              description: f.description ?? "",
              resourceId: `${repositoryName}:${imageTag}`,
              resourceType: "AWS::ECR::Image",
              remediationSteps: [f.uri ? `See: ${f.uri}` : "Update base image or affected packages"],
              complianceFrameworks: [],
              riskScore: 0,
              firstDetected: new Date(),
              lastSeen: new Date(),
              rawFinding: f,
              cveId: f.name,
              cvssScore: f.attributes?.find(a => a.key === "CVSS2_SCORE")?.value ? parseFloat(f.attributes.find(a => a.key === "CVSS2_SCORE")!.value!) : undefined,
              packageName: f.attributes?.find(a => a.key === "package_name")?.value,
              packageVersion: f.attributes?.find(a => a.key === "package_version")?.value,
              fixedVersion: undefined,
              affectedResource: `${repositoryName}:${imageTag}`,
            };
            finding.riskScore = computeRiskScore(finding);
            return finding;
          });

        const response: ToolResponse<VulnerabilityFinding[]> = {
          success: true,
          requestId,
          data: findings,
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("aws_get_ecr_vulnerabilities failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
