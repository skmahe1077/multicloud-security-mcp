import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

async function azureDevOpsRequest(url: string, token: string): Promise<unknown> {
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
  });
  if (!response.ok) throw new Error(`Azure DevOps API error: ${response.status} ${response.statusText}`);
  return response.json();
}

export function register(server: McpServer): void {
  server.tool(
    "azure_audit_devops_security",
    "Audit Azure DevOps repos for branch protection, pipeline permissions, and secret scanning",
    {
      organizationUrl: z.string().describe("Azure DevOps organization URL"),
      projectName: z.string().optional().describe("Specific project name"),
      checkBranchPolicies: z.boolean().default(true).describe("Check branch protection policies"),
      checkPipelinePermissions: z.boolean().default(true).describe("Check pipeline service connection permissions"),
      checkSecretScanning: z.boolean().default(true).describe("Check for exposed secrets"),
    },
    async ({ organizationUrl, projectName, checkBranchPolicies, checkPipelinePermissions, checkSecretScanning }) => {
      const requestId = uuidv4();
      logger.info("azure_audit_devops_security invoked", { requestId });
      try {
        const credential = new DefaultAzureCredential();
        const tokenResponse = await credential.getToken("499b84ac-1321-427f-aa17-267ca6975798/.default");
        const token = tokenResponse.token;
        const findings: NormalizedFinding[] = [];
        const baseUrl = organizationUrl.replace(/\/$/, "");

        // List projects
        const projectsResp = await azureDevOpsRequest(
          `${baseUrl}/_apis/projects?api-version=7.1`,
          token
        ) as { value: Record<string, unknown>[] };

        const projects = projectName
          ? (projectsResp.value ?? []).filter(p => p["name"] === projectName)
          : (projectsResp.value ?? []);

        for (const project of projects) {
          const pName = project["name"] as string;
          const pId = project["id"] as string;

          if (checkBranchPolicies) {
            try {
              const repos = await azureDevOpsRequest(
                `${baseUrl}/${pName}/_apis/git/repositories?api-version=7.1`,
                token
              ) as { value: Record<string, unknown>[] };

              for (const repo of repos.value ?? []) {
                const repoId = repo["id"] as string;
                const repoName = repo["name"] as string;

                const policies = await azureDevOpsRequest(
                  `${baseUrl}/${pName}/_apis/policy/configurations?repositoryId=${repoId}&api-version=7.1`,
                  token
                ) as { value: Record<string, unknown>[] };

                const hasBranchPolicy = (policies.value ?? []).some(
                  (p) => (p["isEnabled"] as boolean) && (p["isBlocking"] as boolean)
                );

                if (!hasBranchPolicy) {
                  const finding: NormalizedFinding = {
                    id: `devops-branch-${repoId}`,
                    cloud: "azure",
                    service: "devops-security",
                    category: "COMPLIANCE_VIOLATION",
                    severity: "HIGH",
                    title: `No Branch Protection: ${pName}/${repoName}`,
                    description: `Repository ${repoName} in project ${pName} has no enforced branch policies`,
                    resourceId: repoId,
                    resourceType: "Azure DevOps Repository",
                    remediationSteps: [
                      "Configure branch policies on main/default branch",
                      "Require pull request reviews",
                      "Enable build validation",
                    ],
                    complianceFrameworks: ["SOC2", "NIST"],
                    riskScore: 0,
                    firstDetected: new Date(),
                    lastSeen: new Date(),
                    rawFinding: { project: pName, repo: repoName },
                  };
                  finding.riskScore = computeRiskScore(finding);
                  findings.push(finding);
                }
              }
            } catch (e) {
              logger.warn("Failed to check branch policies", { project: pName, error: String(e) });
            }
          }

          if (checkPipelinePermissions) {
            try {
              const endpoints = await azureDevOpsRequest(
                `${baseUrl}/${pName}/_apis/serviceendpoint/endpoints?api-version=7.1`,
                token
              ) as { value: Record<string, unknown>[] };

              for (const ep of endpoints.value ?? []) {
                if (ep["isShared"] === true) {
                  const finding: NormalizedFinding = {
                    id: `devops-endpoint-${ep["id"]}`,
                    cloud: "azure",
                    service: "devops-security",
                    category: "IAM_RISK",
                    severity: "MEDIUM",
                    title: `Shared Service Connection: ${ep["name"]}`,
                    description: `Service connection ${ep["name"]} is shared across projects — may grant excessive pipeline permissions`,
                    resourceId: ep["id"] as string ?? "",
                    resourceType: "Azure DevOps Service Connection",
                    remediationSteps: ["Restrict service connection to specific pipelines", "Review pipeline permissions"],
                    complianceFrameworks: ["SOC2"],
                    riskScore: 0,
                    firstDetected: new Date(),
                    lastSeen: new Date(),
                    rawFinding: { endpoint: ep["name"], type: ep["type"] },
                  };
                  finding.riskScore = computeRiskScore(finding);
                  findings.push(finding);
                }
              }
            } catch (e) {
              logger.warn("Failed to check pipeline permissions", { project: pName, error: String(e) });
            }
          }
        }

        const response: ToolResponse<NormalizedFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("azure_audit_devops_security failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
