import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { google } from "googleapis";
import { logger } from "../../logger.js";
import { ToolResponse, NormalizedFinding } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_check_binary_authorization",
    "Check GCP Binary Authorization policy enforcement, blocked deployments, and attestor configuration",
    {
      projectId: z.string().describe("GCP project ID"),
      clusterName: z.string().optional().describe("GKE cluster name"),
    },
    async ({ projectId, clusterName }) => {
      const requestId = uuidv4();
      logger.info("gcp_check_binary_authorization invoked", { requestId });
      try {
        const auth = new google.auth.GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform"] });
        const binaryAuth = google.binaryauthorization({ version: "v1", auth });

        const policyResp = await binaryAuth.projects.getPolicy({
          name: `projects/${projectId}/policy`,
        });
        const policy = policyResp.data;
        const findings: NormalizedFinding[] = [];

        // Check enforcement mode
        if (policy.defaultAdmissionRule?.enforcementMode !== "ENFORCED_BLOCK_AND_AUDIT_LOG") {
          const finding: NormalizedFinding = {
            id: `binauth-enforcement-${projectId}`,
            cloud: "gcp",
            service: "binary-auth",
            category: "CONTAINER_RISK",
            severity: policy.defaultAdmissionRule?.enforcementMode === "DRYRUN_AUDIT_LOG_ONLY" ? "MEDIUM" : "HIGH",
            title: "Binary Authorization Not Fully Enforced",
            description: `Default admission rule is in ${policy.defaultAdmissionRule?.enforcementMode ?? "unknown"} mode`,
            resourceId: `projects/${projectId}/policy`,
            resourceType: "binaryauthorization.policy",
            accountId: projectId,
            remediationSteps: ["Set enforcement mode to ENFORCED_BLOCK_AND_AUDIT_LOG"],
            complianceFrameworks: ["CIS", "SOC2"],
            riskScore: 0,
            firstDetected: new Date(),
            lastSeen: new Date(),
            rawFinding: policy.defaultAdmissionRule,
          };
          finding.riskScore = computeRiskScore(finding);
          findings.push(finding);
        }

        if (policy.defaultAdmissionRule?.evaluationMode === "ALWAYS_ALLOW") {
          const finding: NormalizedFinding = {
            id: `binauth-allowall-${projectId}`,
            cloud: "gcp",
            service: "binary-auth",
            category: "CONTAINER_RISK",
            severity: "CRITICAL",
            title: "Binary Authorization Default Policy Allows All",
            description: "Default admission rule allows all images — no attestation required",
            resourceId: `projects/${projectId}/policy`,
            resourceType: "binaryauthorization.policy",
            accountId: projectId,
            remediationSteps: ["Change evaluation mode to REQUIRE_ATTESTATION", "Configure attestors"],
            complianceFrameworks: ["CIS", "SOC2", "NIST"],
            riskScore: 0,
            firstDetected: new Date(),
            lastSeen: new Date(),
            rawFinding: policy,
          };
          finding.riskScore = computeRiskScore(finding);
          findings.push(finding);
        }

        // List attestors
        const attestorsResp = await binaryAuth.projects.attestors.list({ parent: `projects/${projectId}` });
        const attestors = attestorsResp.data.attestors ?? [];

        const response: ToolResponse = {
          success: true,
          requestId,
          data: {
            policy: {
              enforcementMode: policy.defaultAdmissionRule?.enforcementMode,
              evaluationMode: policy.defaultAdmissionRule?.evaluationMode,
              clusterAdmissionRules: policy.clusterAdmissionRules ? Object.keys(policy.clusterAdmissionRules) : [],
            },
            attestors: attestors.map(a => ({
              name: a.name,
              description: a.description,
              publicKeyCount: a.userOwnedGrafeasNote ? 1 : 0,
            })),
            findings,
          },
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("gcp_check_binary_authorization failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
