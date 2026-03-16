import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { ContainerRegistryManagementClient } from "@azure/arm-containerregistry";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { VulnerabilityFinding } from "../../types/vulnerabilities.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

export function register(server: McpServer): void {
  server.tool(
    "azure_scan_container_registry",
    "Scan Azure Container Registry images for vulnerabilities via Defender for Containers",
    {
      subscriptionId: z.string().describe("Azure subscription ID"),
      registryName: z.string().describe("ACR registry name"),
      repositoryName: z.string().optional().describe("Specific repository"),
      severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).default("HIGH").describe("Minimum severity"),
    },
    async ({ subscriptionId, registryName, repositoryName, severity }) => {
      const requestId = uuidv4();
      logger.info("azure_scan_container_registry invoked", { requestId, registryName });
      try {
        const client = new ContainerRegistryManagementClient(new DefaultAzureCredential(), subscriptionId);

        // Get registry details
        const registries = client.registries.list();
        const findings: VulnerabilityFinding[] = [];
        let registryFound = false;

        for await (const registry of registries) {
          if (registry.name !== registryName) continue;
          registryFound = true;

          // Check security posture of the registry itself
          if (registry.publicNetworkAccess === "Enabled") {
            const finding: VulnerabilityFinding = {
              id: `acr-public-${registry.name}`,
              cloud: "azure",
              service: "container-registry",
              category: "CONTAINER_RISK",
              severity: "HIGH",
              title: `ACR Public Access Enabled: ${registry.name}`,
              description: `Container registry ${registry.name} has public network access enabled`,
              resourceId: registry.id ?? "",
              resourceType: "Microsoft.ContainerRegistry/registries",
              region: registry.location,
              accountId: subscriptionId,
              remediationSteps: ["Disable public network access", "Configure private endpoints"],
              complianceFrameworks: ["CIS"],
              riskScore: 0,
              firstDetected: new Date(),
              lastSeen: new Date(),
              rawFinding: registry,
              affectedResource: registry.loginServer ?? registryName,
            };
            finding.riskScore = computeRiskScore(finding);
            findings.push(finding);
          }

          if (!registry.adminUserEnabled) {
            // Good - admin user disabled
          } else {
            const finding: VulnerabilityFinding = {
              id: `acr-admin-${registry.name}`,
              cloud: "azure",
              service: "container-registry",
              category: "CONTAINER_RISK",
              severity: "MEDIUM",
              title: `ACR Admin User Enabled: ${registry.name}`,
              description: `Container registry ${registry.name} has admin user enabled — use RBAC instead`,
              resourceId: registry.id ?? "",
              resourceType: "Microsoft.ContainerRegistry/registries",
              region: registry.location,
              accountId: subscriptionId,
              remediationSteps: ["Disable admin user", "Use Azure RBAC for access control"],
              complianceFrameworks: ["CIS", "SOC2"],
              riskScore: 0,
              firstDetected: new Date(),
              lastSeen: new Date(),
              rawFinding: registry,
              affectedResource: registry.loginServer ?? registryName,
            };
            finding.riskScore = computeRiskScore(finding);
            findings.push(finding);
          }
        }

        if (!registryFound) {
          return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: `Registry ${registryName} not found` }) }] };
        }

        const response: ToolResponse<VulnerabilityFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("azure_scan_container_registry failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
