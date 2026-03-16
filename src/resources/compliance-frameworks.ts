import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { logger } from "../logger.js";

const FRAMEWORK_DESCRIPTIONS: Record<string, { name: string; version: string; description: string; domains: string[] }> = {
  CIS: {
    name: "CIS Benchmarks",
    version: "3.0",
    description: "Center for Internet Security best practice guidelines for cloud security configuration",
    domains: ["Identity", "Logging", "Monitoring", "Networking", "Storage", "Compute"],
  },
  NIST: {
    name: "NIST 800-53",
    version: "Rev 5",
    description: "National Institute of Standards and Technology security and privacy controls",
    domains: ["Access Control", "Audit", "Configuration Management", "Incident Response", "Risk Assessment", "System Protection"],
  },
  SOC2: {
    name: "SOC 2 Type II",
    version: "2024",
    description: "Service Organization Control 2 trust services criteria",
    domains: ["Security", "Availability", "Processing Integrity", "Confidentiality", "Privacy"],
  },
  ISO27001: {
    name: "ISO/IEC 27001:2022",
    version: "2022",
    description: "International standard for information security management systems",
    domains: ["Information Security Policies", "Organization", "Human Resources", "Asset Management", "Access Control", "Cryptography"],
  },
  PCI_DSS: {
    name: "PCI DSS",
    version: "4.0",
    description: "Payment Card Industry Data Security Standard",
    domains: ["Network Security", "Data Protection", "Vulnerability Management", "Access Control", "Monitoring", "Security Policy"],
  },
};

export function registerComplianceResources(server: McpServer): void {
  // Static resource: findings summary
  server.resource(
    "findings-summary",
    "security://findings/summary",
    {
      description: "Aggregated open findings count by cloud and severity",
      mimeType: "application/json",
    },
    async () => {
      logger.info("Resource accessed: findings/summary");
      return {
        contents: [
          {
            uri: "security://findings/summary",
            mimeType: "application/json",
            text: JSON.stringify({
              description: "Use the multicloud_get_critical_findings tool to get live findings data",
              note: "This resource provides a schema reference. Invoke the tool for real-time data.",
              schema: {
                clouds: ["aws", "azure", "gcp"],
                severities: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                categories: [
                  "THREAT_DETECTION", "VULNERABILITY", "IAM_RISK",
                  "DATA_EXPOSURE", "NETWORK_EXPOSURE", "SECRET_RISK",
                  "CONTAINER_RISK", "COMPLIANCE_VIOLATION", "DLP_VIOLATION",
                  "ANOMALOUS_ACTIVITY",
                ],
              },
            }, null, 2),
          },
        ],
      };
    }
  );

  // Dynamic resource: compliance framework details
  server.resource(
    "compliance-framework",
    new ResourceTemplate("security://compliance/{framework}", {
      list: async () => {
        return {
          resources: Object.keys(FRAMEWORK_DESCRIPTIONS).map((key) => ({
            uri: `security://compliance/${key}`,
            name: FRAMEWORK_DESCRIPTIONS[key]!.name,
            description: FRAMEWORK_DESCRIPTIONS[key]!.description,
            mimeType: "application/json" as const,
          })),
        };
      },
    }),
    {
      description: "Compliance posture snapshot for supported frameworks",
      mimeType: "application/json",
    },
    async (uri, { framework }) => {
      logger.info("Resource accessed: compliance framework", { framework });
      const fw = FRAMEWORK_DESCRIPTIONS[framework as string];
      if (!fw) {
        return {
          contents: [
            {
              uri: uri.href,
              mimeType: "application/json",
              text: JSON.stringify({ error: `Unknown framework: ${framework}. Valid: ${Object.keys(FRAMEWORK_DESCRIPTIONS).join(", ")}` }),
            },
          ],
        };
      }
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: "application/json",
            text: JSON.stringify({
              ...fw,
              supportedClouds: ["aws", "azure", "gcp"],
              tools: {
                aws: "aws_list_config_violations",
                azure: "azure_check_policy_compliance",
                gcp: "gcp_get_asset_violations",
              },
              note: "Use multicloud_compliance_dashboard tool for live compliance data",
            }, null, 2),
          },
        ],
      };
    }
  );

  // Static resource: IAM overprivileged
  server.resource(
    "iam-overprivileged",
    "security://iam/overprivileged",
    {
      description: "Cross-cloud overprivileged identities sorted by risk score",
      mimeType: "application/json",
    },
    async () => {
      logger.info("Resource accessed: iam/overprivileged");
      return {
        contents: [
          {
            uri: "security://iam/overprivileged",
            mimeType: "application/json",
            text: JSON.stringify({
              description: "Use multicloud_iam_blast_radius tool for live IAM risk data",
              tools: {
                aws: "aws_analyze_iam_access",
                azure: "azure_get_entra_risky_identities",
                gcp: "gcp_get_iam_recommendations",
              },
            }, null, 2),
          },
        ],
      };
    }
  );

  // Static resource: secrets rotation status
  server.resource(
    "secrets-rotation-status",
    "security://secrets/rotation-status",
    {
      description: "All secrets/keys overdue for rotation across clouds",
      mimeType: "application/json",
    },
    async () => {
      logger.info("Resource accessed: secrets/rotation-status");
      return {
        contents: [
          {
            uri: "security://secrets/rotation-status",
            mimeType: "application/json",
            text: JSON.stringify({
              description: "Use multicloud_secret_rotation_audit tool for live rotation data",
              tools: {
                aws: ["aws_audit_secrets_manager", "aws_audit_kms_keys"],
                azure: ["azure_audit_key_vault"],
                gcp: ["gcp_audit_secret_manager", "gcp_audit_kms_keys"],
              },
            }, null, 2),
          },
        ],
      };
    }
  );

  // Static resource: critical vulnerabilities
  server.resource(
    "vulnerabilities-critical",
    "security://vulnerabilities/critical",
    {
      description: "Open CVEs with CVSS >= 9.0 across Inspector, Defender, and SCC",
      mimeType: "application/json",
    },
    async () => {
      logger.info("Resource accessed: vulnerabilities/critical");
      return {
        contents: [
          {
            uri: "security://vulnerabilities/critical",
            mimeType: "application/json",
            text: JSON.stringify({
              description: "Use cloud-specific vulnerability tools for live CVE data",
              tools: {
                aws: ["aws_get_inspector_vulnerabilities", "aws_get_ecr_vulnerabilities"],
                azure: ["azure_scan_container_registry", "azure_get_defender_endpoint_vulns"],
                gcp: ["gcp_scan_artifact_registry", "gcp_get_scc_findings"],
              },
              filter: "CVSS >= 9.0",
            }, null, 2),
          },
        ],
      };
    }
  );
}
