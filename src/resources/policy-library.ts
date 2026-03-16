import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { logger } from "../logger.js";

interface PolicyTemplate {
  id: string;
  name: string;
  cloud: "aws" | "azure" | "gcp" | "all";
  framework: string;
  category: string;
  description: string;
  checkTool: string;
  severity: string;
}

const POLICY_LIBRARY: PolicyTemplate[] = [
  // AWS Policies
  {
    id: "aws-cis-1.1",
    name: "Avoid use of root account",
    cloud: "aws",
    framework: "CIS",
    category: "IAM",
    description: "Ensure root account is not used for day-to-day operations",
    checkTool: "aws_get_cloudtrail_anomalies",
    severity: "CRITICAL",
  },
  {
    id: "aws-cis-1.4",
    name: "MFA enabled for IAM users with console access",
    cloud: "aws",
    framework: "CIS",
    category: "IAM",
    description: "Ensure MFA is enabled for all IAM users with console password",
    checkTool: "aws_analyze_iam_access",
    severity: "HIGH",
  },
  {
    id: "aws-cis-2.1",
    name: "CloudTrail enabled in all regions",
    cloud: "aws",
    framework: "CIS",
    category: "Logging",
    description: "Ensure CloudTrail is enabled in all regions",
    checkTool: "aws_list_config_violations",
    severity: "HIGH",
  },
  {
    id: "aws-cis-3.1",
    name: "S3 bucket public access blocked",
    cloud: "aws",
    framework: "CIS",
    category: "Storage",
    description: "Ensure S3 buckets block public access",
    checkTool: "aws_list_config_violations",
    severity: "CRITICAL",
  },
  {
    id: "aws-sec-1",
    name: "KMS key rotation enabled",
    cloud: "aws",
    framework: "NIST",
    category: "Cryptography",
    description: "Ensure KMS CMK rotation is enabled",
    checkTool: "aws_audit_kms_keys",
    severity: "MEDIUM",
  },
  {
    id: "aws-sec-2",
    name: "Secrets Manager rotation configured",
    cloud: "aws",
    framework: "SOC2",
    category: "Secrets",
    description: "Ensure secrets have automatic rotation configured",
    checkTool: "aws_audit_secrets_manager",
    severity: "HIGH",
  },

  // Azure Policies
  {
    id: "azure-cis-1.1",
    name: "MFA enforced for all users",
    cloud: "azure",
    framework: "CIS",
    category: "IAM",
    description: "Ensure MFA is enforced for all Azure AD users",
    checkTool: "azure_get_entra_risky_identities",
    severity: "CRITICAL",
  },
  {
    id: "azure-cis-2.1",
    name: "Defender for Cloud enabled",
    cloud: "azure",
    framework: "CIS",
    category: "Monitoring",
    description: "Ensure Microsoft Defender for Cloud is enabled on all subscriptions",
    checkTool: "azure_get_defender_alerts",
    severity: "HIGH",
  },
  {
    id: "azure-sec-1",
    name: "Key Vault soft delete enabled",
    cloud: "azure",
    framework: "NIST",
    category: "Cryptography",
    description: "Ensure Key Vault has soft delete enabled",
    checkTool: "azure_audit_key_vault",
    severity: "MEDIUM",
  },
  {
    id: "azure-sec-2",
    name: "App Service uses HTTPS only",
    cloud: "azure",
    framework: "SOC2",
    category: "Network",
    description: "Ensure App Services require HTTPS",
    checkTool: "azure_check_app_service_security",
    severity: "HIGH",
  },

  // GCP Policies
  {
    id: "gcp-cis-1.1",
    name: "Service account key rotation",
    cloud: "gcp",
    framework: "CIS",
    category: "IAM",
    description: "Ensure service account keys are rotated within 90 days",
    checkTool: "gcp_get_iam_recommendations",
    severity: "HIGH",
  },
  {
    id: "gcp-cis-2.1",
    name: "Audit logging enabled",
    cloud: "gcp",
    framework: "CIS",
    category: "Logging",
    description: "Ensure audit logging is enabled for all services",
    checkTool: "gcp_get_audit_log_anomalies",
    severity: "HIGH",
  },
  {
    id: "gcp-sec-1",
    name: "KMS key rotation configured",
    cloud: "gcp",
    framework: "NIST",
    category: "Cryptography",
    description: "Ensure Cloud KMS keys have rotation configured",
    checkTool: "gcp_audit_kms_keys",
    severity: "MEDIUM",
  },
  {
    id: "gcp-sec-2",
    name: "Binary Authorization enforced",
    cloud: "gcp",
    framework: "SOC2",
    category: "Container",
    description: "Ensure Binary Authorization is enforced on GKE clusters",
    checkTool: "gcp_check_binary_authorization",
    severity: "HIGH",
  },

  // Cross-cloud
  {
    id: "xcloud-sec-1",
    name: "Secret rotation across all clouds",
    cloud: "all",
    framework: "SOC2",
    category: "Secrets",
    description: "Ensure all secrets are rotated within 90 days across all cloud providers",
    checkTool: "multicloud_secret_rotation_audit",
    severity: "HIGH",
  },
  {
    id: "xcloud-sec-2",
    name: "Cross-cloud IAM least privilege",
    cloud: "all",
    framework: "NIST",
    category: "IAM",
    description: "Ensure IAM follows least privilege across all cloud providers",
    checkTool: "multicloud_iam_blast_radius",
    severity: "CRITICAL",
  },
];

export function registerPolicyLibrary(server: McpServer): void {
  server.resource(
    "policy-library",
    "security://policies/library",
    {
      description: "Security policy templates organized by cloud, framework, and category",
      mimeType: "application/json",
    },
    async () => {
      logger.info("Resource accessed: policy library");

      const byCloud: Record<string, PolicyTemplate[]> = {};
      const byFramework: Record<string, PolicyTemplate[]> = {};

      for (const p of POLICY_LIBRARY) {
        (byCloud[p.cloud] ??= []).push(p);
        (byFramework[p.framework] ??= []).push(p);
      }

      return {
        contents: [
          {
            uri: "security://policies/library",
            mimeType: "application/json",
            text: JSON.stringify({
              totalPolicies: POLICY_LIBRARY.length,
              byCloud: Object.fromEntries(
                Object.entries(byCloud).map(([k, v]) => [k, v.length])
              ),
              byFramework: Object.fromEntries(
                Object.entries(byFramework).map(([k, v]) => [k, v.length])
              ),
              policies: POLICY_LIBRARY,
            }, null, 2),
          },
        ],
      };
    }
  );
}
