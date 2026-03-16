import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import pLimit from "p-limit";
import { logger } from "./logger.js";
import { NormalizedFinding, ToolResponse, CloudProvider, ComplianceSummary } from "./types/findings.js";
import { sortByRiskScore } from "./tools/shared/risk-scorer.js";
import { correlateFindings, CorrelationKey } from "./tools/shared/siem-correlator.js";
import { mergeSecretRotationReports } from "./tools/shared/secret-rotation-auditor.js";

// AWS tool registrations
import { register as registerSecurityHub } from "./tools/aws/security-hub.js";
import { register as registerGuardDuty } from "./tools/aws/guardduty.js";
import { register as registerInspector } from "./tools/aws/inspector.js";
import { register as registerIAMAnalyzer } from "./tools/aws/iam-analyzer.js";
import { register as registerMacie } from "./tools/aws/macie.js";
import { register as registerCloudTrail } from "./tools/aws/cloudtrail.js";
import { register as registerDetective } from "./tools/aws/detective.js";
import { register as registerConfigRules } from "./tools/aws/config-rules.js";
import { register as registerWAF } from "./tools/aws/waf.js";
import { register as registerShield } from "./tools/aws/shield.js";
import { register as registerNetworkFirewall } from "./tools/aws/network-firewall.js";
import { register as registerSecretsManager } from "./tools/aws/secrets-manager.js";
import { register as registerKMS } from "./tools/aws/kms.js";
import { register as registerECR } from "./tools/aws/ecr.js";
import { register as registerSSMPatch } from "./tools/aws/ssm-patch.js";

// Azure tool registrations
import { register as registerDefender } from "./tools/azure/defender.js";
import { register as registerSentinel } from "./tools/azure/sentinel.js";
import { register as registerEntraID } from "./tools/azure/entra-id-protection.js";
import { register as registerPurview } from "./tools/azure/purview.js";
import { register as registerAzurePolicy } from "./tools/azure/policy.js";
import { register as registerKeyVault } from "./tools/azure/key-vault.js";
import { register as registerAzureFirewall } from "./tools/azure/firewall.js";
import { register as registerDDoSProtection } from "./tools/azure/ddos-protection.js";
import { register as registerContainerRegistry } from "./tools/azure/container-registry.js";
import { register as registerNetworkWatcher } from "./tools/azure/network-watcher.js";
import { register as registerDefenderEndpoint } from "./tools/azure/defender-endpoint.js";
import { register as registerAppServiceSecurity } from "./tools/azure/app-service-security.js";
import { register as registerDevOpsSecurity } from "./tools/azure/devops-security.js";

// GCP tool registrations
import { register as registerSCC } from "./tools/gcp/scc.js";
import { register as registerChronicle } from "./tools/gcp/chronicle.js";
import { register as registerIAMRecommender } from "./tools/gcp/iam-recommender.js";
import { register as registerDLP } from "./tools/gcp/dlp.js";
import { register as registerCloudArmor } from "./tools/gcp/cloud-armor.js";
import { register as registerBinaryAuth } from "./tools/gcp/binary-auth.js";
import { register as registerArtifactRegistry } from "./tools/gcp/artifact-registry.js";
import { register as registerVPCSC } from "./tools/gcp/vpc-service-controls.js";
import { register as registerGCPKMS } from "./tools/gcp/kms.js";
import { register as registerSecretManager } from "./tools/gcp/secret-manager.js";
import { register as registerAssetInventory } from "./tools/gcp/asset-inventory.js";
import { register as registerAccessTransparency } from "./tools/gcp/access-transparency.js";
import { register as registerAuditLogs } from "./tools/gcp/audit-logs.js";

// Resources
import { registerComplianceResources } from "./resources/compliance-frameworks.js";
import { registerPolicyLibrary } from "./resources/policy-library.js";

const limit = pLimit(3);

// ─── Connectivity cache ─────────────────────────────────────────────
let connectivityCache: { result: Record<string, unknown>; timestamp: number } | null = null;

function getCacheTTL(): number {
  return (parseInt(process.env["CACHE_TTL_SECONDS"] ?? "300", 10)) * 1000;
}

async function checkAWSConnectivity(): Promise<{ status: string; detail?: string }> {
  try {
    const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts");
    const client = new STSClient({ region: process.env["AWS_DEFAULT_REGION"] ?? "us-east-1" });
    const result = await client.send(new GetCallerIdentityCommand({}));
    return { status: "connected", detail: `Account: ${result.Account}` };
  } catch (error) {
    return { status: "error", detail: String(error) };
  }
}

async function checkAzureConnectivity(): Promise<{ status: string; detail?: string }> {
  try {
    const { DefaultAzureCredential } = await import("@azure/identity");
    const cred = new DefaultAzureCredential();
    const token = await cred.getToken("https://management.azure.com/.default");
    return { status: "connected", detail: `Token expires: ${new Date(token.expiresOnTimestamp).toISOString()}` };
  } catch (error) {
    return { status: "error", detail: String(error) };
  }
}

async function checkGCPConnectivity(): Promise<{ status: string; detail?: string }> {
  try {
    const { google } = await import("googleapis");
    const auth = new google.auth.GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform"] });
    const client = await auth.getClient();
    const projectId = await auth.getProjectId();
    if (client && projectId) {
      return { status: "connected", detail: `Project: ${projectId}` };
    }
    return { status: "error", detail: "Could not determine project" };
  } catch (error) {
    return { status: "error", detail: String(error) };
  }
}

async function invokeToolSafe<T>(
  fn: () => Promise<T>,
  cloudName: string
): Promise<{ data: T | null; warning?: string }> {
  try {
    const data = await fn();
    return { data };
  } catch (error) {
    logger.warn(`${cloudName} call failed`, { error: String(error) });
    return { data: null, warning: `${cloudName}: ${String(error)}` };
  }
}

export interface CreateServerOptions {
  /** Override server name (default: multicloud-security-mcp) */
  name?: string;
  /** Override server version (default: 1.0.0) */
  version?: string;
  /** Cloud providers to enable (default: all three) */
  clouds?: ("aws" | "azure" | "gcp")[];
}

/**
 * Create and configure the Multi-Cloud Security MCP server.
 *
 * Call this to get a fully-wired `McpServer` instance that you can
 * connect to any MCP transport (stdio, SSE, etc.).
 *
 * ```ts
 * import { createServer } from "multicloud-security-mcp";
 * import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
 *
 * const server = createServer();
 * await server.connect(new StdioServerTransport());
 * ```
 */
export function createServer(options: CreateServerOptions = {}): McpServer {
  const serverName = options.name ?? process.env["MCP_SERVER_NAME"] ?? "multicloud-security-mcp";
  const serverVersion = options.version ?? process.env["MCP_SERVER_VERSION"] ?? "1.0.0";
  const enabledClouds = new Set(options.clouds ?? ["aws", "azure", "gcp"]);

  const server = new McpServer({
    name: serverName,
    version: serverVersion,
  });

  logger.info(`Configuring ${serverName} v${serverVersion}`, {
    clouds: [...enabledClouds],
  });

  // ─── Register cloud-specific tools ────────────────────────────────
  if (enabledClouds.has("aws")) {
    registerSecurityHub(server);
    registerGuardDuty(server);
    registerInspector(server);
    registerIAMAnalyzer(server);
    registerMacie(server);
    registerCloudTrail(server);
    registerDetective(server);
    registerConfigRules(server);
    registerWAF(server);
    registerShield(server);
    registerNetworkFirewall(server);
    registerSecretsManager(server);
    registerKMS(server);
    registerECR(server);
    registerSSMPatch(server);
  }

  if (enabledClouds.has("azure")) {
    registerDefender(server);
    registerSentinel(server);
    registerEntraID(server);
    registerPurview(server);
    registerAzurePolicy(server);
    registerKeyVault(server);
    registerAzureFirewall(server);
    registerDDoSProtection(server);
    registerContainerRegistry(server);
    registerNetworkWatcher(server);
    registerDefenderEndpoint(server);
    registerAppServiceSecurity(server);
    registerDevOpsSecurity(server);
  }

  if (enabledClouds.has("gcp")) {
    registerSCC(server);
    registerChronicle(server);
    registerIAMRecommender(server);
    registerDLP(server);
    registerCloudArmor(server);
    registerBinaryAuth(server);
    registerArtifactRegistry(server);
    registerVPCSC(server);
    registerGCPKMS(server);
    registerSecretManager(server);
    registerAssetInventory(server);
    registerAccessTransparency(server);
    registerAuditLogs(server);
  }

  // Resources
  registerComplianceResources(server);
  registerPolicyLibrary(server);

  // ─── validate_cloud_connectivity ────────────────────────────────
  server.tool(
    "validate_cloud_connectivity",
    "Check connectivity to AWS, Azure, and GCP with a lightweight read call per cloud",
    {},
    async () => {
      const requestId = uuidv4();
      logger.info("Validating cloud connectivity", { requestId });

      const CACHE_TTL = getCacheTTL();
      if (connectivityCache && Date.now() - connectivityCache.timestamp < CACHE_TTL) {
        logger.info("Returning cached connectivity result", { requestId });
        return {
          content: [{
            type: "text" as const,
            text: JSON.stringify({ success: true, requestId, cached: true, data: connectivityCache.result }, null, 2),
          }],
        };
      }

      const [aws, azure, gcp] = await Promise.all([
        limit(() => checkAWSConnectivity()),
        limit(() => checkAzureConnectivity()),
        limit(() => checkGCPConnectivity()),
      ]);

      const result = { aws, azure, gcp };
      connectivityCache = { result, timestamp: Date.now() };

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({ success: true, requestId, cached: false, data: result }, null, 2),
        }],
      };
    }
  );

  // ─── X1: multicloud_get_critical_findings ───────────────────────
  server.tool(
    "multicloud_get_critical_findings",
    "Get critical security findings across AWS, Azure, and GCP in parallel. Returns unified NormalizedFinding[] sorted by risk score.",
    {
      clouds: z.array(z.enum(["aws", "azure", "gcp"])).describe("Cloud providers to query"),
      minSeverity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).default("HIGH").describe("Minimum severity to return"),
      categories: z.array(z.string()).optional().describe("Finding categories to filter"),
    },
    async ({ clouds, minSeverity, categories }) => {
      const requestId = uuidv4();
      logger.info("multicloud_get_critical_findings", { requestId, clouds, minSeverity });

      const allFindings: NormalizedFinding[] = [];
      const warnings: string[] = [];
      const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
      const minIdx = severityOrder.indexOf(minSeverity);

      const tasks: Promise<void>[] = [];

      if (clouds.includes("aws")) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { SecurityHubClient, GetFindingsCommand } = await import("@aws-sdk/client-securityhub");
            const client = new SecurityHubClient({ region: process.env["AWS_DEFAULT_REGION"] ?? "us-east-1" });
            const resp = await client.send(new GetFindingsCommand({
              Filters: { SeverityLabel: [{ Value: minSeverity, Comparison: "EQUALS" }, ...severityOrder.slice(0, minIdx).map(s => ({ Value: s, Comparison: "EQUALS" as const }))] },
              MaxResults: 100,
            }));
            const { normalizeSecurityHubFinding } = await import("./tools/shared/findings-normalizer.js");
            return (resp.Findings ?? []).map(f =>
              normalizeSecurityHubFinding(f as unknown as Record<string, unknown>)
            );
          }, "AWS SecurityHub");
          if (result.data) allFindings.push(...result.data);
          if (result.warning) warnings.push(result.warning);
        }));

        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { GuardDutyClient, ListDetectorsCommand, ListFindingsCommand, GetFindingsCommand } = await import("@aws-sdk/client-guardduty");
            const client = new GuardDutyClient({ region: process.env["AWS_DEFAULT_REGION"] ?? "us-east-1" });
            const detectors = await client.send(new ListDetectorsCommand({}));
            const detectorId = detectors.DetectorIds?.[0];
            if (!detectorId) return [];
            const findingIds = await client.send(new ListFindingsCommand({
              DetectorId: detectorId,
              FindingCriteria: { Criterion: { "severity": { Gte: minIdx <= 1 ? 7 : 4 } } },
              MaxResults: 50,
            }));
            if (!findingIds.FindingIds?.length) return [];
            const findings = await client.send(new GetFindingsCommand({ DetectorId: detectorId, FindingIds: findingIds.FindingIds }));
            const { normalizeGuardDutyFinding } = await import("./tools/shared/findings-normalizer.js");
            return (findings.Findings ?? []).map(f =>
              normalizeGuardDutyFinding(f as unknown as Record<string, unknown>)
            );
          }, "AWS GuardDuty");
          if (result.data) allFindings.push(...result.data);
          if (result.warning) warnings.push(result.warning);
        }));
      }

      if (clouds.includes("azure")) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { SecurityCenter } = await import("@azure/arm-security");
            const { DefaultAzureCredential } = await import("@azure/identity");
            const subId = process.env["AZURE_SUBSCRIPTION_ID"] ?? "";
            const client = new SecurityCenter(new DefaultAzureCredential(), subId);
            const { normalizeDefenderAlert } = await import("./tools/shared/findings-normalizer.js");
            const alerts: NormalizedFinding[] = [];
            for await (const alert of client.alerts.list()) {
              const normalized = normalizeDefenderAlert(alert as unknown as Record<string, unknown>);
              if (severityOrder.indexOf(normalized.severity) <= minIdx) {
                alerts.push(normalized);
              }
            }
            return alerts.slice(0, 100);
          }, "Azure Defender");
          if (result.data) allFindings.push(...result.data);
          if (result.warning) warnings.push(result.warning);
        }));

        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { SecurityInsights } = await import("@azure/arm-securityinsight");
            const { DefaultAzureCredential } = await import("@azure/identity");
            const subId = process.env["AZURE_SUBSCRIPTION_ID"] ?? "";
            const workspaceId = process.env["AZURE_LOG_ANALYTICS_WORKSPACE_ID"] ?? "";
            const client = new SecurityInsights(new DefaultAzureCredential(), subId);
            const { normalizeSentinelIncident } = await import("./tools/shared/findings-normalizer.js");
            const incidents: NormalizedFinding[] = [];
            for await (const incident of client.incidents.list("rg-security", workspaceId)) {
              incidents.push(normalizeSentinelIncident(incident as unknown as Record<string, unknown>));
            }
            return incidents.slice(0, 100);
          }, "Azure Sentinel");
          if (result.data) allFindings.push(...result.data);
          if (result.warning) warnings.push(result.warning);
        }));
      }

      if (clouds.includes("gcp")) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { SecurityCenterClient } = await import("@google-cloud/security-center");
            const client = new SecurityCenterClient();
            const orgId = process.env["GCP_ORGANIZATION_ID"] ?? "";
            const projectId = process.env["GCP_PROJECT_ID"] ?? "";
            const parent = orgId ? `organizations/${orgId}/sources/-` : `projects/${projectId}/sources/-`;
            const [findings] = await client.listFindings({
              parent,
              filter: `severity="${minSeverity}" OR severity="CRITICAL"`,
              pageSize: 100,
            });
            const { normalizeSCCFinding } = await import("./tools/shared/findings-normalizer.js");
            return (findings ?? []).map(f =>
              normalizeSCCFinding((f as Record<string, unknown>)["finding"] as Record<string, unknown> ?? f as unknown as Record<string, unknown>)
            );
          }, "GCP SCC");
          if (result.data) allFindings.push(...result.data);
          if (result.warning) warnings.push(result.warning);
        }));
      }

      await Promise.all(tasks);

      let filtered = allFindings.filter(f => severityOrder.indexOf(f.severity) <= minIdx);
      if (categories?.length) {
        filtered = filtered.filter(f => categories.includes(f.category));
      }

      const sorted = sortByRiskScore(filtered);

      const response: ToolResponse<NormalizedFinding[]> = {
        success: true,
        requestId,
        data: sorted,
        warnings: warnings.length > 0 ? warnings : undefined,
      };

      return {
        content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }],
      };
    }
  );

  // ─── X2: multicloud_compliance_dashboard ────────────────────────
  server.tool(
    "multicloud_compliance_dashboard",
    "Aggregated compliance posture across clouds for CIS, NIST, SOC2, ISO27001, or PCI_DSS frameworks",
    {
      framework: z.enum(["CIS", "NIST", "SOC2", "ISO27001", "PCI_DSS"]).describe("Compliance framework"),
      clouds: z.array(z.enum(["aws", "azure", "gcp"])).describe("Cloud providers to check"),
    },
    async ({ framework, clouds }) => {
      const requestId = uuidv4();
      logger.info("multicloud_compliance_dashboard", { requestId, framework, clouds });

      const summaries: ComplianceSummary[] = [];
      const warnings: string[] = [];
      const tasks: Promise<void>[] = [];

      if (clouds.includes("aws")) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { ConfigServiceClient, DescribeComplianceByConfigRuleCommand } = await import("@aws-sdk/client-config-service");
            const client = new ConfigServiceClient({ region: process.env["AWS_DEFAULT_REGION"] ?? "us-east-1" });
            const resp = await client.send(new DescribeComplianceByConfigRuleCommand({}));
            const rules = resp.ComplianceByConfigRules ?? [];
            const passed = rules.filter(r => r.Compliance?.ComplianceType === "COMPLIANT").length;
            const failed = rules.filter(r => r.Compliance?.ComplianceType === "NON_COMPLIANT").length;
            return {
              cloud: "aws" as CloudProvider, framework,
              totalChecks: rules.length, passedChecks: passed, failedChecks: failed,
              unknownChecks: rules.length - passed - failed,
              failingResources: rules.filter(r => r.Compliance?.ComplianceType === "NON_COMPLIANT").map(r => ({
                ruleId: r.ConfigRuleName ?? "", ruleName: r.ConfigRuleName ?? "",
                resourceId: "", resourceType: "",
              })),
              evaluatedAt: new Date(),
            } satisfies ComplianceSummary;
          }, "AWS Config");
          if (result.data) summaries.push(result.data);
          if (result.warning) warnings.push(result.warning);
        }));
      }

      if (clouds.includes("azure")) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { PolicyInsightsClient } = await import("@azure/arm-policyinsights");
            const { DefaultAzureCredential } = await import("@azure/identity");
            const subId = process.env["AZURE_SUBSCRIPTION_ID"] ?? "";
            const client = new PolicyInsightsClient(new DefaultAzureCredential(), subId);
            let passed = 0, failed = 0, total = 0;
            for await (const state of client.policyStates.listQueryResultsForSubscription("latest", subId)) {
              total++;
              if (state.complianceState === "Compliant") passed++;
              else if (state.complianceState === "NonCompliant") failed++;
            }
            return {
              cloud: "azure" as CloudProvider, framework,
              totalChecks: total, passedChecks: passed, failedChecks: failed,
              unknownChecks: total - passed - failed, failingResources: [],
              evaluatedAt: new Date(),
            } satisfies ComplianceSummary;
          }, "Azure Policy");
          if (result.data) summaries.push(result.data);
          if (result.warning) warnings.push(result.warning);
        }));
      }

      if (clouds.includes("gcp")) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { AssetServiceClient } = await import("@google-cloud/asset");
            const client = new AssetServiceClient();
            const scope = process.env["GCP_ORGANIZATION_ID"]
              ? `organizations/${process.env["GCP_ORGANIZATION_ID"]}`
              : `projects/${process.env["GCP_PROJECT_ID"]}`;
            const [assets] = await client.searchAllResources({ scope, pageSize: 500 });
            return {
              cloud: "gcp" as CloudProvider, framework,
              totalChecks: (assets ?? []).length, passedChecks: 0, failedChecks: 0,
              unknownChecks: (assets ?? []).length, failingResources: [],
              evaluatedAt: new Date(),
            } satisfies ComplianceSummary;
          }, "GCP Asset");
          if (result.data) summaries.push(result.data);
          if (result.warning) warnings.push(result.warning);
        }));
      }

      await Promise.all(tasks);

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({ success: true, requestId, data: summaries, warnings: warnings.length > 0 ? warnings : undefined }, null, 2),
        }],
      };
    }
  );

  // ─── X3: multicloud_iam_blast_radius ────────────────────────────
  server.tool(
    "multicloud_iam_blast_radius",
    "Analyze cross-cloud privilege exposure for given identities across AWS, Azure, and GCP",
    {
      awsPrincipalArn: z.string().optional().describe("AWS IAM principal ARN"),
      azurePrincipalId: z.string().optional().describe("Azure AD principal ID"),
      gcpPrincipalEmail: z.string().optional().describe("GCP IAM principal email"),
    },
    async ({ awsPrincipalArn, azurePrincipalId, gcpPrincipalEmail }) => {
      const requestId = uuidv4();
      logger.info("multicloud_iam_blast_radius", { requestId });

      const results: Record<string, unknown> = {};
      const warnings: string[] = [];
      const tasks: Promise<void>[] = [];

      if (awsPrincipalArn) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { AccessAnalyzerClient, ListFindingsCommand } = await import("@aws-sdk/client-accessanalyzer");
            const client = new AccessAnalyzerClient({ region: process.env["AWS_DEFAULT_REGION"] ?? "us-east-1" });
            const resp = await client.send(new ListFindingsCommand({ analyzerArn: awsPrincipalArn, maxResults: 50 }));
            return { cloud: "aws", principal: awsPrincipalArn, findingsCount: resp.findings?.length ?? 0, findings: resp.findings?.slice(0, 20) ?? [] };
          }, "AWS IAM Analyzer");
          if (result.data) results["aws"] = result.data;
          if (result.warning) warnings.push(result.warning);
        }));
      }

      if (azurePrincipalId) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            return { cloud: "azure", principal: azurePrincipalId, note: "Query Entra ID Protection for risky identity details" };
          }, "Azure Entra ID");
          if (result.data) results["azure"] = result.data;
          if (result.warning) warnings.push(result.warning);
        }));
      }

      if (gcpPrincipalEmail) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { google } = await import("googleapis");
            const auth = new google.auth.GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform"] });
            const recommender = google.recommender({ version: "v1", auth });
            const projectId = process.env["GCP_PROJECT_ID"] ?? "";
            const resp = await recommender.projects.locations.recommenders.recommendations.list({
              parent: `projects/${projectId}/locations/global/recommenders/google.iam.policy.Recommender`,
            });
            return { cloud: "gcp", principal: gcpPrincipalEmail, recommendations: resp.data.recommendations?.slice(0, 20) ?? [] };
          }, "GCP IAM Recommender");
          if (result.data) results["gcp"] = result.data;
          if (result.warning) warnings.push(result.warning);
        }));
      }

      await Promise.all(tasks);

      return {
        content: [{ type: "text" as const, text: JSON.stringify({ success: true, requestId, data: results, warnings: warnings.length > 0 ? warnings : undefined }, null, 2) }],
      };
    }
  );

  // ─── X4: multicloud_siem_correlation ────────────────────────────
  server.tool(
    "multicloud_siem_correlation",
    "Correlate security events across AWS CloudTrail, Azure Sentinel, and GCP Audit Logs by IP, account, resource, or email",
    {
      lookbackHours: z.number().min(1).max(720).default(24).describe("Hours to look back"),
      correlationKey: z.enum(["IP", "ACCOUNT_ID", "RESOURCE_ID", "USER_EMAIL"]).describe("Key to correlate across clouds"),
      value: z.string().describe("Value to search for (e.g., IP address, email)"),
    },
    async ({ lookbackHours, correlationKey, value }) => {
      const requestId = uuidv4();
      logger.info("multicloud_siem_correlation", { requestId, correlationKey, value });

      const allFindings: NormalizedFinding[] = [];
      const warnings: string[] = [];
      const since = new Date(Date.now() - lookbackHours * 60 * 60 * 1000);
      const tasks: Promise<void>[] = [];

      tasks.push(limit(async () => {
        const result = await invokeToolSafe(async () => {
          const { CloudTrailClient, LookupEventsCommand } = await import("@aws-sdk/client-cloudtrail");
          const client = new CloudTrailClient({ region: process.env["AWS_DEFAULT_REGION"] ?? "us-east-1" });
          const resp = await client.send(new LookupEventsCommand({ StartTime: since, EndTime: new Date(), MaxResults: 50 }));
          return (resp.Events ?? []).map(e => ({
            id: e.EventId ?? "", cloud: "aws" as CloudProvider, service: "cloudtrail",
            category: "ANOMALOUS_ACTIVITY" as const, severity: "MEDIUM" as const,
            title: e.EventName ?? "CloudTrail Event",
            description: `${e.EventName} by ${e.Username ?? "unknown"}`,
            resourceId: e.EventId ?? "", resourceType: "API Call",
            accountId: e.AccessKeyId ?? undefined, remediationSteps: [],
            complianceFrameworks: [], riskScore: 30,
            firstDetected: e.EventTime ?? new Date(), lastSeen: e.EventTime ?? new Date(),
            rawFinding: e,
          } satisfies NormalizedFinding));
        }, "AWS CloudTrail");
        if (result.data) allFindings.push(...result.data);
        if (result.warning) warnings.push(result.warning);
      }));

      tasks.push(limit(async () => {
        const result = await invokeToolSafe(async () => {
          const { SecurityInsights } = await import("@azure/arm-securityinsight");
          const { DefaultAzureCredential } = await import("@azure/identity");
          const subId = process.env["AZURE_SUBSCRIPTION_ID"] ?? "";
          const workspaceId = process.env["AZURE_LOG_ANALYTICS_WORKSPACE_ID"] ?? "";
          const client = new SecurityInsights(new DefaultAzureCredential(), subId);
          const { normalizeSentinelIncident } = await import("./tools/shared/findings-normalizer.js");
          const incidents: NormalizedFinding[] = [];
          for await (const incident of client.incidents.list("rg-security", workspaceId)) {
            incidents.push(normalizeSentinelIncident(incident as unknown as Record<string, unknown>));
          }
          return incidents;
        }, "Azure Sentinel");
        if (result.data) allFindings.push(...result.data);
        if (result.warning) warnings.push(result.warning);
      }));

      tasks.push(limit(async () => {
        const result = await invokeToolSafe(async () => {
          const { Logging } = await import("@google-cloud/logging");
          const logging = new Logging({ projectId: process.env["GCP_PROJECT_ID"] });
          const [entries] = await logging.getEntries({
            filter: `timestamp>="${since.toISOString()}" AND logName:"cloudaudit.googleapis.com"`,
            pageSize: 50, orderBy: "timestamp desc",
          });
          return (entries ?? []).map(e => {
            const data = e.data as Record<string, unknown> ?? {};
            return {
              id: e.metadata?.insertId ?? "", cloud: "gcp" as CloudProvider, service: "audit-logs",
              category: "ANOMALOUS_ACTIVITY" as const, severity: "MEDIUM" as const,
              title: (data["methodName"] as string) ?? "Audit Log Entry",
              description: `${data["methodName"]} by ${(data["authenticationInfo"] as Record<string, unknown>)?.["principalEmail"] ?? "unknown"}`,
              resourceId: (data["resourceName"] as string) ?? "",
              resourceType: (data["serviceName"] as string) ?? "Unknown",
              remediationSteps: [], complianceFrameworks: [], riskScore: 30,
              firstDetected: new Date(e.metadata?.timestamp as string ?? Date.now()),
              lastSeen: new Date(e.metadata?.timestamp as string ?? Date.now()),
              rawFinding: e.data,
            } satisfies NormalizedFinding;
          });
        }, "GCP Audit Logs");
        if (result.data) allFindings.push(...result.data);
        if (result.warning) warnings.push(result.warning);
      }));

      await Promise.all(tasks);
      const correlated = correlateFindings(allFindings, correlationKey as CorrelationKey, value);

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({ success: true, requestId, data: correlated, totalFindingsScanned: allFindings.length, warnings: warnings.length > 0 ? warnings : undefined }, null, 2),
        }],
      };
    }
  );

  // ─── X5: multicloud_secret_rotation_audit ───────────────────────
  server.tool(
    "multicloud_secret_rotation_audit",
    "Audit secret and key rotation status across AWS Secrets Manager, Azure Key Vault, GCP Secret Manager and KMS",
    {
      clouds: z.array(z.enum(["aws", "azure", "gcp"])).describe("Cloud providers to audit"),
      maxAgeDays: z.number().default(90).describe("Maximum acceptable age in days"),
      includeUnused: z.boolean().default(false).describe("Include unused secrets"),
    },
    async ({ clouds, maxAgeDays, includeUnused }) => {
      const requestId = uuidv4();
      logger.info("multicloud_secret_rotation_audit", { requestId, clouds, maxAgeDays });

      const reports: import("./types/findings.js").SecretRotationReport[] = [];
      const warnings: string[] = [];
      const tasks: Promise<void>[] = [];

      if (clouds.includes("aws")) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { SecretsManagerClient, ListSecretsCommand } = await import("@aws-sdk/client-secrets-manager");
            const client = new SecretsManagerClient({ region: process.env["AWS_DEFAULT_REGION"] ?? "us-east-1" });
            const resp = await client.send(new ListSecretsCommand({ MaxResults: 100 }));
            const entries = (resp.SecretList ?? []).map(s => {
              const age = s.LastChangedDate ? Math.floor((Date.now() - s.LastChangedDate.getTime()) / (1000 * 60 * 60 * 24)) : 999;
              return {
                name: s.Name ?? "", cloud: "aws" as CloudProvider,
                lastRotated: s.LastRotatedDate ?? s.LastChangedDate,
                rotationEnabled: s.RotationEnabled ?? false, ageDays: age, hasPublicAccess: false,
                recommendation: !s.RotationEnabled ? "Enable automatic rotation" : age > maxAgeDays ? "Secret overdue for rotation" : "OK",
              };
            });
            const { buildSecretRotationReport } = await import("./tools/shared/secret-rotation-auditor.js");
            return buildSecretRotationReport(entries, "aws");
          }, "AWS Secrets Manager");
          if (result.data) reports.push(result.data);
          if (result.warning) warnings.push(result.warning);
        }));
      }

      if (clouds.includes("azure")) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { KeyVaultManagementClient } = await import("@azure/arm-keyvault");
            const { DefaultAzureCredential } = await import("@azure/identity");
            const subId = process.env["AZURE_SUBSCRIPTION_ID"] ?? "";
            const client = new KeyVaultManagementClient(new DefaultAzureCredential(), subId);
            const entries: import("./types/findings.js").SecretRotationEntry[] = [];
            for await (const vault of client.vaults.listBySubscription()) {
              entries.push({
                name: vault.name ?? "", cloud: "azure" as CloudProvider,
                rotationEnabled: false, ageDays: 0,
                hasPublicAccess: vault.properties?.publicNetworkAccess === "Enabled",
                recommendation: vault.properties?.enableSoftDelete ? "OK" : "Enable soft delete",
              });
            }
            const { buildSecretRotationReport } = await import("./tools/shared/secret-rotation-auditor.js");
            return buildSecretRotationReport(entries, "azure");
          }, "Azure Key Vault");
          if (result.data) reports.push(result.data);
          if (result.warning) warnings.push(result.warning);
        }));
      }

      if (clouds.includes("gcp")) {
        tasks.push(limit(async () => {
          const result = await invokeToolSafe(async () => {
            const { SecretManagerServiceClient } = await import("@google-cloud/secret-manager");
            const client = new SecretManagerServiceClient();
            const projectId = process.env["GCP_PROJECT_ID"] ?? "";
            const [secrets] = await client.listSecrets({ parent: `projects/${projectId}` });
            const entries = (secrets ?? []).map(s => ({
              name: (s.name ?? "").split("/").pop() ?? "", cloud: "gcp" as CloudProvider,
              rotationEnabled: !!s.rotation?.nextRotationTime,
              ageDays: s.createTime ? Math.floor((Date.now() - new Date(s.createTime as string).getTime()) / (1000 * 60 * 60 * 24)) : 999,
              hasPublicAccess: false,
              recommendation: !s.rotation ? "Configure rotation policy" : "OK",
            }));
            const { buildSecretRotationReport } = await import("./tools/shared/secret-rotation-auditor.js");
            return buildSecretRotationReport(entries, "gcp");
          }, "GCP Secret Manager");
          if (result.data) reports.push(result.data);
          if (result.warning) warnings.push(result.warning);
        }));
      }

      await Promise.all(tasks);
      const merged = mergeSecretRotationReports(reports);

      return {
        content: [{ type: "text" as const, text: JSON.stringify({ success: true, requestId, data: merged, warnings: warnings.length > 0 ? warnings : undefined }, null, 2) }],
      };
    }
  );

  return server;
}
