import {
  NormalizedFinding,
  FindingCategory,
  Severity,
  CloudProvider,
} from "../../types/findings.js";
import { VulnerabilityFinding } from "../../types/vulnerabilities.js";
import { IAMRiskFinding } from "../../types/identity.js";
import { NetworkFinding } from "../../types/network.js";
import { computeRiskScore } from "./risk-scorer.js";

// ─── AWS Normalizers ────────────────────────────────────────────────

export function normalizeSecurityHubFinding(raw: Record<string, unknown>): NormalizedFinding {
  const severity = mapAwsSeverity(raw["Severity"] as Record<string, unknown>);
  const finding: NormalizedFinding = {
    id: (raw["Id"] as string) ?? "",
    cloud: "aws",
    service: "security-hub",
    category: mapSecurityHubCategory(raw["Types"] as string[] | undefined),
    severity,
    title: (raw["Title"] as string) ?? "",
    description: (raw["Description"] as string) ?? "",
    resourceId: extractAwsResourceId(raw["Resources"] as Record<string, unknown>[] | undefined),
    resourceType: extractAwsResourceType(raw["Resources"] as Record<string, unknown>[] | undefined),
    region: (raw["Region"] as string) ?? undefined,
    accountId: (raw["AwsAccountId"] as string) ?? undefined,
    remediationSteps: extractRemediationSteps(raw["Remediation"] as Record<string, unknown> | undefined),
    complianceFrameworks: extractComplianceFrameworks(raw["Compliance"] as Record<string, unknown> | undefined),
    riskScore: 0,
    firstDetected: new Date((raw["FirstObservedAt"] as string) ?? Date.now()),
    lastSeen: new Date((raw["LastObservedAt"] as string) ?? Date.now()),
    rawFinding: raw,
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

export function normalizeGuardDutyFinding(raw: Record<string, unknown>): NormalizedFinding {
  const severityValue = (raw["Severity"] as number) ?? 0;
  const finding: NormalizedFinding = {
    id: (raw["Id"] as string) ?? "",
    cloud: "aws",
    service: "guardduty",
    category: "THREAT_DETECTION",
    severity: mapGuardDutySeverity(severityValue),
    title: (raw["Title"] as string) ?? "",
    description: (raw["Description"] as string) ?? "",
    resourceId: extractGuardDutyResourceId(raw["Resource"] as Record<string, unknown> | undefined),
    resourceType: (raw["ResourceType"] as string) ?? "Unknown",
    region: (raw["Region"] as string) ?? undefined,
    accountId: (raw["AccountId"] as string) ?? undefined,
    remediationSteps: [(raw["Service"] as Record<string, unknown>)?.["Action"] ? "Review the action details and block if malicious" : "Investigate the finding in GuardDuty console"],
    complianceFrameworks: [],
    riskScore: 0,
    firstDetected: new Date((raw["CreatedAt"] as string) ?? Date.now()),
    lastSeen: new Date((raw["UpdatedAt"] as string) ?? Date.now()),
    rawFinding: raw,
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

export function normalizeInspectorFinding(raw: Record<string, unknown>): VulnerabilityFinding {
  const vuln = raw["PackageVulnerabilityDetails"] as Record<string, unknown> | undefined;
  const finding: VulnerabilityFinding = {
    id: (raw["FindingArn"] as string) ?? "",
    cloud: "aws",
    service: "inspector",
    category: "VULNERABILITY",
    severity: mapAwsInspectorSeverity((raw["Severity"] as string) ?? "INFORMATIONAL"),
    title: (raw["Title"] as string) ?? "",
    description: (raw["Description"] as string) ?? "",
    resourceId: (raw["AwsAccountId"] as string) ?? "",
    resourceType: (raw["Type"] as string) ?? "Unknown",
    region: undefined,
    accountId: (raw["AwsAccountId"] as string) ?? undefined,
    remediationSteps: [(raw["Remediation"] as Record<string, unknown>)?.["Recommendation"] ? String((raw["Remediation"] as Record<string, unknown>)["Recommendation"]) : "Update the affected package to the fixed version"],
    complianceFrameworks: [],
    riskScore: 0,
    firstDetected: new Date((raw["FirstObservedAt"] as string) ?? Date.now()),
    lastSeen: new Date((raw["LastObservedAt"] as string) ?? Date.now()),
    rawFinding: raw,
    cveId: vuln?.["VulnerabilityId"] as string | undefined,
    cvssScore: extractCvssScore(vuln),
    packageName: (vuln?.["VulnerablePackages"] as Record<string, unknown>[])?.[0]?.["Name"] as string | undefined,
    packageVersion: (vuln?.["VulnerablePackages"] as Record<string, unknown>[])?.[0]?.["Version"] as string | undefined,
    fixedVersion: (vuln?.["VulnerablePackages"] as Record<string, unknown>[])?.[0]?.["FixedInVersion"] as string | undefined,
    affectedResource: (raw["Resources"] as Record<string, unknown>[])?.[0]?.["Id"] as string ?? "",
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

export function normalizeIAMAccessFinding(raw: Record<string, unknown>): IAMRiskFinding {
  const finding: IAMRiskFinding = {
    id: (raw["Id"] as string) ?? "",
    cloud: "aws",
    service: "iam-analyzer",
    category: "IAM_RISK",
    severity: mapAwsSeverity({ Label: raw["Status"] === "ACTIVE" ? "HIGH" : "MEDIUM" }),
    title: `IAM Access Finding: ${(raw["ResourceType"] as string) ?? "Unknown"}`,
    description: `External access to ${(raw["Resource"] as string) ?? "unknown resource"} via ${(raw["Principal"] as Record<string, unknown>)?.["AWS"] ?? "unknown principal"}`,
    resourceId: (raw["Resource"] as string) ?? "",
    resourceType: (raw["ResourceType"] as string) ?? "Unknown",
    remediationSteps: ["Review the IAM policy and restrict access", "Remove unused permissions"],
    complianceFrameworks: ["CIS", "SOC2"],
    riskScore: 0,
    firstDetected: new Date((raw["CreatedAt"] as string) ?? Date.now()),
    lastSeen: new Date((raw["UpdatedAt"] as string) ?? Date.now()),
    rawFinding: raw,
    principalType: mapAwsPrincipalType(raw),
    unusedPermissionsCount: (raw["UnusedPermissions"] as string[] | undefined)?.length,
    lastActivityDate: raw["LastAccessed"] ? new Date(raw["LastAccessed"] as string) : undefined,
    hasConsoleAccess: undefined,
    hasMFAEnabled: undefined,
    overprivilegedActions: (raw["Actions"] as string[]) ?? [],
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

// ─── Azure Normalizers ──────────────────────────────────────────────

export function normalizeDefenderAlert(raw: Record<string, unknown>): NormalizedFinding {
  const props = (raw["properties"] as Record<string, unknown>) ?? raw;
  const finding: NormalizedFinding = {
    id: (raw["id"] as string) ?? "",
    cloud: "azure",
    service: "defender",
    category: "THREAT_DETECTION",
    severity: mapAzureSeverity((props["severity"] as string) ?? "Medium"),
    title: (props["alertDisplayName"] as string) ?? "",
    description: (props["description"] as string) ?? "",
    resourceId: (props["compromisedEntity"] as string) ?? "",
    resourceType: (props["resourceIdentifiers"] as Record<string, unknown>[])?.[0]?.["type"] as string ?? "Unknown",
    region: undefined,
    accountId: (raw["subscriptionId"] as string) ?? undefined,
    remediationSteps: ((props["remediationSteps"] as string[]) ?? []),
    complianceFrameworks: extractMitreTactics(props),
    riskScore: 0,
    firstDetected: new Date((props["timeGeneratedUtc"] as string) ?? Date.now()),
    lastSeen: new Date((props["processingEndTimeUtc"] as string) ?? Date.now()),
    rawFinding: raw,
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

export function normalizeSentinelIncident(raw: Record<string, unknown>): NormalizedFinding {
  const props = (raw["properties"] as Record<string, unknown>) ?? raw;
  const finding: NormalizedFinding = {
    id: (raw["id"] as string) ?? (raw["name"] as string) ?? "",
    cloud: "azure",
    service: "sentinel",
    category: "THREAT_DETECTION",
    severity: mapAzureSeverity((props["severity"] as string) ?? "Medium"),
    title: (props["title"] as string) ?? "",
    description: (props["description"] as string) ?? "",
    resourceId: (props["incidentNumber"] as string) ?? String(props["incidentNumber"] ?? ""),
    resourceType: "Incident",
    region: undefined,
    accountId: undefined,
    remediationSteps: [],
    complianceFrameworks: [],
    riskScore: 0,
    firstDetected: new Date((props["createdTimeUtc"] as string) ?? Date.now()),
    lastSeen: new Date((props["lastModifiedTimeUtc"] as string) ?? Date.now()),
    rawFinding: raw,
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

export function normalizeEntraRiskyUser(raw: Record<string, unknown>): IAMRiskFinding {
  const finding: IAMRiskFinding = {
    id: (raw["id"] as string) ?? "",
    cloud: "azure",
    service: "entra-id-protection",
    category: "IAM_RISK",
    severity: mapAzureRiskLevel((raw["riskLevel"] as string) ?? "medium"),
    title: `Risky Identity: ${(raw["userDisplayName"] as string) ?? (raw["userPrincipalName"] as string) ?? "Unknown"}`,
    description: `Risk state: ${(raw["riskState"] as string) ?? "unknown"}, Detail: ${(raw["riskDetail"] as string) ?? "none"}`,
    resourceId: (raw["userPrincipalName"] as string) ?? "",
    resourceType: "User",
    remediationSteps: ["Review sign-in activity", "Enforce MFA", "Reset credentials if compromised"],
    complianceFrameworks: ["CIS", "SOC2", "NIST"],
    riskScore: 0,
    firstDetected: new Date((raw["riskLastUpdatedDateTime"] as string) ?? Date.now()),
    lastSeen: new Date((raw["riskLastUpdatedDateTime"] as string) ?? Date.now()),
    rawFinding: raw,
    principalType: "user",
    lastActivityDate: raw["lastSignInDateTime"] ? new Date(raw["lastSignInDateTime"] as string) : undefined,
    hasMFAEnabled: undefined,
    hasConsoleAccess: true,
    overprivilegedActions: [],
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

// ─── GCP Normalizers ────────────────────────────────────────────────

export function normalizeSCCFinding(raw: Record<string, unknown>): NormalizedFinding {
  const finding: NormalizedFinding = {
    id: (raw["name"] as string) ?? "",
    cloud: "gcp",
    service: "scc",
    category: mapSCCCategory((raw["category"] as string) ?? ""),
    severity: mapGcpSeverity((raw["severity"] as string) ?? "MEDIUM"),
    title: (raw["category"] as string) ?? "",
    description: (raw["description"] as string) ?? (raw["category"] as string) ?? "",
    resourceId: (raw["resourceName"] as string) ?? "",
    resourceType: (raw["resourceName"] as string)?.split("/")?.[2] ?? "Unknown",
    region: undefined,
    accountId: (raw["parent"] as string)?.split("/")?.[1] ?? undefined,
    remediationSteps: raw["nextSteps"] ? [(raw["nextSteps"] as string)] : ["Review the finding in Security Command Center"],
    complianceFrameworks: extractSCCCompliance(raw),
    riskScore: 0,
    firstDetected: new Date((raw["createTime"] as string) ?? Date.now()),
    lastSeen: new Date((raw["eventTime"] as string) ?? Date.now()),
    rawFinding: raw,
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

export function normalizeChronicleDetection(raw: Record<string, unknown>): NormalizedFinding {
  const detection = (raw["detection"] as Record<string, unknown>) ?? raw;
  const finding: NormalizedFinding = {
    id: (raw["id"] as string) ?? (raw["name"] as string) ?? "",
    cloud: "gcp",
    service: "chronicle",
    category: "THREAT_DETECTION",
    severity: mapGcpSeverity((detection["severity"] as string) ?? (raw["severity"] as string) ?? "MEDIUM"),
    title: (detection["ruleName"] as string) ?? (raw["ruleName"] as string) ?? "Chronicle Detection",
    description: (detection["description"] as string) ?? "",
    resourceId: "",
    resourceType: "Detection",
    remediationSteps: ["Investigate in Chronicle SIEM", "Review UDM events"],
    complianceFrameworks: [],
    riskScore: 0,
    firstDetected: new Date((raw["detectionTime"] as string) ?? Date.now()),
    lastSeen: new Date((raw["detectionTime"] as string) ?? Date.now()),
    rawFinding: raw,
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

export function normalizeGCPIAMRecommendation(raw: Record<string, unknown>): IAMRiskFinding {
  const content = (raw["content"] as Record<string, unknown>) ?? {};
  const overview = (content["overview"] as Record<string, unknown>) ?? {};
  const finding: IAMRiskFinding = {
    id: (raw["name"] as string) ?? "",
    cloud: "gcp",
    service: "iam-recommender",
    category: "IAM_RISK",
    severity: mapGcpRecommenderPriority((raw["priority"] as string) ?? "P2"),
    title: (raw["description"] as string) ?? "IAM Recommendation",
    description: (raw["description"] as string) ?? "",
    resourceId: (overview["member"] as string) ?? "",
    resourceType: "IAM Binding",
    remediationSteps: extractRecommenderActions(raw),
    complianceFrameworks: ["CIS"],
    riskScore: 0,
    firstDetected: new Date((raw["lastRefreshTime"] as string) ?? Date.now()),
    lastSeen: new Date((raw["lastRefreshTime"] as string) ?? Date.now()),
    rawFinding: raw,
    principalType: "service_account",
    unusedPermissionsCount: (overview["excessPermissions"] as string[] | undefined)?.length,
    overprivilegedActions: (overview["excessPermissions"] as string[]) ?? [],
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

// ─── Helpers ────────────────────────────────────────────────────────

function mapAwsSeverity(severity: Record<string, unknown> | undefined): Severity {
  const label = ((severity?.["Label"] as string) ?? "INFORMATIONAL").toUpperCase();
  const map: Record<string, Severity> = {
    CRITICAL: "CRITICAL",
    HIGH: "HIGH",
    MEDIUM: "MEDIUM",
    LOW: "LOW",
    INFORMATIONAL: "INFO",
  };
  return map[label] ?? "INFO";
}

function mapGuardDutySeverity(value: number): Severity {
  if (value >= 8) return "CRITICAL";
  if (value >= 7) return "HIGH";
  if (value >= 4) return "MEDIUM";
  if (value >= 1) return "LOW";
  return "INFO";
}

function mapAwsInspectorSeverity(severity: string): Severity {
  const map: Record<string, Severity> = {
    CRITICAL: "CRITICAL",
    HIGH: "HIGH",
    MEDIUM: "MEDIUM",
    LOW: "LOW",
    INFORMATIONAL: "INFO",
    UNTRIAGED: "INFO",
  };
  return map[severity.toUpperCase()] ?? "INFO";
}

function mapAzureSeverity(severity: string): Severity {
  const map: Record<string, Severity> = {
    High: "HIGH",
    Medium: "MEDIUM",
    Low: "LOW",
    Informational: "INFO",
  };
  return map[severity] ?? "MEDIUM";
}

function mapAzureRiskLevel(level: string): Severity {
  const map: Record<string, Severity> = {
    high: "HIGH",
    medium: "MEDIUM",
    low: "LOW",
    hidden: "INFO",
    none: "INFO",
  };
  return map[level.toLowerCase()] ?? "MEDIUM";
}

function mapGcpSeverity(severity: string): Severity {
  const map: Record<string, Severity> = {
    CRITICAL: "CRITICAL",
    HIGH: "HIGH",
    MEDIUM: "MEDIUM",
    LOW: "LOW",
  };
  return map[severity.toUpperCase()] ?? "INFO";
}

function mapGcpRecommenderPriority(priority: string): Severity {
  const map: Record<string, Severity> = {
    P1: "CRITICAL",
    P2: "HIGH",
    P3: "MEDIUM",
    P4: "LOW",
  };
  return map[priority] ?? "MEDIUM";
}

function mapSecurityHubCategory(types: string[] | undefined): FindingCategory {
  if (!types?.length) return "THREAT_DETECTION";
  const type = types[0].toLowerCase();
  if (type.includes("vulnerability") || type.includes("software")) return "VULNERABILITY";
  if (type.includes("iam") || type.includes("access")) return "IAM_RISK";
  if (type.includes("data") || type.includes("sensitive")) return "DATA_EXPOSURE";
  if (type.includes("network") || type.includes("reachability")) return "NETWORK_EXPOSURE";
  if (type.includes("container")) return "CONTAINER_RISK";
  if (type.includes("compliance") || type.includes("policy")) return "COMPLIANCE_VIOLATION";
  return "THREAT_DETECTION";
}

function mapSCCCategory(category: string): FindingCategory {
  const lower = category.toLowerCase();
  if (lower.includes("vulnerability")) return "VULNERABILITY";
  if (lower.includes("iam") || lower.includes("identity")) return "IAM_RISK";
  if (lower.includes("data")) return "DATA_EXPOSURE";
  if (lower.includes("network") || lower.includes("firewall")) return "NETWORK_EXPOSURE";
  if (lower.includes("container") || lower.includes("gke")) return "CONTAINER_RISK";
  if (lower.includes("compliance") || lower.includes("policy")) return "COMPLIANCE_VIOLATION";
  if (lower.includes("anomal")) return "ANOMALOUS_ACTIVITY";
  return "THREAT_DETECTION";
}

function extractAwsResourceId(resources: Record<string, unknown>[] | undefined): string {
  return (resources?.[0]?.["Id"] as string) ?? "";
}

function extractAwsResourceType(resources: Record<string, unknown>[] | undefined): string {
  return (resources?.[0]?.["Type"] as string) ?? "Unknown";
}

function extractRemediationSteps(remediation: Record<string, unknown> | undefined): string[] {
  if (!remediation) return [];
  const rec = remediation["Recommendation"] as Record<string, unknown> | undefined;
  if (rec?.["Text"]) return [rec["Text"] as string];
  return [];
}

function extractComplianceFrameworks(compliance: Record<string, unknown> | undefined): string[] {
  if (!compliance) return [];
  const standards = compliance["RelatedRequirements"] as string[] | undefined;
  if (!standards?.length) return [];
  const frameworks = new Set<string>();
  for (const s of standards) {
    if (s.includes("CIS")) frameworks.add("CIS");
    if (s.includes("NIST")) frameworks.add("NIST");
    if (s.includes("SOC")) frameworks.add("SOC2");
    if (s.includes("ISO")) frameworks.add("ISO27001");
    if (s.includes("PCI")) frameworks.add("PCI_DSS");
  }
  return Array.from(frameworks);
}

function extractGuardDutyResourceId(resource: Record<string, unknown> | undefined): string {
  if (!resource) return "";
  const instanceDetails = resource["InstanceDetails"] as Record<string, unknown> | undefined;
  if (instanceDetails?.["InstanceId"]) return instanceDetails["InstanceId"] as string;
  const accessKeyDetails = resource["AccessKeyDetails"] as Record<string, unknown> | undefined;
  if (accessKeyDetails?.["AccessKeyId"]) return accessKeyDetails["AccessKeyId"] as string;
  return "";
}

function extractCvssScore(vuln: Record<string, unknown> | undefined): number | undefined {
  if (!vuln) return undefined;
  const scores = vuln["Cvss"] as Record<string, unknown>[] | undefined;
  if (scores?.length) return scores[0]["BaseScore"] as number;
  return undefined;
}

function mapAwsPrincipalType(raw: Record<string, unknown>): IAMRiskFinding["principalType"] {
  const rt = (raw["ResourceType"] as string) ?? "";
  if (rt.includes("Role")) return "role";
  if (rt.includes("User")) return "user";
  return "role";
}

function extractMitreTactics(props: Record<string, unknown>): string[] {
  const tactics = props["tactics"] as string[] | undefined;
  return tactics ?? [];
}

function extractSCCCompliance(raw: Record<string, unknown>): string[] {
  const compliances = raw["compliances"] as Record<string, unknown>[] | undefined;
  if (!compliances?.length) return [];
  return compliances.map((c) => (c["standard"] as string) ?? "").filter(Boolean);
}

function extractRecommenderActions(raw: Record<string, unknown>): string[] {
  const content = raw["content"] as Record<string, unknown> | undefined;
  const operationGroups = content?.["operationGroups"] as Record<string, unknown>[] | undefined;
  if (!operationGroups?.length) return ["Follow IAM Recommender suggestions"];
  return operationGroups.map((g) => {
    const ops = g["operations"] as Record<string, unknown>[] | undefined;
    return ops?.map((o) => `${o["action"]} on ${o["resource"]}`).join(", ") ?? "";
  }).filter(Boolean);
}
