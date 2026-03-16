export type CloudProvider = "aws" | "azure" | "gcp";

export type FindingCategory =
  | "THREAT_DETECTION"
  | "VULNERABILITY"
  | "IAM_RISK"
  | "DATA_EXPOSURE"
  | "NETWORK_EXPOSURE"
  | "SECRET_RISK"
  | "CONTAINER_RISK"
  | "COMPLIANCE_VIOLATION"
  | "DLP_VIOLATION"
  | "ANOMALOUS_ACTIVITY";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface NormalizedFinding {
  id: string;
  cloud: CloudProvider;
  service: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  resourceId: string;
  resourceType: string;
  region?: string;
  accountId?: string;
  remediationSteps: string[];
  complianceFrameworks: string[];
  riskScore: number;
  firstDetected: Date;
  lastSeen: Date;
  rawFinding: unknown;
}

export interface ComplianceSummary {
  cloud: CloudProvider;
  framework: string;
  frameworkVersion?: string;
  totalChecks: number;
  passedChecks: number;
  failedChecks: number;
  unknownChecks: number;
  failingResources: ComplianceFailure[];
  evaluatedAt: Date;
}

export interface ComplianceFailure {
  ruleId: string;
  ruleName: string;
  resourceId: string;
  resourceType: string;
  region?: string;
  remediationUrl?: string;
}

export interface CorrelatedEvent {
  correlationKey: string;
  correlationValue: string;
  clouds: CloudProvider[];
  findings: NormalizedFinding[];
  isCrossCloudThreat: boolean;
  summary: string;
}

export interface SecretRotationReport {
  cloud: CloudProvider;
  totalSecrets: number;
  overdueCount: number;
  neverRotated: number;
  publicAccess: number;
  secrets: SecretRotationEntry[];
}

export interface SecretRotationEntry {
  name: string;
  cloud: CloudProvider;
  lastRotated?: Date;
  rotationEnabled: boolean;
  ageDays: number;
  hasPublicAccess: boolean;
  recommendation: string;
}

export interface ToolResponse<T = unknown> {
  success: boolean;
  requestId: string;
  data?: T;
  warnings?: string[];
  error?: string;
}
