// Public API for programmatic usage.

// Server factory
export { createServer, type CreateServerOptions } from "./server.js";

// Types
export {
  type NormalizedFinding,
  type CloudProvider,
  type FindingCategory,
  type Severity,
  type ComplianceSummary,
  type ComplianceFailure,
  type CorrelatedEvent,
  type SecretRotationReport,
  type SecretRotationEntry,
  type ToolResponse,
} from "./types/findings.js";

export { type VulnerabilityFinding } from "./types/vulnerabilities.js";
export { type IAMRiskFinding } from "./types/identity.js";
export { type NetworkFinding } from "./types/network.js";

// Normalizers
export {
  normalizeSecurityHubFinding,
  normalizeGuardDutyFinding,
  normalizeInspectorFinding,
  normalizeIAMAccessFinding,
  normalizeDefenderAlert,
  normalizeSentinelIncident,
  normalizeEntraRiskyUser,
  normalizeSCCFinding,
  normalizeChronicleDetection,
  normalizeGCPIAMRecommendation,
} from "./tools/shared/findings-normalizer.js";

// Risk scoring
export {
  computeRiskScore,
  categorizeFindingsBySeverity,
  sortByRiskScore,
} from "./tools/shared/risk-scorer.js";

// SIEM correlation
export {
  correlateFindings,
  type CorrelationKey,
} from "./tools/shared/siem-correlator.js";

// Secret rotation
export {
  buildSecretRotationReport,
  mergeSecretRotationReports,
} from "./tools/shared/secret-rotation-auditor.js";
