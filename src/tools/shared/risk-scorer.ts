import { NormalizedFinding, Severity, FindingCategory } from "../../types/findings.js";

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 40,
  HIGH: 30,
  MEDIUM: 20,
  LOW: 10,
  INFO: 5,
};

const CATEGORY_WEIGHTS: Record<FindingCategory, number> = {
  THREAT_DETECTION: 15,
  VULNERABILITY: 12,
  IAM_RISK: 14,
  DATA_EXPOSURE: 13,
  NETWORK_EXPOSURE: 11,
  SECRET_RISK: 14,
  CONTAINER_RISK: 10,
  COMPLIANCE_VIOLATION: 8,
  DLP_VIOLATION: 12,
  ANOMALOUS_ACTIVITY: 13,
};

export function computeRiskScore(finding: NormalizedFinding): number {
  let score = 0;

  // Severity component (0-40)
  score += SEVERITY_WEIGHTS[finding.severity] ?? 5;

  // Category component (0-15)
  score += CATEGORY_WEIGHTS[finding.category] ?? 8;

  // Age factor: older findings get higher scores (0-15)
  const ageDays = Math.floor(
    (Date.now() - finding.firstDetected.getTime()) / (1000 * 60 * 60 * 24)
  );
  if (ageDays > 90) score += 15;
  else if (ageDays > 30) score += 10;
  else if (ageDays > 7) score += 5;

  // Compliance factor (0-10)
  if (finding.complianceFrameworks.length > 0) {
    score += Math.min(finding.complianceFrameworks.length * 2, 10);
  }

  // Resource exposure factor (0-10)
  if (finding.category === "NETWORK_EXPOSURE" || finding.category === "DATA_EXPOSURE") {
    score += 10;
  }

  // CVSS bonus for vulnerability findings (0-10)
  const vulnFinding = finding as unknown as Record<string, unknown>;
  if (typeof vulnFinding["cvssScore"] === "number") {
    score += Math.round(vulnFinding["cvssScore"]);
  }

  return Math.min(100, Math.max(0, score));
}

export function categorizeFindingsBySeverity(
  findings: NormalizedFinding[]
): Record<Severity, NormalizedFinding[]> {
  const result: Record<Severity, NormalizedFinding[]> = {
    CRITICAL: [],
    HIGH: [],
    MEDIUM: [],
    LOW: [],
    INFO: [],
  };
  for (const f of findings) {
    result[f.severity].push(f);
  }
  return result;
}

export function sortByRiskScore(findings: NormalizedFinding[]): NormalizedFinding[] {
  return [...findings].sort((a, b) => b.riskScore - a.riskScore);
}
