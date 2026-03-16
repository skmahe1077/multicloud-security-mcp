import { describe, it, expect } from "vitest";
import { computeRiskScore, categorizeFindingsBySeverity, sortByRiskScore } from "../src/tools/shared/risk-scorer.js";
import { NormalizedFinding } from "../src/types/findings.js";

function createMockFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    id: "test-1",
    cloud: "aws",
    service: "test",
    category: "THREAT_DETECTION",
    severity: "MEDIUM",
    title: "Test Finding",
    description: "Test description",
    resourceId: "resource-1",
    resourceType: "TestResource",
    remediationSteps: [],
    complianceFrameworks: [],
    riskScore: 0,
    firstDetected: new Date(),
    lastSeen: new Date(),
    rawFinding: {},
    ...overrides,
  };
}

describe("computeRiskScore", () => {
  it("returns higher scores for critical severity", () => {
    const critical = computeRiskScore(createMockFinding({ severity: "CRITICAL" }));
    const low = computeRiskScore(createMockFinding({ severity: "LOW" }));
    expect(critical).toBeGreaterThan(low);
  });

  it("returns scores between 0 and 100", () => {
    const score = computeRiskScore(createMockFinding({ severity: "CRITICAL" }));
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  it("gives higher scores to older findings", () => {
    const old = computeRiskScore(createMockFinding({
      firstDetected: new Date(Date.now() - 100 * 24 * 60 * 60 * 1000),
    }));
    const recent = computeRiskScore(createMockFinding({
      firstDetected: new Date(),
    }));
    expect(old).toBeGreaterThan(recent);
  });

  it("gives higher scores for compliance-mapped findings", () => {
    const withCompliance = computeRiskScore(createMockFinding({
      complianceFrameworks: ["CIS", "NIST", "SOC2"],
    }));
    const withoutCompliance = computeRiskScore(createMockFinding({
      complianceFrameworks: [],
    }));
    expect(withCompliance).toBeGreaterThan(withoutCompliance);
  });

  it("gives bonus for network/data exposure categories", () => {
    const exposed = computeRiskScore(createMockFinding({
      category: "NETWORK_EXPOSURE",
      severity: "MEDIUM",
    }));
    const notExposed = computeRiskScore(createMockFinding({
      category: "COMPLIANCE_VIOLATION",
      severity: "MEDIUM",
    }));
    expect(exposed).toBeGreaterThan(notExposed);
  });

  it("incorporates CVSS score for vulnerability findings", () => {
    const withCvss = computeRiskScore(createMockFinding({
      category: "VULNERABILITY",
      severity: "HIGH",
    }) as NormalizedFinding & { cvssScore: number });

    // Manually set cvssScore
    const vulnFinding = { ...createMockFinding({ category: "VULNERABILITY", severity: "HIGH" }), cvssScore: 9.8 };
    const withHighCvss = computeRiskScore(vulnFinding as unknown as NormalizedFinding);

    expect(withHighCvss).toBeGreaterThan(withCvss);
  });
});

describe("categorizeFindingsBySeverity", () => {
  it("groups findings by severity", () => {
    const findings = [
      createMockFinding({ severity: "CRITICAL", id: "1" }),
      createMockFinding({ severity: "HIGH", id: "2" }),
      createMockFinding({ severity: "HIGH", id: "3" }),
      createMockFinding({ severity: "MEDIUM", id: "4" }),
      createMockFinding({ severity: "LOW", id: "5" }),
      createMockFinding({ severity: "INFO", id: "6" }),
    ];

    const result = categorizeFindingsBySeverity(findings);

    expect(result.CRITICAL).toHaveLength(1);
    expect(result.HIGH).toHaveLength(2);
    expect(result.MEDIUM).toHaveLength(1);
    expect(result.LOW).toHaveLength(1);
    expect(result.INFO).toHaveLength(1);
  });

  it("returns empty arrays for missing severities", () => {
    const result = categorizeFindingsBySeverity([]);
    expect(result.CRITICAL).toHaveLength(0);
    expect(result.HIGH).toHaveLength(0);
  });
});

describe("sortByRiskScore", () => {
  it("sorts findings by risk score descending", () => {
    const findings = [
      createMockFinding({ riskScore: 30, id: "1" }),
      createMockFinding({ riskScore: 90, id: "2" }),
      createMockFinding({ riskScore: 60, id: "3" }),
    ];

    const sorted = sortByRiskScore(findings);

    expect(sorted[0].riskScore).toBe(90);
    expect(sorted[1].riskScore).toBe(60);
    expect(sorted[2].riskScore).toBe(30);
  });

  it("does not mutate the original array", () => {
    const findings = [
      createMockFinding({ riskScore: 10, id: "1" }),
      createMockFinding({ riskScore: 50, id: "2" }),
    ];
    const original = [...findings];
    sortByRiskScore(findings);
    expect(findings[0].id).toBe(original[0].id);
  });
});
