import { describe, it, expect, vi, beforeEach } from "vitest";
import { correlateFindings, CorrelationKey } from "../src/tools/shared/siem-correlator.js";
import { mergeSecretRotationReports } from "../src/tools/shared/secret-rotation-auditor.js";
import { buildSecretRotationReport } from "../src/tools/shared/secret-rotation-auditor.js";
import { NormalizedFinding, SecretRotationReport, SecretRotationEntry } from "../src/types/findings.js";

function createFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
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
    riskScore: 50,
    firstDetected: new Date(),
    lastSeen: new Date(),
    rawFinding: {},
    ...overrides,
  };
}

describe("SIEM Correlator", () => {
  it("correlates findings by IP across clouds", () => {
    const findings = [
      createFinding({
        id: "aws-1",
        cloud: "aws",
        service: "guardduty",
        rawFinding: { sourceIp: "1.2.3.4", action: "PortProbe" },
      }),
      createFinding({
        id: "gcp-1",
        cloud: "gcp",
        service: "audit-logs",
        rawFinding: { callerIp: "1.2.3.4", methodName: "compute.instances.delete" },
      }),
      createFinding({
        id: "azure-1",
        cloud: "azure",
        service: "sentinel",
        rawFinding: { remoteIp: "5.6.7.8" },
      }),
    ];

    const result = correlateFindings(findings, "IP", "1.2.3.4");

    expect(result).toHaveLength(1);
    expect(result[0].isCrossCloudThreat).toBe(true);
    expect(result[0].clouds).toContain("aws");
    expect(result[0].clouds).toContain("gcp");
    expect(result[0].findings).toHaveLength(2);
    expect(result[0].summary).toContain("CROSS-CLOUD THREAT INDICATOR");
  });

  it("correlates findings by account ID", () => {
    const findings = [
      createFinding({ id: "1", cloud: "aws", accountId: "123456789012" }),
      createFinding({ id: "2", cloud: "aws", accountId: "123456789012" }),
      createFinding({ id: "3", cloud: "aws", accountId: "999999999999" }),
    ];

    const result = correlateFindings(findings, "ACCOUNT_ID", "123456789012");

    expect(result).toHaveLength(1);
    expect(result[0].findings).toHaveLength(2);
    expect(result[0].isCrossCloudThreat).toBe(false);
  });

  it("correlates findings by resource ID", () => {
    const findings = [
      createFinding({ id: "1", cloud: "aws", resourceId: "arn:aws:s3:::my-bucket" }),
      createFinding({ id: "2", cloud: "gcp", resourceId: "projects/test/buckets/other" }),
    ];

    const result = correlateFindings(findings, "RESOURCE_ID", "my-bucket");

    expect(result).toHaveLength(1);
    expect(result[0].findings).toHaveLength(1);
  });

  it("correlates findings by user email across clouds", () => {
    const findings = [
      createFinding({
        id: "1",
        cloud: "aws",
        rawFinding: { userIdentity: { arn: "admin@company.com" } },
      }),
      createFinding({
        id: "2",
        cloud: "azure",
        rawFinding: { userPrincipalName: "admin@company.com" },
      }),
      createFinding({
        id: "3",
        cloud: "gcp",
        rawFinding: { authenticationInfo: { principalEmail: "admin@company.com" } },
      }),
    ];

    const result = correlateFindings(findings, "USER_EMAIL", "admin@company.com");

    expect(result).toHaveLength(1);
    expect(result[0].isCrossCloudThreat).toBe(true);
    expect(result[0].findings).toHaveLength(3);
    expect(result[0].clouds).toHaveLength(3);
  });

  it("returns empty array when no findings match", () => {
    const findings = [
      createFinding({ id: "1", cloud: "aws", accountId: "111111111111" }),
    ];

    const result = correlateFindings(findings, "IP", "9.9.9.9");

    expect(result).toHaveLength(0);
  });
});

describe("Secret Rotation Auditor", () => {
  it("builds a secret rotation report", () => {
    const entries: SecretRotationEntry[] = [
      { name: "secret-1", cloud: "aws", rotationEnabled: true, ageDays: 30, hasPublicAccess: false, recommendation: "OK" },
      { name: "secret-2", cloud: "aws", rotationEnabled: false, ageDays: 120, hasPublicAccess: false, recommendation: "Enable rotation" },
      { name: "secret-3", cloud: "aws", rotationEnabled: true, ageDays: 10, hasPublicAccess: true, recommendation: "Restrict access" },
    ];

    const report = buildSecretRotationReport(entries, "aws");

    expect(report.cloud).toBe("aws");
    expect(report.totalSecrets).toBe(3);
    expect(report.overdueCount).toBe(1);
    expect(report.publicAccess).toBe(1);
    expect(report.neverRotated).toBe(3); // none have lastRotated set
  });

  it("merges reports across clouds", () => {
    const awsReport: SecretRotationReport = {
      cloud: "aws",
      totalSecrets: 10,
      overdueCount: 3,
      neverRotated: 1,
      publicAccess: 0,
      secrets: [],
    };
    const gcpReport: SecretRotationReport = {
      cloud: "gcp",
      totalSecrets: 5,
      overdueCount: 2,
      neverRotated: 2,
      publicAccess: 1,
      secrets: [],
    };

    const merged = mergeSecretRotationReports([awsReport, gcpReport]);

    expect(merged.totalSecrets).toBe(15);
    expect(merged.overdueByCloud["aws"]).toBe(3);
    expect(merged.overdueByCloud["gcp"]).toBe(2);
    expect(merged.publicAccessByCloud["gcp"]).toBe(1);
    expect(merged.recommendedActions.length).toBeGreaterThan(0);
  });

  it("generates recommended actions for issues", () => {
    const report: SecretRotationReport = {
      cloud: "azure",
      totalSecrets: 5,
      overdueCount: 2,
      neverRotated: 1,
      publicAccess: 1,
      secrets: [],
    };

    const merged = mergeSecretRotationReports([report]);

    expect(merged.recommendedActions).toEqual(
      expect.arrayContaining([
        expect.stringContaining("overdue for rotation"),
        expect.stringContaining("public access"),
        expect.stringContaining("never been rotated"),
      ])
    );
  });

  it("handles empty reports", () => {
    const merged = mergeSecretRotationReports([]);

    expect(merged.totalSecrets).toBe(0);
    expect(merged.reports).toHaveLength(0);
    expect(merged.recommendedActions).toHaveLength(0);
  });
});
