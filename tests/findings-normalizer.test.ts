import { describe, it, expect } from "vitest";
import {
  normalizeSecurityHubFinding,
  normalizeGuardDutyFinding,
  normalizeInspectorFinding,
  normalizeDefenderAlert,
  normalizeSentinelIncident,
  normalizeEntraRiskyUser,
  normalizeSCCFinding,
  normalizeChronicleDetection,
  normalizeGCPIAMRecommendation,
  normalizeIAMAccessFinding,
} from "../src/tools/shared/findings-normalizer.js";

describe("AWS Normalizers", () => {
  it("normalizes SecurityHub finding", () => {
    const raw = {
      Id: "arn:aws:securityhub:us-east-1:123456789012:finding/test-1",
      Title: "S3 bucket has public access",
      Description: "S3 bucket allows public read access",
      Severity: { Label: "HIGH" },
      Resources: [{ Id: "arn:aws:s3:::test-bucket", Type: "AwsS3Bucket" }],
      Region: "us-east-1",
      AwsAccountId: "123456789012",
      Types: ["Software and Configuration Checks/Industry and Regulatory Standards"],
      FirstObservedAt: "2024-01-01T00:00:00Z",
      LastObservedAt: "2024-01-02T00:00:00Z",
      Compliance: { RelatedRequirements: ["CIS AWS Foundations 2.1.1"] },
      Remediation: { Recommendation: { Text: "Block public access" } },
    };

    const result = normalizeSecurityHubFinding(raw);

    expect(result.cloud).toBe("aws");
    expect(result.service).toBe("security-hub");
    expect(result.severity).toBe("HIGH");
    expect(result.title).toBe("S3 bucket has public access");
    expect(result.resourceId).toBe("arn:aws:s3:::test-bucket");
    expect(result.resourceType).toBe("AwsS3Bucket");
    expect(result.region).toBe("us-east-1");
    expect(result.accountId).toBe("123456789012");
    expect(result.complianceFrameworks).toContain("CIS");
    expect(result.remediationSteps).toContain("Block public access");
    expect(result.riskScore).toBeGreaterThan(0);
    expect(result.riskScore).toBeLessThanOrEqual(100);
  });

  it("normalizes GuardDuty finding", () => {
    const raw = {
      Id: "guardduty-finding-1",
      Title: "Unusual API activity detected",
      Description: "An API was called from an unusual location",
      Severity: 8.5,
      Resource: { InstanceDetails: { InstanceId: "i-1234567890" } },
      ResourceType: "EC2",
      Region: "us-west-2",
      AccountId: "123456789012",
      CreatedAt: "2024-01-01T00:00:00Z",
      UpdatedAt: "2024-01-02T00:00:00Z",
      Service: { Action: { ActionType: "AWS_API_CALL" } },
    };

    const result = normalizeGuardDutyFinding(raw);

    expect(result.cloud).toBe("aws");
    expect(result.service).toBe("guardduty");
    expect(result.category).toBe("THREAT_DETECTION");
    expect(result.severity).toBe("CRITICAL");
    expect(result.resourceId).toBe("i-1234567890");
    expect(result.riskScore).toBeGreaterThan(0);
  });

  it("normalizes Inspector vulnerability finding", () => {
    const raw = {
      FindingArn: "arn:aws:inspector2:us-east-1:123456789012:finding/test-vuln",
      Title: "CVE-2024-1234",
      Description: "Remote code execution vulnerability",
      Severity: "CRITICAL",
      Type: "PACKAGE_VULNERABILITY",
      AwsAccountId: "123456789012",
      FirstObservedAt: "2024-01-01T00:00:00Z",
      LastObservedAt: "2024-01-02T00:00:00Z",
      PackageVulnerabilityDetails: {
        VulnerabilityId: "CVE-2024-1234",
        Cvss: [{ BaseScore: 9.8 }],
        VulnerablePackages: [{
          Name: "openssl",
          Version: "1.0.0",
          FixedInVersion: "1.1.1",
        }],
      },
      Resources: [{ Id: "arn:aws:ec2:us-east-1:123456789012:instance/i-1234" }],
      Remediation: { Recommendation: "Update openssl" },
    };

    const result = normalizeInspectorFinding(raw);

    expect(result.cloud).toBe("aws");
    expect(result.service).toBe("inspector");
    expect(result.category).toBe("VULNERABILITY");
    expect(result.severity).toBe("CRITICAL");
    expect(result.cveId).toBe("CVE-2024-1234");
    expect(result.cvssScore).toBe(9.8);
    expect(result.packageName).toBe("openssl");
    expect(result.fixedVersion).toBe("1.1.1");
  });

  it("normalizes IAM access finding", () => {
    const raw = {
      Id: "iam-finding-1",
      Resource: "arn:aws:s3:::sensitive-bucket",
      ResourceType: "AWS::S3::Bucket",
      Status: "ACTIVE",
      Principal: { AWS: "arn:aws:iam::123456789012:root" },
      Actions: ["s3:GetObject", "s3:PutObject"],
      CreatedAt: "2024-01-01T00:00:00Z",
      UpdatedAt: "2024-01-01T00:00:00Z",
    };

    const result = normalizeIAMAccessFinding(raw);

    expect(result.cloud).toBe("aws");
    expect(result.service).toBe("iam-analyzer");
    expect(result.category).toBe("IAM_RISK");
    expect(result.overprivilegedActions).toEqual(["s3:GetObject", "s3:PutObject"]);
  });

  it("maps severity levels correctly", () => {
    expect(normalizeGuardDutyFinding({ Severity: 9, Id: "1", Title: "", Description: "", CreatedAt: "2024-01-01", UpdatedAt: "2024-01-01" }).severity).toBe("CRITICAL");
    expect(normalizeGuardDutyFinding({ Severity: 7, Id: "2", Title: "", Description: "", CreatedAt: "2024-01-01", UpdatedAt: "2024-01-01" }).severity).toBe("HIGH");
    expect(normalizeGuardDutyFinding({ Severity: 4, Id: "3", Title: "", Description: "", CreatedAt: "2024-01-01", UpdatedAt: "2024-01-01" }).severity).toBe("MEDIUM");
    expect(normalizeGuardDutyFinding({ Severity: 2, Id: "4", Title: "", Description: "", CreatedAt: "2024-01-01", UpdatedAt: "2024-01-01" }).severity).toBe("LOW");
    expect(normalizeGuardDutyFinding({ Severity: 0, Id: "5", Title: "", Description: "", CreatedAt: "2024-01-01", UpdatedAt: "2024-01-01" }).severity).toBe("INFO");
  });
});

describe("Azure Normalizers", () => {
  it("normalizes Defender alert", () => {
    const raw = {
      id: "/subscriptions/sub-1/providers/Microsoft.Security/alerts/alert-1",
      properties: {
        alertDisplayName: "Suspicious login detected",
        description: "A login from an unusual location was detected",
        severity: "High",
        compromisedEntity: "user@example.com",
        remediationSteps: ["Review the login", "Reset credentials"],
        timeGeneratedUtc: "2024-01-01T00:00:00Z",
        processingEndTimeUtc: "2024-01-01T01:00:00Z",
        tactics: ["InitialAccess", "CredentialAccess"],
        resourceIdentifiers: [{ type: "AzureResource" }],
      },
      subscriptionId: "sub-1",
    };

    const result = normalizeDefenderAlert(raw);

    expect(result.cloud).toBe("azure");
    expect(result.service).toBe("defender");
    expect(result.severity).toBe("HIGH");
    expect(result.title).toBe("Suspicious login detected");
    expect(result.resourceId).toBe("user@example.com");
    expect(result.remediationSteps).toHaveLength(2);
    expect(result.complianceFrameworks).toContain("InitialAccess");
  });

  it("normalizes Sentinel incident", () => {
    const raw = {
      id: "/subscriptions/sub-1/incidents/inc-1",
      name: "inc-1",
      properties: {
        title: "Multi-stage attack detected",
        description: "Possible multi-stage attack involving credential theft",
        severity: "High",
        incidentNumber: "42",
        createdTimeUtc: "2024-01-01T00:00:00Z",
        lastModifiedTimeUtc: "2024-01-02T00:00:00Z",
      },
    };

    const result = normalizeSentinelIncident(raw);

    expect(result.cloud).toBe("azure");
    expect(result.service).toBe("sentinel");
    expect(result.severity).toBe("HIGH");
    expect(result.title).toBe("Multi-stage attack detected");
  });

  it("normalizes Entra risky user", () => {
    const raw = {
      id: "user-1",
      userDisplayName: "John Doe",
      userPrincipalName: "john@example.com",
      riskLevel: "high",
      riskState: "atRisk",
      riskDetail: "suspiciousActivity",
      riskLastUpdatedDateTime: "2024-01-01T00:00:00Z",
    };

    const result = normalizeEntraRiskyUser(raw);

    expect(result.cloud).toBe("azure");
    expect(result.service).toBe("entra-id-protection");
    expect(result.category).toBe("IAM_RISK");
    expect(result.severity).toBe("HIGH");
    expect(result.principalType).toBe("user");
    expect(result.title).toContain("John Doe");
  });
});

describe("GCP Normalizers", () => {
  it("normalizes SCC finding", () => {
    const raw = {
      name: "organizations/123/sources/456/findings/finding-1",
      category: "PUBLIC_BUCKET_ACL",
      severity: "HIGH",
      description: "Bucket has public ACL",
      resourceName: "//storage.googleapis.com/projects/_/buckets/public-bucket",
      parent: "organizations/123/sources/456",
      createTime: "2024-01-01T00:00:00Z",
      eventTime: "2024-01-02T00:00:00Z",
      nextSteps: "Remove public ACL from the bucket",
    };

    const result = normalizeSCCFinding(raw);

    expect(result.cloud).toBe("gcp");
    expect(result.service).toBe("scc");
    expect(result.severity).toBe("HIGH");
    expect(result.resourceId).toContain("public-bucket");
    expect(result.remediationSteps).toContain("Remove public ACL from the bucket");
  });

  it("normalizes Chronicle detection", () => {
    const raw = {
      id: "detection-1",
      name: "detection-1",
      severity: "HIGH",
      detectionTime: "2024-01-01T00:00:00Z",
      detection: {
        ruleName: "Suspicious Login",
        description: "Login from TOR exit node",
        severity: "HIGH",
      },
    };

    const result = normalizeChronicleDetection(raw);

    expect(result.cloud).toBe("gcp");
    expect(result.service).toBe("chronicle");
    expect(result.category).toBe("THREAT_DETECTION");
    expect(result.title).toBe("Suspicious Login");
  });

  it("normalizes IAM recommendation", () => {
    const raw = {
      name: "projects/test/locations/global/recommenders/google.iam.policy.Recommender/recommendations/rec-1",
      description: "Remove excess permissions for service account",
      priority: "P1",
      lastRefreshTime: "2024-01-01T00:00:00Z",
      content: {
        overview: {
          member: "serviceAccount:test@project.iam.gserviceaccount.com",
          excessPermissions: ["storage.buckets.delete", "compute.instances.delete"],
        },
        operationGroups: [{
          operations: [{ action: "remove", resource: "roles/editor" }],
        }],
      },
    };

    const result = normalizeGCPIAMRecommendation(raw);

    expect(result.cloud).toBe("gcp");
    expect(result.service).toBe("iam-recommender");
    expect(result.category).toBe("IAM_RISK");
    expect(result.severity).toBe("CRITICAL");
    expect(result.principalType).toBe("service_account");
    expect(result.overprivilegedActions).toHaveLength(2);
    expect(result.unusedPermissionsCount).toBe(2);
  });
});
