import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import {
  Macie2Client,
  ListFindingsCommand,
  GetFindingsCommand,
  type ListFindingsCommandInput,
  type FindingCriteria,
} from "@aws-sdk/client-macie2";
import { logger } from "../../logger.js";
import { computeRiskScore } from "../shared/risk-scorer.js";
import { type ToolResponse, type NormalizedFinding } from "../../types/findings.js";

async function withRetry<T>(fn: () => Promise<T>, retries = 5): Promise<T> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (error: unknown) {
      const err = error as { name?: string; code?: string };
      if (
        attempt < retries &&
        (err.name === "ThrottlingException" ||
          err.code === "TooManyRequestsException" ||
          err.name === "TooManyRequestsException")
      ) {
        const delay = Math.min(100 * Math.pow(2, attempt) + Math.random() * 100, 10000);
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }
      throw error;
    }
  }
  throw new Error("Retry exhausted");
}

function normalizeMacieFinding(raw: Record<string, unknown>): NormalizedFinding {
  const severity = raw["severity"] as Record<string, unknown> | undefined;
  const severityScore = (severity?.["score"] as number) ?? 0;
  const mappedSeverity =
    severityScore >= 8
      ? "CRITICAL" as const
      : severityScore >= 5
        ? "HIGH" as const
        : severityScore >= 3
          ? "MEDIUM" as const
          : severityScore >= 1
            ? "LOW" as const
            : "INFO" as const;

  const resourcesAffected = raw["resourcesAffected"] as Record<string, unknown> | undefined;
  const s3Bucket = resourcesAffected?.["s3Bucket"] as Record<string, unknown> | undefined;
  const s3Object = resourcesAffected?.["s3Object"] as Record<string, unknown> | undefined;

  const finding: NormalizedFinding = {
    id: (raw["id"] as string) ?? "",
    cloud: "aws",
    service: "macie",
    category: "DATA_EXPOSURE",
    severity: mappedSeverity,
    title: (raw["title"] as string) ?? "Macie Sensitive Data Finding",
    description: (raw["description"] as string) ?? "",
    resourceId: (s3Bucket?.["name"] as string) ?? "",
    resourceType: "AWS::S3::Bucket",
    region: (raw["region"] as string) ?? undefined,
    accountId: (raw["accountId"] as string) ?? undefined,
    remediationSteps: [
      "Review the S3 bucket policy and access controls",
      "Enable server-side encryption if not already enabled",
      "Consider adding S3 Block Public Access settings",
    ],
    complianceFrameworks: ["PCI_DSS", "SOC2", "HIPAA"],
    riskScore: 0,
    firstDetected: new Date((raw["createdAt"] as string) ?? Date.now()),
    lastSeen: new Date((raw["updatedAt"] as string) ?? Date.now()),
    rawFinding: raw,
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

export function register(server: McpServer): void {
  server.tool(
    "aws_scan_macie_sensitive_data",
    "Scan for sensitive data findings from AWS Macie including PII, credentials, and financial data",
    {
      region: z.string().default("us-east-1").describe("AWS region"),
      bucketName: z.string().optional().describe("S3 bucket name to filter findings"),
      classificationJobId: z.string().optional().describe("Classification job ID to filter findings"),
      sensitivityTypes: z
        .array(
          z.enum([
            "CREDENTIALS",
            "FINANCIAL_INFORMATION",
            "PERSONAL_INFORMATION",
            "CUSTOM_IDENTIFIER",
          ])
        )
        .describe("Types of sensitive data to scan for"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "aws_scan_macie_sensitive_data" });

      try {
        const client = new Macie2Client({
          region: params.region,
          requestHandler: { requestTimeout: 30000 },
        });

        const findingCriteria: FindingCriteria = {
          criterion: {
            "category": {
              eq: ["CLASSIFICATION"],
            },
          },
        };

        if (params.bucketName) {
          findingCriteria.criterion!["resourcesAffected.s3Bucket.name"] = {
            eq: [params.bucketName],
          };
        }

        if (params.classificationJobId) {
          findingCriteria.criterion!["classificationDetails.jobId"] = {
            eq: [params.classificationJobId],
          };
        }

        const listInput: ListFindingsCommandInput = {
          findingCriteria,
          maxResults: 50,
        };

        const listResult = await withRetry(() => client.send(new ListFindingsCommand(listInput)));
        const findingIds = listResult.findingIds ?? [];

        if (findingIds.length === 0) {
          const response: ToolResponse<NormalizedFinding[]> = {
            success: true,
            requestId,
            data: [],
          };
          return { content: [{ type: "text", text: JSON.stringify(response) }] };
        }

        // GetFindings accepts up to 50 IDs at a time
        const batchSize = 50;
        const allNormalized: NormalizedFinding[] = [];

        for (let i = 0; i < findingIds.length; i += batchSize) {
          const batch = findingIds.slice(i, i + batchSize);
          const getResult = await withRetry(() =>
            client.send(new GetFindingsCommand({ findingIds: batch }))
          );
          const rawFindings = (getResult.findings ?? []) as unknown as Record<string, unknown>[];
          const normalized = rawFindings.map((f) => normalizeMacieFinding(f));
          allNormalized.push(...normalized);
        }

        // Filter by sensitivity types if specified
        const filtered = allNormalized.filter((f) => {
          const raw = f.rawFinding as Record<string, unknown>;
          const classificationDetails = raw["classificationDetails"] as Record<string, unknown> | undefined;
          const result = classificationDetails?.["result"] as Record<string, unknown> | undefined;
          const sensitiveData = result?.["sensitiveData"] as Record<string, unknown>[] | undefined;
          if (!sensitiveData) return true;
          return sensitiveData.some((sd) => {
            const category = (sd["category"] as string) ?? "";
            return params.sensitivityTypes.some((t) => category.toUpperCase().includes(t));
          });
        });

        const response: ToolResponse<NormalizedFinding[]> = {
          success: true,
          requestId,
          data: filtered,
        };

        return { content: [{ type: "text", text: JSON.stringify(response) }] };
      } catch (error) {
        logger.error("Tool failed", { requestId, error: String(error) });
        const response: ToolResponse = {
          success: false,
          requestId,
          error: String(error),
        };
        return { content: [{ type: "text", text: JSON.stringify(response) }] };
      }
    }
  );
}
