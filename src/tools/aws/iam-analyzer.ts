import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import {
  AccessAnalyzerClient,
  ListFindingsCommand,
  type ListFindingsCommandInput,
} from "@aws-sdk/client-accessanalyzer";
import { logger } from "../../logger.js";
import { normalizeIAMAccessFinding } from "../shared/findings-normalizer.js";
import { type ToolResponse } from "../../types/findings.js";
import { type IAMRiskFinding } from "../../types/identity.js";

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

export function register(server: McpServer): void {
  server.tool(
    "aws_analyze_iam_access",
    "Analyze IAM access findings using AWS IAM Access Analyzer to detect overprivileged and unused access",
    {
      analyzerArn: z.string().describe("ARN of the IAM Access Analyzer"),
      resourceType: z
        .enum([
          "AWS::IAM::Role",
          "AWS::S3::Bucket",
          "AWS::KMS::Key",
          "AWS::Lambda::Function",
          "AWS::SQS::Queue",
          "AWS::SecretsManager::Secret",
        ])
        .optional()
        .describe("Resource type to filter findings"),
      checkUnusedAccess: z
        .boolean()
        .default(false)
        .describe("Whether to check for unused access findings"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "aws_analyze_iam_access" });

      try {
        // Extract region from the analyzer ARN
        const arnParts = params.analyzerArn.split(":");
        const region = arnParts.length >= 4 ? arnParts[3] : "us-east-1";

        const client = new AccessAnalyzerClient({
          region,
          requestHandler: { requestTimeout: 30000 },
        });

        const input: ListFindingsCommandInput = {
          analyzerArn: params.analyzerArn,
          filter: {
            status: {
              eq: ["ACTIVE"],
            },
          },
          maxResults: 100,
        };

        if (params.resourceType) {
          input.filter!["resourceType"] = {
            eq: [params.resourceType],
          };
        }

        const allFindings: IAMRiskFinding[] = [];
        let nextToken: string | undefined;

        do {
          input.nextToken = nextToken;
          const command = new ListFindingsCommand(input);
          const result = await withRetry(() => client.send(command));

          const rawFindings = (result.findings ?? []) as unknown as Record<string, unknown>[];
          const normalized = rawFindings.map((f) => normalizeIAMAccessFinding(f));
          allFindings.push(...normalized);
          nextToken = result.nextToken;
        } while (nextToken && allFindings.length < 500);

        // Filter for unused access if requested
        const filteredFindings = params.checkUnusedAccess
          ? allFindings.filter(
              (f) =>
                f.unusedPermissionsCount !== undefined && f.unusedPermissionsCount > 0
            )
          : allFindings;

        const response: ToolResponse<{
          findings: IAMRiskFinding[];
          summary: {
            total: number;
            byPrincipalType: Record<string, number>;
            withUnusedAccess: number;
          };
        }> = {
          success: true,
          requestId,
          data: {
            findings: filteredFindings,
            summary: {
              total: filteredFindings.length,
              byPrincipalType: filteredFindings.reduce(
                (acc, f) => {
                  acc[f.principalType] = (acc[f.principalType] ?? 0) + 1;
                  return acc;
                },
                {} as Record<string, number>
              ),
              withUnusedAccess: filteredFindings.filter(
                (f) => f.unusedPermissionsCount !== undefined && f.unusedPermissionsCount > 0
              ).length,
            },
          },
          warnings: nextToken
            ? ["Results were truncated. Narrow filters to see all results."]
            : undefined,
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
