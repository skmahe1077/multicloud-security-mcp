import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import {
  SecurityHubClient,
  GetFindingsCommand,
  type AwsSecurityFindingFilters,
  type StringFilter,
  type SeverityLabel,
} from "@aws-sdk/client-securityhub";
import { logger } from "../../logger.js";
import { normalizeSecurityHubFinding } from "../shared/findings-normalizer.js";
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

export function register(server: McpServer): void {
  server.tool(
    "aws_get_security_hub_findings",
    "Retrieve and normalize AWS Security Hub findings filtered by severity, account, and product",
    {
      accountId: z.string().optional().describe("AWS account ID to filter findings"),
      severity: z
        .enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])
        .describe("Minimum severity level to filter"),
      region: z.string().default("us-east-1").describe("AWS region"),
      maxResults: z.number().min(1).max(100).default(20).describe("Maximum number of findings to return"),
      productArn: z.string().optional().describe("ARN of the product to filter findings by"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "aws_get_security_hub_findings" });

      try {
        const client = new SecurityHubClient({
          region: params.region,
          requestHandler: { requestTimeout: 30000 },
        });

        const filters: AwsSecurityFindingFilters = {
          SeverityLabel: [
            {
              Value: params.severity as SeverityLabel,
              Comparison: "EQUALS",
            } as StringFilter,
          ],
          RecordState: [
            {
              Value: "ACTIVE",
              Comparison: "EQUALS",
            } as StringFilter,
          ],
        };

        if (params.accountId) {
          filters.AwsAccountId = [
            { Value: params.accountId, Comparison: "EQUALS" } as StringFilter,
          ];
        }

        if (params.productArn) {
          filters.ProductArn = [
            { Value: params.productArn, Comparison: "EQUALS" } as StringFilter,
          ];
        }

        const command = new GetFindingsCommand({
          Filters: filters,
          MaxResults: params.maxResults,
        });

        const result = await withRetry(() => client.send(command));
        const rawFindings = (result.Findings ?? []) as unknown as Record<string, unknown>[];
        const normalized: NormalizedFinding[] = rawFindings.map((f) =>
          normalizeSecurityHubFinding(f)
        );

        const response: ToolResponse<NormalizedFinding[]> = {
          success: true,
          requestId,
          data: normalized,
          warnings:
            normalized.length === params.maxResults
              ? ["Results may be truncated. Increase maxResults or narrow filters."]
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
