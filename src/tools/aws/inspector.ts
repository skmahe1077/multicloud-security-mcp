import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import {
  Inspector2Client,
  ListFindingsCommand,
  type FilterCriteria,
  type StringFilter,
  type NumberFilter,
} from "@aws-sdk/client-inspector2";
import { logger } from "../../logger.js";
import { normalizeInspectorFinding } from "../shared/findings-normalizer.js";
import { type ToolResponse } from "../../types/findings.js";
import { type VulnerabilityFinding } from "../../types/vulnerabilities.js";

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
    "aws_get_inspector_vulnerabilities",
    "Retrieve AWS Inspector vulnerability findings filtered by resource type, severity, and CVSS score",
    {
      region: z.string().default("us-east-1").describe("AWS region"),
      resourceType: z
        .enum(["EC2", "LAMBDA", "ECR"])
        .describe("Type of resource to scan for vulnerabilities"),
      severity: z
        .enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])
        .describe("Minimum severity level"),
      filterByCVSS: z
        .number()
        .min(0)
        .max(10)
        .optional()
        .describe("Minimum CVSS score threshold to filter findings"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "aws_get_inspector_vulnerabilities" });

      try {
        const client = new Inspector2Client({
          region: params.region,
          requestHandler: { requestTimeout: 30000 },
        });

        const filterCriteria: FilterCriteria = {
          resourceType: [
            {
              comparison: "EQUALS",
              value: params.resourceType === "EC2"
                ? "AWS_EC2_INSTANCE"
                : params.resourceType === "LAMBDA"
                  ? "AWS_LAMBDA_FUNCTION"
                  : "AWS_ECR_CONTAINER_IMAGE",
            } as StringFilter,
          ],
          severity: [
            {
              comparison: "EQUALS",
              value: params.severity,
            } as StringFilter,
          ],
          findingStatus: [
            {
              comparison: "EQUALS",
              value: "ACTIVE",
            } as StringFilter,
          ],
        };

        if (params.filterByCVSS !== undefined) {
          filterCriteria.inspectorScore = [
            {
              lowerInclusive: params.filterByCVSS,
              upperInclusive: 10,
            } as NumberFilter,
          ];
        }

        const allFindings: VulnerabilityFinding[] = [];
        let nextToken: string | undefined;

        do {
          const command = new ListFindingsCommand({
            filterCriteria,
            maxResults: 100,
            nextToken,
          });

          const result = await withRetry(() => client.send(command));
          const rawFindings = (result.findings ?? []) as unknown as Record<string, unknown>[];
          const normalized = rawFindings.map((f) => normalizeInspectorFinding(f));
          allFindings.push(...normalized);
          nextToken = result.nextToken;
        } while (nextToken && allFindings.length < 500);

        const response: ToolResponse<VulnerabilityFinding[]> = {
          success: true,
          requestId,
          data: allFindings,
          warnings:
            nextToken
              ? ["Results were truncated at 500 findings. Narrow filters to see all results."]
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
