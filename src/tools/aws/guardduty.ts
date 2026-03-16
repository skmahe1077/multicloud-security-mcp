import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import {
  GuardDutyClient,
  ListFindingsCommand,
  GetFindingsCommand,
  type FindingCriteria,
} from "@aws-sdk/client-guardduty";
import { logger } from "../../logger.js";
import { normalizeGuardDutyFinding } from "../shared/findings-normalizer.js";
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
    "aws_get_guardduty_threats",
    "List and retrieve AWS GuardDuty threat findings filtered by severity and type",
    {
      detectorId: z.string().describe("GuardDuty detector ID"),
      region: z.string().default("us-east-1").describe("AWS region"),
      severityThreshold: z
        .number()
        .min(0)
        .max(10)
        .default(4)
        .describe("Minimum severity threshold (0-10, where 8+ is critical)"),
      findingType: z.string().optional().describe("Finding type filter (e.g., Recon:EC2/PortProbeUnprotectedPort)"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "aws_get_guardduty_threats" });

      try {
        const client = new GuardDutyClient({
          region: params.region,
          requestHandler: { requestTimeout: 30000 },
        });

        const findingCriteria: FindingCriteria = {
          Criterion: {
            severity: {
              GreaterThanOrEqual: params.severityThreshold,
            },
          },
        };

        if (params.findingType) {
          findingCriteria.Criterion!["type"] = {
            Equals: [params.findingType],
          };
        }

        const listCommand = new ListFindingsCommand({
          DetectorId: params.detectorId,
          FindingCriteria: findingCriteria,
          MaxResults: 50,
        });

        const listResult = await withRetry(() => client.send(listCommand));
        const findingIds = listResult.FindingIds ?? [];

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
          const getCommand = new GetFindingsCommand({
            DetectorId: params.detectorId,
            FindingIds: batch,
          });

          const getResult = await withRetry(() => client.send(getCommand));
          const rawFindings = (getResult.Findings ?? []) as unknown as Record<string, unknown>[];
          const normalized = rawFindings.map((f) => normalizeGuardDutyFinding(f));
          allNormalized.push(...normalized);
        }

        const response: ToolResponse<NormalizedFinding[]> = {
          success: true,
          requestId,
          data: allNormalized,
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
