import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { SecurityCenterClient } from "@google-cloud/security-center";
import { logger } from "../../logger.js";
import { normalizeSCCFinding } from "../shared/findings-normalizer.js";
import { type ToolResponse, type NormalizedFinding } from "../../types/findings.js";

async function withRetry<T>(fn: () => Promise<T>, retries = 5): Promise<T> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (error: unknown) {
      const err = error as { code?: number; status?: number; message?: string };
      if (
        attempt < retries &&
        (err.code === 429 ||
          err.status === 429 ||
          (err.message ?? "").includes("RESOURCE_EXHAUSTED"))
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
    "gcp_get_scc_findings",
    "Retrieve and normalize Google Cloud Security Command Center findings filtered by severity, category, and mute state",
    {
      organizationId: z
        .string()
        .optional()
        .describe("GCP organization ID (e.g., '123456789'). Provide either organizationId or projectId"),
      projectId: z
        .string()
        .optional()
        .describe("GCP project ID. Provide either organizationId or projectId"),
      severity: z
        .enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        .describe("Minimum severity level to filter"),
      category: z
        .string()
        .optional()
        .describe("SCC finding category to filter (e.g., 'OPEN_FIREWALL', 'PUBLIC_BUCKET_ACL')"),
      muted: z
        .boolean()
        .default(false)
        .describe("Whether to include muted findings"),
      findingClass: z
        .enum(["THREAT", "VULNERABILITY", "MISCONFIGURATION", "OBSERVATION", "SCC_ERROR", "POSTURE_VIOLATION"])
        .optional()
        .describe("SCC finding class to filter"),
      maxResults: z
        .number()
        .min(1)
        .max(1000)
        .default(50)
        .describe("Maximum number of findings to return"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "gcp_get_scc_findings" });

      try {
        if (!params.organizationId && !params.projectId) {
          throw new Error("Either organizationId or projectId must be provided");
        }

        const client = new SecurityCenterClient();

        const parent = params.organizationId
          ? `organizations/${params.organizationId}/sources/-`
          : `projects/${params.projectId}/sources/-`;

        const filterParts: string[] = [];

        const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
        const severityIndex = severityOrder.indexOf(params.severity);
        const severityFilters = severityOrder
          .slice(0, severityIndex + 1)
          .map((s) => `severity = "${s}"`)
          .join(" OR ");
        filterParts.push(`(${severityFilters})`);

        if (params.category) {
          filterParts.push(`category = "${params.category}"`);
        }

        if (!params.muted) {
          filterParts.push(`mute != "MUTED"`);
        }

        if (params.findingClass) {
          filterParts.push(`finding_class = "${params.findingClass}"`);
        }

        filterParts.push(`state = "ACTIVE"`);

        const filter = filterParts.join(" AND ");

        logger.debug("SCC query", { requestId, parent, filter });

        const findings: NormalizedFinding[] = [];

        const [response] = await withRetry(() =>
          client.listFindings({
            parent,
            filter,
            pageSize: params.maxResults,
          })
        );

        if (Array.isArray(response)) {
          for (const result of response) {
            const raw = (result as Record<string, unknown>)["finding"] ?? result;
            findings.push(normalizeSCCFinding(raw as Record<string, unknown>));
          }
        }

        logger.info("SCC findings retrieved", {
          requestId,
          count: findings.length,
        });

        const response2: ToolResponse<NormalizedFinding[]> = {
          success: true,
          requestId,
          data: findings,
          warnings:
            findings.length === params.maxResults
              ? ["Results may be truncated. Increase maxResults or narrow filters."]
              : undefined,
        };

        return { content: [{ type: "text", text: JSON.stringify(response2) }] };
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
