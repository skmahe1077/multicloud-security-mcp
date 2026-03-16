import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { google } from "googleapis";
import { logger } from "../../logger.js";
import { normalizeChronicleDetection } from "../shared/findings-normalizer.js";
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
    "gcp_get_chronicle_detections",
    "Retrieve Chronicle SIEM detections for a GCP project, filtered by rule and severity",
    {
      projectId: z.string().describe("GCP project ID hosting the Chronicle instance"),
      ruleId: z
        .string()
        .optional()
        .describe("Specific Chronicle detection rule ID to filter by"),
      severity: z
        .enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        .describe("Minimum severity level to filter"),
      lookbackHours: z
        .number()
        .min(1)
        .max(720)
        .default(24)
        .describe("Number of hours to look back for detections"),
      location: z
        .string()
        .default("us")
        .describe("Chronicle instance location (e.g., 'us', 'europe', 'asia-southeast1')"),
      maxResults: z
        .number()
        .min(1)
        .max(1000)
        .default(50)
        .describe("Maximum number of detections to return"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "gcp_get_chronicle_detections" });

      try {
        const auth = new google.auth.GoogleAuth({
          scopes: ["https://www.googleapis.com/auth/cloud-platform"],
        });
        const authClient = await auth.getClient();

        const now = new Date();
        const startTime = new Date(now.getTime() - params.lookbackHours * 60 * 60 * 1000);

        const baseUrl = `https://${params.location}-chronicle.googleapis.com/v1alpha`;
        const parent = `projects/${params.projectId}/locations/${params.location}/instances/-`;

        let url = `${baseUrl}/${parent}/detections?pageSize=${params.maxResults}`;
        url += `&filter=detection.detectionTime>="${startTime.toISOString()}"`;

        if (params.ruleId) {
          url += ` AND detection.ruleId="${params.ruleId}"`;
        }

        const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
        const severityIndex = severityOrder.indexOf(params.severity);
        if (severityIndex < severityOrder.length - 1) {
          const allowedSeverities = severityOrder.slice(0, severityIndex + 1);
          const severityFilter = allowedSeverities
            .map((s) => `detection.severity="${s}"`)
            .join(" OR ");
          url += ` AND (${severityFilter})`;
        }

        logger.debug("Chronicle API request", { requestId, url });

        const response = await withRetry(async () => {
          const res = await (authClient as { request: (opts: { url: string }) => Promise<{ data: unknown }> }).request({
            url,
          });
          return res.data as Record<string, unknown>;
        });

        const rawDetections = (response["detections"] as Record<string, unknown>[]) ?? [];
        const findings: NormalizedFinding[] = rawDetections.map((d) =>
          normalizeChronicleDetection(d)
        );

        logger.info("Chronicle detections retrieved", {
          requestId,
          count: findings.length,
        });

        const toolResponse: ToolResponse<NormalizedFinding[]> = {
          success: true,
          requestId,
          data: findings,
          warnings:
            findings.length === params.maxResults
              ? ["Results may be truncated. Increase maxResults or narrow filters."]
              : undefined,
        };

        return { content: [{ type: "text", text: JSON.stringify(toolResponse) }] };
      } catch (error) {
        logger.error("Tool failed", { requestId, error: String(error) });
        const toolResponse: ToolResponse = {
          success: false,
          requestId,
          error: String(error),
        };
        return { content: [{ type: "text", text: JSON.stringify(toolResponse) }] };
      }
    }
  );
}
