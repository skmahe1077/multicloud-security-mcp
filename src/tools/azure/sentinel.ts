import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { SecurityInsights } from "@azure/arm-securityinsight";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { normalizeSentinelIncident } from "../shared/findings-normalizer.js";
import { type ToolResponse, type NormalizedFinding } from "../../types/findings.js";

async function withRetry<T>(fn: () => Promise<T>, retries = 5): Promise<T> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (error: unknown) {
      const err = error as { name?: string; code?: string; statusCode?: number };
      if (
        attempt < retries &&
        (err.statusCode === 429 || err.code === "TooManyRequests")
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
    "azure_get_sentinel_incidents",
    "Retrieve and normalize Microsoft Sentinel incidents filtered by severity, status, and time range",
    {
      subscriptionId: z.string().describe("Azure subscription ID"),
      workspaceId: z.string().describe("Log Analytics workspace name for Sentinel"),
      severity: z
        .enum(["High", "Medium", "Low", "Informational"])
        .describe("Incident severity to filter"),
      status: z
        .enum(["New", "Active", "Closed"])
        .default("Active")
        .describe("Incident status to filter"),
      lookbackDays: z
        .number()
        .min(1)
        .max(90)
        .default(7)
        .describe("Number of days to look back for incidents"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "azure_get_sentinel_incidents" });

      try {
        const credential = new DefaultAzureCredential();
        const client = new SecurityInsights(credential, params.subscriptionId);

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - params.lookbackDays);

        const resourceGroupName = params.workspaceId.split("/")[0] || params.workspaceId;
        const workspaceName = params.workspaceId.includes("/")
          ? params.workspaceId.split("/").pop()!
          : params.workspaceId;

        const incidents: NormalizedFinding[] = [];
        const warnings: string[] = [];
        const maxResults = 100;

        const iterator = client.incidents.list(resourceGroupName, workspaceName);

        for await (const incident of iterator) {
          const raw = incident as unknown as Record<string, unknown>;
          const props = (raw["properties"] as Record<string, unknown>) ?? raw;

          const incidentSeverity = (props["severity"] as string) ?? (raw["severity"] as string) ?? "";
          const incidentStatus = (props["status"] as string) ?? (raw["status"] as string) ?? "";
          const createdTime = (props["createdTimeUtc"] as string) ?? (raw["createdTimeUtc"] as string);

          if (incidentSeverity !== params.severity) continue;
          if (incidentStatus !== params.status) continue;

          if (createdTime) {
            const createdDate = new Date(createdTime);
            if (createdDate < cutoffDate) continue;
          }

          const normalized = await withRetry(() =>
            Promise.resolve(normalizeSentinelIncident(raw))
          );
          incidents.push(normalized);

          if (incidents.length >= maxResults) {
            warnings.push("Results truncated at 100. Narrow filters or reduce lookbackDays.");
            break;
          }
        }

        logger.info("Sentinel incidents retrieved", {
          requestId,
          count: incidents.length,
          severity: params.severity,
          status: params.status,
          lookbackDays: params.lookbackDays,
        });

        const response: ToolResponse<NormalizedFinding[]> = {
          success: true,
          requestId,
          data: incidents,
          warnings: warnings.length > 0 ? warnings : undefined,
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
