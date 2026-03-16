import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { SecurityCenter } from "@azure/arm-security";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { normalizeDefenderAlert } from "../shared/findings-normalizer.js";
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
    "azure_get_defender_alerts",
    "Retrieve and normalize Microsoft Defender for Cloud alerts filtered by severity and state",
    {
      subscriptionId: z.string().describe("Azure subscription ID"),
      severity: z
        .enum(["High", "Medium", "Low", "Informational"])
        .describe("Alert severity to filter"),
      alertState: z
        .enum(["Active", "Dismissed", "Resolved"])
        .default("Active")
        .describe("State of alerts to retrieve"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "azure_get_defender_alerts" });

      try {
        const credential = new DefaultAzureCredential();
        const client = new SecurityCenter(credential, params.subscriptionId);

        const alerts: NormalizedFinding[] = [];
        const warnings: string[] = [];

        const iterator = client.alerts.list();
        let count = 0;
        const maxResults = 100;

        for await (const alert of iterator) {
          const raw = alert as unknown as Record<string, unknown>;
          const props = (raw["properties"] as Record<string, unknown>) ?? raw;

          const alertSeverity = (props["severity"] as string) ?? "";
          const state = (props["status"] as string) ?? (props["alertState"] as string) ?? "";

          if (alertSeverity !== params.severity) continue;
          if (state !== params.alertState) continue;

          const normalized = await withRetry(() =>
            Promise.resolve(normalizeDefenderAlert(raw))
          );
          alerts.push(normalized);
          count++;

          if (count >= maxResults) {
            warnings.push("Results truncated at 100. Narrow filters for complete results.");
            break;
          }
        }

        logger.info("Defender alerts retrieved", {
          requestId,
          count: alerts.length,
          severity: params.severity,
          state: params.alertState,
        });

        const response: ToolResponse<NormalizedFinding[]> = {
          success: true,
          requestId,
          data: alerts,
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
