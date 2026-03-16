import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { Client } from "@microsoft/microsoft-graph-client";
import { TokenCredentialAuthenticationProvider } from "@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials/index.js";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { type ToolResponse, type NormalizedFinding, type Severity } from "../../types/findings.js";
import { computeRiskScore } from "../shared/risk-scorer.js";

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

function mapDlpSeverity(severity: string): Severity {
  const map: Record<string, Severity> = {
    high: "HIGH",
    medium: "MEDIUM",
    low: "LOW",
    informational: "INFO",
  };
  return map[severity.toLowerCase()] ?? "MEDIUM";
}

export function register(server: McpServer): void {
  server.tool(
    "azure_get_purview_dlp_alerts",
    "Retrieve DLP (Data Loss Prevention) alerts from Microsoft Purview Information Protection",
    {
      subscriptionId: z.string().describe("Azure subscription ID"),
      policyName: z.string().optional().describe("DLP policy name to filter alerts"),
      sensitivityLabel: z.string().optional().describe("Sensitivity label to filter by"),
      lookbackDays: z
        .number()
        .min(1)
        .max(90)
        .default(7)
        .describe("Number of days to look back for DLP alerts"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "azure_get_purview_dlp_alerts" });

      try {
        const credential = new DefaultAzureCredential();
        const authProvider = new TokenCredentialAuthenticationProvider(credential, {
          scopes: ["https://graph.microsoft.com/.default"],
        });

        const graphClient = Client.initWithMiddleware({ authProvider });

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - params.lookbackDays);
        const cutoffIso = cutoffDate.toISOString();

        // Query DLP alerts from Microsoft Graph Security alerts API
        let filter = `createdDateTime ge ${cutoffIso} and category eq 'DataLossPrevention'`;
        if (params.policyName) {
          filter += ` and title eq '${params.policyName}'`;
        }

        const alertsResponse = await withRetry(() =>
          graphClient
            .api("/security/alerts_v2")
            .filter(filter)
            .top(100)
            .get()
        );

        const rawAlerts = (alertsResponse?.value as Record<string, unknown>[]) ?? [];

        const findings: NormalizedFinding[] = [];
        const warnings: string[] = [];

        for (const alert of rawAlerts) {
          // Filter by sensitivity label if specified
          if (params.sensitivityLabel) {
            const evidence = alert["evidence"] as Record<string, unknown>[] | undefined;
            const labels = evidence
              ?.map((e) => (e["sensitivityLabel"] as string) ?? "")
              .filter(Boolean) ?? [];
            if (!labels.some((l) => l.toLowerCase().includes(params.sensitivityLabel!.toLowerCase()))) {
              continue;
            }
          }

          const finding: NormalizedFinding = {
            id: (alert["id"] as string) ?? "",
            cloud: "azure",
            service: "purview",
            category: "DLP_VIOLATION",
            severity: mapDlpSeverity((alert["severity"] as string) ?? "medium"),
            title: (alert["title"] as string) ?? "DLP Alert",
            description: (alert["description"] as string) ?? "",
            resourceId: (alert["resourceId"] as string) ??
              ((alert["evidence"] as Record<string, unknown>[])?.[0]?.["resourceId"] as string) ?? "",
            resourceType: "DLP Policy Match",
            region: undefined,
            accountId: params.subscriptionId,
            remediationSteps: [
              "Review the DLP policy match details",
              "Verify if the data sharing was authorized",
              "Apply appropriate sensitivity labels",
              "Contact the data owner if data exposure is confirmed",
            ],
            complianceFrameworks: ["GDPR", "HIPAA", "SOC2"],
            riskScore: 0,
            firstDetected: new Date((alert["createdDateTime"] as string) ?? Date.now()),
            lastSeen: new Date((alert["lastUpdateDateTime"] as string) ?? Date.now()),
            rawFinding: alert,
          };

          finding.riskScore = computeRiskScore(finding);
          findings.push(finding);
        }

        // Also attempt to get sensitivity label information
        try {
          const labelsResponse = await withRetry(() =>
            graphClient
              .api("/security/informationProtection/sensitivityLabels")
              .top(50)
              .get()
          );
          const labelCount = (labelsResponse?.value as unknown[])?.length ?? 0;
          logger.info("Sensitivity labels retrieved", { requestId, labelCount });
        } catch (labelError) {
          warnings.push(
            "Could not retrieve sensitivity label metadata. " +
            "Ensure the app has InformationProtectionPolicy.Read.All permission."
          );
          logger.warn("Sensitivity labels retrieval failed", {
            requestId,
            error: String(labelError),
          });
        }

        logger.info("Purview DLP alerts retrieved", {
          requestId,
          count: findings.length,
          lookbackDays: params.lookbackDays,
        });

        const response: ToolResponse<NormalizedFinding[]> = {
          success: true,
          requestId,
          data: findings,
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
