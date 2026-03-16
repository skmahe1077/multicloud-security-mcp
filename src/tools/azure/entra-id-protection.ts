import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { Client } from "@microsoft/microsoft-graph-client";
import { TokenCredentialAuthenticationProvider } from "@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials/index.js";
import { DefaultAzureCredential } from "@azure/identity";
import { logger } from "../../logger.js";
import { normalizeEntraRiskyUser } from "../shared/findings-normalizer.js";
import { type ToolResponse } from "../../types/findings.js";
import { type IAMRiskFinding } from "../../types/identity.js";

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
    "azure_get_entra_risky_identities",
    "Retrieve risky users and optionally service principals from Microsoft Entra ID Protection",
    {
      tenantId: z.string().describe("Azure AD / Entra tenant ID"),
      riskLevel: z
        .enum(["High", "Medium", "Low"])
        .describe("Minimum risk level to filter"),
      riskState: z
        .string()
        .optional()
        .describe("Risk state filter (e.g., atRisk, confirmedCompromised, remediated, dismissed)"),
      includeServicePrincipals: z
        .boolean()
        .default(false)
        .describe("Whether to also retrieve risky service principals"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "azure_get_entra_risky_identities" });

      try {
        const credential = new DefaultAzureCredential();
        const authProvider = new TokenCredentialAuthenticationProvider(credential, {
          scopes: ["https://graph.microsoft.com/.default"],
        });

        const graphClient = Client.initWithMiddleware({ authProvider });

        const findings: IAMRiskFinding[] = [];
        const warnings: string[] = [];

        // Build filter for risky users
        let filter = `riskLevel eq '${params.riskLevel.toLowerCase()}'`;
        if (params.riskState) {
          filter += ` and riskState eq '${params.riskState}'`;
        }

        // Retrieve risky users
        const riskyUsersResponse = await withRetry(() =>
          graphClient
            .api("/identityProtection/riskyUsers")
            .filter(filter)
            .top(100)
            .get()
        );

        const riskyUsers = (riskyUsersResponse?.value as Record<string, unknown>[]) ?? [];

        for (const user of riskyUsers) {
          const normalized = normalizeEntraRiskyUser(user);
          findings.push(normalized);
        }

        logger.info("Entra risky users retrieved", {
          requestId,
          userCount: riskyUsers.length,
          riskLevel: params.riskLevel,
        });

        // Optionally retrieve risky service principals
        if (params.includeServicePrincipals) {
          try {
            const spFilter = `riskLevel eq '${params.riskLevel.toLowerCase()}'`;
            const riskySpResponse = await withRetry(() =>
              graphClient
                .api("/identityProtection/riskyServicePrincipals")
                .filter(spFilter)
                .top(100)
                .get()
            );

            const riskyServicePrincipals =
              (riskySpResponse?.value as Record<string, unknown>[]) ?? [];

            for (const sp of riskyServicePrincipals) {
              const normalized = normalizeEntraRiskyUser({
                ...sp,
                userDisplayName: sp["displayName"] ?? sp["appId"],
                userPrincipalName: sp["servicePrincipalName"] ?? sp["appId"],
              });
              normalized.principalType = "service_account";
              normalized.resourceType = "ServicePrincipal";
              findings.push(normalized);
            }

            logger.info("Entra risky service principals retrieved", {
              requestId,
              spCount: riskyServicePrincipals.length,
            });
          } catch (spError) {
            warnings.push(
              `Failed to retrieve risky service principals: ${String(spError)}. ` +
              "This API requires Azure AD P2 license."
            );
            logger.warn("Risky service principals retrieval failed", {
              requestId,
              error: String(spError),
            });
          }
        }

        const response: ToolResponse<IAMRiskFinding[]> = {
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
