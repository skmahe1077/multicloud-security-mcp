import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { google } from "googleapis";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";
import { normalizeGCPIAMRecommendation } from "../shared/findings-normalizer.js";
import { IAMRiskFinding } from "../../types/identity.js";

export function register(server: McpServer): void {
  server.tool(
    "gcp_get_iam_recommendations",
    "Get GCP IAM recommendations for excess permissions, lateral movement risks, and service account key issues",
    {
      projectId: z.string().describe("GCP project ID"),
      principalEmail: z.string().optional().describe("Filter by principal email"),
      recommenderType: z.enum(["EXCESS_PERMISSIONS", "LATERAL_MOVEMENT", "SERVICE_ACCOUNT_KEY"]).default("EXCESS_PERMISSIONS").describe("Recommender type"),
    },
    async ({ projectId, principalEmail, recommenderType }) => {
      const requestId = uuidv4();
      logger.info("gcp_get_iam_recommendations invoked", { requestId, recommenderType });
      try {
        const auth = new google.auth.GoogleAuth({ scopes: ["https://www.googleapis.com/auth/cloud-platform"] });
        const recommender = google.recommender({ version: "v1", auth });

        const recommenderMap: Record<string, string> = {
          EXCESS_PERMISSIONS: "google.iam.policy.Recommender",
          LATERAL_MOVEMENT: "google.iam.policy.Recommender",
          SERVICE_ACCOUNT_KEY: "google.iam.serviceAccount.Recommender",
        };

        const resp = await recommender.projects.locations.recommenders.recommendations.list({
          parent: `projects/${projectId}/locations/global/recommenders/${recommenderMap[recommenderType]}`,
        });

        let recommendations = resp.data.recommendations ?? [];
        if (principalEmail) {
          recommendations = recommendations.filter(r => {
            const content = r.content as Record<string, unknown> | undefined;
            const overview = content?.["overview"] as Record<string, unknown> | undefined;
            return (overview?.["member"] as string ?? "").includes(principalEmail);
          });
        }

        const findings: IAMRiskFinding[] = recommendations.map(r =>
          normalizeGCPIAMRecommendation(r as unknown as Record<string, unknown>)
        );

        const response: ToolResponse<IAMRiskFinding[]> = { success: true, requestId, data: findings };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("gcp_get_iam_recommendations failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
