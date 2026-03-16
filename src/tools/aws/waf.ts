import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { WAFV2Client, GetSampledRequestsCommand, ListWebACLsCommand } from "@aws-sdk/client-wafv2";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";

async function withRetry<T>(fn: () => Promise<T>, retries = 5): Promise<T> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try { return await fn(); } catch (error: unknown) {
      const err = error as { name?: string };
      if (attempt < retries && (err.name === "ThrottlingException" || err.name === "WAFLimitsExceededException")) {
        await new Promise((r) => setTimeout(r, Math.min(100 * Math.pow(2, attempt) + Math.random() * 100, 10000)));
        continue;
      }
      throw error;
    }
  }
  throw new Error("Retry exhausted");
}

export function register(server: McpServer): void {
  server.tool(
    "aws_get_waf_blocked_requests",
    "Get WAF blocked requests with top blocked IPs, rule hit counts, and sampled requests",
    {
      webAclArn: z.string().describe("WAF Web ACL ARN"),
      region: z.enum(["REGIONAL", "CLOUDFRONT"]).default("REGIONAL").describe("WAF scope"),
      lookbackHours: z.number().min(1).max(72).default(24).describe("Hours to look back"),
      ruleId: z.string().optional().describe("Specific rule ID to filter"),
    },
    async ({ webAclArn, region, lookbackHours, ruleId }) => {
      const requestId = uuidv4();
      logger.info("aws_get_waf_blocked_requests invoked", { requestId });
      try {
        const scope = region === "CLOUDFRONT" ? "CLOUDFRONT" : "REGIONAL";
        const awsRegion = scope === "CLOUDFRONT" ? "us-east-1" : (process.env["AWS_DEFAULT_REGION"] ?? "us-east-1");
        const client = new WAFV2Client({ region: awsRegion });

        const endTime = new Date();
        const startTime = new Date(Date.now() - lookbackHours * 60 * 60 * 1000);

        const webAclName = webAclArn.split("/").pop() ?? "";
        const webAclId = webAclArn.split("/").slice(-1)[0] ?? "";

        const resp = await withRetry(() => client.send(new GetSampledRequestsCommand({
          WebAclArn: webAclArn,
          RuleMetricName: ruleId ?? "ALL",
          Scope: scope,
          TimeWindow: { StartTime: startTime, EndTime: endTime },
          MaxItems: 500,
        })));

        const blockedRequests = resp.SampledRequests ?? [];
        const ipCounts: Record<string, number> = {};
        for (const req of blockedRequests) {
          const ip = req.Request?.ClientIP ?? "unknown";
          ipCounts[ip] = (ipCounts[ip] ?? 0) + 1;
        }

        const topBlockedIPs = Object.entries(ipCounts)
          .sort(([, a], [, b]) => b - a)
          .slice(0, 20)
          .map(([ip, count]) => ({ ip, count }));

        const response: ToolResponse = {
          success: true,
          requestId,
          data: {
            webAclArn,
            timeRange: { start: startTime.toISOString(), end: endTime.toISOString() },
            totalSampledRequests: blockedRequests.length,
            populationSize: resp.PopulationSize ?? 0,
            topBlockedIPs,
            sampledRequests: blockedRequests.slice(0, 50).map(r => ({
              ip: r.Request?.ClientIP,
              country: r.Request?.Country,
              uri: r.Request?.URI,
              method: r.Request?.Method,
              action: r.Action,
              timestamp: r.Timestamp,
              ruleWithinRuleGroup: r.RuleNameWithinRuleGroup,
            })),
          },
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("aws_get_waf_blocked_requests failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
