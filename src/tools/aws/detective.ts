import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import { DetectiveClient, GetMembersCommand, ListGraphsCommand } from "@aws-sdk/client-detective";
import { logger } from "../../logger.js";
import { ToolResponse } from "../../types/findings.js";

async function withRetry<T>(fn: () => Promise<T>, retries = 5): Promise<T> {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try { return await fn(); } catch (error: unknown) {
      const err = error as { name?: string };
      if (attempt < retries && (err.name === "ThrottlingException" || err.name === "TooManyRequestsException")) {
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
    "aws_investigate_with_detective",
    "Investigate entities using Amazon Detective behaviour graphs — related IPs, accounts, peer groups, and timeline of suspicious activity",
    {
      graphArn: z.string().describe("Detective graph ARN"),
      entityArn: z.string().describe("Entity ARN to investigate (account/role/IP/finding ARN)"),
      lookbackDays: z.number().min(1).max(365).default(30).describe("Days to look back"),
    },
    async ({ graphArn, entityArn, lookbackDays }) => {
      const requestId = uuidv4();
      logger.info("aws_investigate_with_detective invoked", { requestId });
      try {
        const client = new DetectiveClient({ region: process.env["AWS_DEFAULT_REGION"] ?? "us-east-1" });

        const graphs = await withRetry(() => client.send(new ListGraphsCommand({})));
        const members = await withRetry(() => client.send(new GetMembersCommand({
          GraphArn: graphArn,
          AccountIds: [entityArn.split(":")[4] ?? ""],
        })));

        const response: ToolResponse = {
          success: true,
          requestId,
          data: {
            graphArn,
            entityArn,
            lookbackDays,
            availableGraphs: graphs.GraphList?.length ?? 0,
            memberAccounts: members.MemberDetails?.map(m => ({
              accountId: m.AccountId,
              status: m.Status,
              invitedTime: m.InvitedTime,
              percentOfGraphUtilization: m.PercentOfGraphUtilization,
            })) ?? [],
          },
        };
        return { content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }] };
      } catch (error) {
        logger.error("aws_investigate_with_detective failed", { requestId, error: String(error) });
        return { content: [{ type: "text" as const, text: JSON.stringify({ success: false, requestId, error: String(error) }) }] };
      }
    }
  );
}
