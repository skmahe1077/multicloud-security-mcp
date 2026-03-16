import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { v4 as uuidv4 } from "uuid";
import {
  CloudTrailClient,
  LookupEventsCommand,
  type LookupAttribute,
} from "@aws-sdk/client-cloudtrail";
import { logger } from "../../logger.js";
import { computeRiskScore } from "../shared/risk-scorer.js";
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

const ANOMALOUS_EVENT_NAMES = new Set([
  "ConsoleLogin",
  "StopLogging",
  "DeleteTrail",
  "PutBucketPolicy",
  "PutRolePolicy",
  "AttachRolePolicy",
  "CreateAccessKey",
  "CreateUser",
  "DeleteFlowLogs",
  "DisableAlarmActions",
  "DeleteAlarms",
  "AuthorizeSecurityGroupIngress",
  "CreateSecurityGroup",
  "RunInstances",
  "AssumeRole",
  "GetSecretValue",
  "ChangePassword",
  "DeactivateMFADevice",
  "DeleteBucket",
  "PutBucketAcl",
]);

function normalizeCloudTrailEvent(raw: Record<string, unknown>): NormalizedFinding {
  const eventName = (raw["EventName"] as string) ?? "";
  const isAnomalous = ANOMALOUS_EVENT_NAMES.has(eventName);

  const finding: NormalizedFinding = {
    id: (raw["EventId"] as string) ?? uuidv4(),
    cloud: "aws",
    service: "cloudtrail",
    category: "ANOMALOUS_ACTIVITY",
    severity: isAnomalous ? "HIGH" : "MEDIUM",
    title: `CloudTrail Event: ${eventName}`,
    description: `Event ${eventName} performed by ${(raw["Username"] as string) ?? "unknown"} from ${(raw["SourceIPAddress"] as string) ?? "unknown IP"}`,
    resourceId: (raw["ResourceName"] as string) ?? "",
    resourceType: (raw["ResourceType"] as string) ?? "Unknown",
    region: undefined,
    accountId: (raw["AccountId"] as string) ?? undefined,
    remediationSteps: isAnomalous
      ? [
          `Review whether ${eventName} was authorized`,
          "Check the principal's recent activity pattern",
          "Verify the action was performed from a known IP address",
        ]
      : ["Review event details for anomalous patterns"],
    complianceFrameworks: isAnomalous ? ["CIS", "SOC2"] : [],
    riskScore: 0,
    firstDetected: new Date((raw["EventTime"] as string) ?? Date.now()),
    lastSeen: new Date((raw["EventTime"] as string) ?? Date.now()),
    rawFinding: raw,
  };
  finding.riskScore = computeRiskScore(finding);
  return finding;
}

export function register(server: McpServer): void {
  server.tool(
    "aws_get_cloudtrail_anomalies",
    "Retrieve CloudTrail events and detect anomalous API activity such as privilege escalation and security control changes",
    {
      region: z.string().default("us-east-1").describe("AWS region"),
      lookbackHours: z
        .number()
        .min(1)
        .max(2160)
        .default(24)
        .describe("Number of hours to look back for events (max 90 days)"),
      eventTypes: z
        .array(z.string())
        .optional()
        .describe("Event names to filter (e.g., ConsoleLogin, StopLogging)"),
      principalArn: z
        .string()
        .optional()
        .describe("ARN of the principal to filter events by"),
    },
    async (params) => {
      const requestId = uuidv4();
      logger.info("Tool invoked", { requestId, tool: "aws_get_cloudtrail_anomalies" });

      try {
        const client = new CloudTrailClient({
          region: params.region,
          requestHandler: { requestTimeout: 30000 },
        });

        const endTime = new Date();
        const startTime = new Date(endTime.getTime() - params.lookbackHours * 60 * 60 * 1000);

        const lookupAttributes: LookupAttribute[] = [];

        if (params.principalArn) {
          lookupAttributes.push({
            AttributeKey: "ResourceName",
            AttributeValue: params.principalArn,
          });
        }

        const allEvents: Record<string, unknown>[] = [];
        let nextToken: string | undefined;

        do {
          const command = new LookupEventsCommand({
            StartTime: startTime,
            EndTime: endTime,
            LookupAttributes: lookupAttributes.length > 0 ? lookupAttributes : undefined,
            MaxResults: 50,
            NextToken: nextToken,
          });

          const result = await withRetry(() => client.send(command));
          const events = (result.Events ?? []) as unknown as Record<string, unknown>[];
          allEvents.push(...events);
          nextToken = result.NextToken as string | undefined;
        } while (nextToken && allEvents.length < 1000);

        // Filter by event types if specified, otherwise detect anomalous events
        let filteredEvents: Record<string, unknown>[];
        if (params.eventTypes && params.eventTypes.length > 0) {
          const eventTypeSet = new Set(params.eventTypes);
          filteredEvents = allEvents.filter((e) =>
            eventTypeSet.has((e["EventName"] as string) ?? "")
          );
        } else {
          filteredEvents = allEvents.filter((e) =>
            ANOMALOUS_EVENT_NAMES.has((e["EventName"] as string) ?? "")
          );
        }

        const normalized = filteredEvents.map((e) => normalizeCloudTrailEvent(e));

        const response: ToolResponse<{
          findings: NormalizedFinding[];
          summary: {
            totalEventsScanned: number;
            anomalousEventsDetected: number;
            timeRange: { start: string; end: string };
            topEventNames: Record<string, number>;
          };
        }> = {
          success: true,
          requestId,
          data: {
            findings: normalized,
            summary: {
              totalEventsScanned: allEvents.length,
              anomalousEventsDetected: normalized.length,
              timeRange: {
                start: startTime.toISOString(),
                end: endTime.toISOString(),
              },
              topEventNames: normalized.reduce(
                (acc, f) => {
                  const eventName = f.title.replace("CloudTrail Event: ", "");
                  acc[eventName] = (acc[eventName] ?? 0) + 1;
                  return acc;
                },
                {} as Record<string, number>
              ),
            },
          },
          warnings:
            allEvents.length >= 1000
              ? ["Event scan was capped at 1000 events. Narrow the lookback window for complete coverage."]
              : undefined,
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
