import { NormalizedFinding, CorrelatedEvent, CloudProvider } from "../../types/findings.js";

export type CorrelationKey = "IP" | "ACCOUNT_ID" | "RESOURCE_ID" | "USER_EMAIL";

export function correlateFindings(
  findings: NormalizedFinding[],
  correlationKey: CorrelationKey,
  value: string
): CorrelatedEvent[] {
  const matched = findings.filter((f) => matchesByKey(f, correlationKey, value));

  if (matched.length === 0) {
    return [];
  }

  const clouds = [...new Set(matched.map((f) => f.cloud))];
  const isCrossCloud = clouds.length > 1;

  const event: CorrelatedEvent = {
    correlationKey,
    correlationValue: value,
    clouds: clouds as CloudProvider[],
    findings: matched,
    isCrossCloudThreat: isCrossCloud,
    summary: buildCorrelationSummary(matched, correlationKey, value, isCrossCloud),
  };

  return [event];
}

function matchesByKey(
  finding: NormalizedFinding,
  key: CorrelationKey,
  value: string
): boolean {
  const lowerValue = value.toLowerCase();
  switch (key) {
    case "IP": {
      const raw = finding.rawFinding as Record<string, unknown>;
      return jsonContainsValue(raw, lowerValue);
    }
    case "ACCOUNT_ID":
      return finding.accountId?.toLowerCase() === lowerValue;
    case "RESOURCE_ID":
      return finding.resourceId.toLowerCase().includes(lowerValue);
    case "USER_EMAIL": {
      const raw = finding.rawFinding as Record<string, unknown>;
      return jsonContainsValue(raw, lowerValue);
    }
    default:
      return false;
  }
}

function jsonContainsValue(obj: unknown, value: string): boolean {
  if (obj === null || obj === undefined) return false;
  if (typeof obj === "string") return obj.toLowerCase().includes(value);
  if (typeof obj === "number") return String(obj) === value;
  if (Array.isArray(obj)) return obj.some((item) => jsonContainsValue(item, value));
  if (typeof obj === "object") {
    return Object.values(obj as Record<string, unknown>).some((v) =>
      jsonContainsValue(v, value)
    );
  }
  return false;
}

function buildCorrelationSummary(
  findings: NormalizedFinding[],
  key: CorrelationKey,
  value: string,
  isCrossCloud: boolean
): string {
  const clouds = [...new Set(findings.map((f) => f.cloud))].join(", ");
  const services = [...new Set(findings.map((f) => f.service))].join(", ");
  const critCount = findings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").length;

  let summary = `Found ${findings.length} finding(s) matching ${key}="${value}" across ${clouds}.`;
  summary += ` Services involved: ${services}.`;
  if (critCount > 0) {
    summary += ` ${critCount} are CRITICAL/HIGH severity.`;
  }
  if (isCrossCloud) {
    summary += ` Cross-cloud threat indicator: same entity detected in multiple cloud environments.`;
  }
  return summary;
}
