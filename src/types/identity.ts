import { NormalizedFinding } from "./findings.js";

export interface IAMRiskFinding extends NormalizedFinding {
  principalType: "user" | "role" | "service_account" | "managed_identity";
  unusedPermissionsCount?: number;
  lastActivityDate?: Date;
  hasConsoleAccess?: boolean;
  hasMFAEnabled?: boolean;
  overprivilegedActions: string[];
}
