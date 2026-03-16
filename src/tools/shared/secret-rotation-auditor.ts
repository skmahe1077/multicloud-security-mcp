import {
  CloudProvider,
  SecretRotationReport,
  SecretRotationEntry,
} from "../../types/findings.js";

export function buildSecretRotationReport(
  entries: SecretRotationEntry[],
  cloud: CloudProvider
): SecretRotationReport {
  return {
    cloud,
    totalSecrets: entries.length,
    overdueCount: entries.filter((e) => !e.rotationEnabled || e.ageDays > 90).length,
    neverRotated: entries.filter((e) => !e.lastRotated).length,
    publicAccess: entries.filter((e) => e.hasPublicAccess).length,
    secrets: entries,
  };
}

export function mergeSecretRotationReports(
  reports: SecretRotationReport[]
): {
  totalSecrets: number;
  overdueByCloud: Record<string, number>;
  neverRotatedByCloud: Record<string, number>;
  publicAccessByCloud: Record<string, number>;
  reports: SecretRotationReport[];
  recommendedActions: string[];
} {
  const overdueByCloud: Record<string, number> = {};
  const neverRotatedByCloud: Record<string, number> = {};
  const publicAccessByCloud: Record<string, number> = {};
  let totalSecrets = 0;

  for (const r of reports) {
    totalSecrets += r.totalSecrets;
    overdueByCloud[r.cloud] = r.overdueCount;
    neverRotatedByCloud[r.cloud] = r.neverRotated;
    publicAccessByCloud[r.cloud] = r.publicAccess;
  }

  const recommendedActions: string[] = [];
  for (const r of reports) {
    if (r.overdueCount > 0) {
      recommendedActions.push(
        `[${r.cloud.toUpperCase()}] ${r.overdueCount} secret(s) overdue for rotation — enable auto-rotation`
      );
    }
    if (r.publicAccess > 0) {
      recommendedActions.push(
        `[${r.cloud.toUpperCase()}] ${r.publicAccess} secret(s) have public access — restrict immediately`
      );
    }
    if (r.neverRotated > 0) {
      recommendedActions.push(
        `[${r.cloud.toUpperCase()}] ${r.neverRotated} secret(s) have never been rotated`
      );
    }
  }

  return {
    totalSecrets,
    overdueByCloud,
    neverRotatedByCloud,
    publicAccessByCloud,
    reports,
    recommendedActions,
  };
}
