import { NormalizedFinding } from "./findings.js";

export interface VulnerabilityFinding extends NormalizedFinding {
  cveId?: string;
  cvssScore?: number;
  packageName?: string;
  packageVersion?: string;
  fixedVersion?: string;
  affectedResource: string;
}
