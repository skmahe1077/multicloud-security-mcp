import { NormalizedFinding } from "./findings.js";

export interface NetworkFinding extends NormalizedFinding {
  sourceIp?: string;
  destinationPort?: number;
  protocol?: string;
  blockedByFirewall?: boolean;
  ddosAttackType?: string;
}
