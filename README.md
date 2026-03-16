# Multi-Cloud Security MCP Server

[![npm version](https://img.shields.io/npm/v/multicloud-security-mcp.svg)](https://www.npmjs.com/package/multicloud-security-mcp)
[![PyPI version](https://img.shields.io/pypi/v/multicloud-security-mcp.svg)](https://pypi.org/project/multicloud-security-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green.svg)](https://nodejs.org)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)

A production-ready **Model Context Protocol (MCP)** server providing unified security visibility across **AWS**, **Azure**, and **GCP**. Built for AI agents and Claude Desktop.

**46 security tools** | **5 MCP resources** | **3 cloud providers** | **1 unified interface**

---

## Features

- **46 security tools** spanning threat detection, vulnerability management, IAM analysis, data protection, network security, key/secret management, container security, and compliance
- **5 cross-cloud tools** for aggregated findings, compliance dashboards, IAM blast radius analysis, SIEM correlation, and secret rotation auditing
- **Normalized finding schema** that unifies findings from all three clouds into a single `NormalizedFinding` format with risk scoring (0-100)
- **Resilient by design** with exponential backoff, jitter-based retry (100ms base, 5 retries), and 30-second SDK timeouts
- **Read-only operations** — no infrastructure modifications, safe for production use
- **Zod-validated inputs** on every tool call
- **Structured logging** via Winston with account ID masking
- **Programmatic API** for embedding the server in your own applications

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │   Claude Desktop / AI Agent      │
                    │          (MCP Client)            │
                    └───────────────┬─────────────────┘
                                    │ stdio
┌───────────────────────────────────▼───────────────────────────────────┐
│                         MCP Server                                    │
│                                                                       │
│  ┌─────────────┐   ┌──────────────┐   ┌────────────────────────────┐ │
│  │  Resources   │   │  41 Tools    │   │   Cross-Cloud Tools (X1-X5)│ │
│  │  (5 URIs)   │   │  per-cloud   │   │   parallel via p-limit(3)  │ │
│  └─────────────┘   └──────┬───────┘   └────────────┬───────────────┘ │
│                            │                        │                 │
│  ┌─────────────────────────▼────────────────────────▼───────────────┐ │
│  │                      Shared Layer                                │ │
│  │  findings-normalizer · risk-scorer · siem-correlator             │ │
│  │  secret-rotation-auditor · logger · retry / backoff              │ │
│  └──────────────────────────────────────────────────────────────────┘ │
└──────────┬──────────────────────┬──────────────────────┬─────────────┘
           │                      │                      │
  ┌────────▼────────┐   ┌────────▼──────────┐   ┌───────▼─────────┐
  │    AWS (15)      │   │   Azure (13)      │   │    GCP (13)     │
  │                  │   │                   │   │                 │
  │  SecurityHub     │   │  Defender         │   │  SCC            │
  │  GuardDuty       │   │  Sentinel         │   │  Chronicle      │
  │  Inspector       │   │  Entra ID Protect │   │  IAM Recommender│
  │  IAM Analyzer    │   │  Purview DLP      │   │  Cloud DLP      │
  │  Macie           │   │  Azure Policy     │   │  Cloud Armor    │
  │  CloudTrail      │   │  Key Vault        │   │  Binary Auth    │
  │  Detective       │   │  Firewall         │   │  Artifact Reg.  │
  │  Config Rules    │   │  DDoS Protection  │   │  VPC SC         │
  │  WAF             │   │  Container Reg.   │   │  Cloud KMS      │
  │  Shield          │   │  Network Watcher  │   │  Secret Manager │
  │  Net Firewall    │   │  Defender Endpt   │   │  Asset Inventory│
  │  Secrets Mgr     │   │  App Service      │   │  Access Transp. │
  │  KMS             │   │  DevOps Security  │   │  Audit Logs     │
  │  ECR             │   │                   │   │                 │
  │  SSM Patch       │   │                   │   │                 │
  └──────────────────┘   └───────────────────┘   └─────────────────┘
```

---

## Install

### npm

```bash
# Run directly with npx (no install needed)
npx multicloud-security-mcp

# Or install globally
npm install -g multicloud-security-mcp

# Or add to a project
npm install multicloud-security-mcp
```

### pip

```bash
# pip
pip install multicloud-security-mcp

# uv
uv pip install multicloud-security-mcp

# uvx (no install needed)
uvx multicloud-security-mcp

# pipx (isolated global install)
pipx install multicloud-security-mcp
```

> **Note:** The Python package is a thin wrapper that delegates to the Node.js server at runtime. Node.js 20+ must be available on PATH.

---

## Quick Start

### Prerequisites

- **Node.js 20+** — [nodejs.org](https://nodejs.org)
- **Python 3.10+** (only if installing via pip)
- Credentials for at least one cloud provider

### Option 1: npx (recommended)

```bash
npx multicloud-security-mcp
```

### Option 2: Global install (npm)

```bash
npm install -g multicloud-security-mcp
multicloud-security-mcp
```

### Option 3: pip install

```bash
pip install multicloud-security-mcp
multicloud-security-mcp
```

### Option 4: From source

```bash
git clone https://github.com/devopstronaut/multicloud-security-mcp.git
cd multicloud-security-mcp
npm install
cp .env.example .env    # edit with your credentials
npm run build
npm start
```

### Development

```bash
npm run dev        # hot reload with tsx watch
npm test           # run tests
npm run typecheck  # type checking only
```

---

## Claude Desktop Configuration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

### Using npx

```json
{
  "mcpServers": {
    "multicloud-security": {
      "command": "npx",
      "args": ["multicloud-security-mcp"],
      "env": {
        "AWS_PROFILE": "security-audit",
        "AZURE_CLIENT_ID": "your-app-id",
        "AZURE_CLIENT_SECRET": "your-secret",
        "AZURE_TENANT_ID": "your-tenant",
        "AZURE_SUBSCRIPTION_ID": "your-sub",
        "GOOGLE_APPLICATION_CREDENTIALS": "/path/to/sa.json",
        "GCP_PROJECT_ID": "your-project"
      }
    }
  }
}
```

### Using global install (npm or pip)

```json
{
  "mcpServers": {
    "multicloud-security": {
      "command": "multicloud-security-mcp",
      "env": {
        "AWS_PROFILE": "security-audit"
      }
    }
  }
}
```

### Using uvx

```json
{
  "mcpServers": {
    "multicloud-security": {
      "command": "uvx",
      "args": ["multicloud-security-mcp"],
      "env": {
        "AWS_PROFILE": "security-audit"
      }
    }
  }
}
```

---

## Cloud Authentication

### AWS

```bash
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
export AWS_DEFAULT_REGION=eu-west-1

# Or use a named profile
export AWS_PROFILE=security-audit
```

Attach the least-privilege policy from [`iam-policy-aws.json`](iam-policy-aws.json) to your IAM user/role.

### Azure

```bash
export AZURE_CLIENT_ID=your-app-id
export AZURE_CLIENT_SECRET=your-secret
export AZURE_TENANT_ID=your-tenant
export AZURE_SUBSCRIPTION_ID=your-sub
```

Deploy role assignments using [`rbac-azure.json`](rbac-azure.json):

```bash
az deployment sub create \
  --location eastus \
  --template-file rbac-azure.json \
  --parameters principalId=<your-sp-object-id>
```

### GCP

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
export GCP_PROJECT_ID=your-project
export GCP_ORGANIZATION_ID=your-org   # optional, for org-level queries
```

Assign roles using commands in [`iam-roles-gcp.txt`](iam-roles-gcp.txt).

---

## Programmatic Usage

Embed the MCP server in your own application:

```typescript
import { createServer } from "multicloud-security-mcp";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

// Create with all clouds enabled (default)
const server = createServer();

// Or enable only specific clouds
const awsOnly = createServer({ clouds: ["aws"] });

// Connect to any MCP transport
await server.connect(new StdioServerTransport());
```

### Using types and utilities directly

```typescript
import {
  // Types
  type NormalizedFinding,
  type VulnerabilityFinding,
  type IAMRiskFinding,

  // Normalizers — convert raw cloud findings to a unified schema
  normalizeSecurityHubFinding,
  normalizeDefenderAlert,
  normalizeSCCFinding,

  // Risk scoring
  computeRiskScore,
  sortByRiskScore,

  // Cross-cloud correlation
  correlateFindings,
} from "multicloud-security-mcp";
```

---

## Tools Reference

### AWS Tools (15)

| Tool | Category | Description |
|------|----------|-------------|
| `aws_get_security_hub_findings` | Aggregated findings | Retrieve consolidated findings from Security Hub |
| `aws_get_guardduty_threats` | Threat detection | Get active threat detections from GuardDuty |
| `aws_get_inspector_vulnerabilities` | Vulnerability mgmt | Scan for software vulnerabilities via Inspector |
| `aws_analyze_iam_access` | IAM security | Analyze IAM access with Access Analyzer |
| `aws_scan_macie_sensitive_data` | Data protection | Detect sensitive data exposure via Macie |
| `aws_get_cloudtrail_anomalies` | Audit & anomaly | Surface unusual API activity from CloudTrail |
| `aws_investigate_with_detective` | Investigation | Deep-dive investigations via Detective |
| `aws_list_config_violations` | Compliance | List AWS Config rule violations |
| `aws_get_waf_blocked_requests` | Network security | Get WAF blocked request metrics |
| `aws_get_shield_attacks` | DDoS protection | Retrieve DDoS attack summaries from Shield |
| `aws_get_network_firewall_alerts` | Network security | Get Network Firewall alert logs |
| `aws_audit_secrets_manager` | Secret mgmt | Audit secret rotation status |
| `aws_audit_kms_keys` | Key mgmt | Audit KMS key configuration and rotation |
| `aws_get_ecr_vulnerabilities` | Container security | Scan ECR container images for CVEs |
| `aws_get_ssm_patch_compliance` | Patch mgmt | Check Systems Manager patch compliance |

### Azure Tools (13)

| Tool | Category | Description |
|------|----------|-------------|
| `azure_get_defender_alerts` | Threat detection | Get Microsoft Defender for Cloud alerts |
| `azure_get_sentinel_incidents` | SIEM | Retrieve Sentinel security incidents |
| `azure_get_entra_risky_identities` | IAM security | Identify risky users in Entra ID |
| `azure_get_purview_dlp_alerts` | Data protection | Get Purview DLP policy alerts |
| `azure_check_policy_compliance` | Compliance | Check Azure Policy compliance state |
| `azure_audit_key_vault` | Secret mgmt | Audit Key Vault secrets and certificates |
| `azure_get_firewall_threats` | Network security | Get Azure Firewall threat intel hits |
| `azure_get_ddos_attacks` | DDoS protection | Retrieve DDoS protection attack logs |
| `azure_scan_container_registry` | Container security | Scan ACR images for vulnerabilities |
| `azure_get_network_watcher_flows` | Network security | Analyze Network Watcher flow logs |
| `azure_get_defender_endpoint_vulns` | Endpoint security | Get Defender for Endpoint vulnerabilities |
| `azure_check_app_service_security` | App security | Audit App Service security config |
| `azure_audit_devops_security` | DevOps security | Check DevOps security posture |

### GCP Tools (13)

| Tool | Category | Description |
|------|----------|-------------|
| `gcp_get_scc_findings` | Aggregated findings | Get Security Command Center findings |
| `gcp_get_chronicle_detections` | SIEM | Retrieve Chronicle SIEM detections |
| `gcp_get_iam_recommendations` | IAM security | Get IAM policy recommendations |
| `gcp_scan_dlp_sensitive_data` | Data protection | Scan for sensitive data via Cloud DLP |
| `gcp_get_cloud_armor_events` | WAF / DDoS | Get Cloud Armor security policy events |
| `gcp_check_binary_authorization` | Container security | Check Binary Authorization policies |
| `gcp_scan_artifact_registry` | Container security | Scan Artifact Registry for vulnerabilities |
| `gcp_get_vpc_sc_violations` | Network security | Get VPC Service Controls violations |
| `gcp_audit_kms_keys` | Key mgmt | Audit Cloud KMS key configuration |
| `gcp_audit_secret_manager` | Secret mgmt | Audit Secret Manager secrets |
| `gcp_get_asset_violations` | Compliance | Get Cloud Asset Inventory violations |
| `gcp_get_access_transparency_logs` | Audit | Review Access Transparency logs |
| `gcp_get_audit_log_anomalies` | Audit & anomaly | Detect anomalies in Cloud Audit Logs |

### Cross-Cloud Tools (5)

| Tool | Description |
|------|-------------|
| `multicloud_get_critical_findings` | Aggregate CRITICAL/HIGH findings across all clouds in parallel |
| `multicloud_compliance_dashboard` | Unified compliance posture for CIS, NIST, SOC2, ISO27001, PCI-DSS |
| `multicloud_iam_blast_radius` | Analyze IAM blast radius across all cloud providers |
| `multicloud_siem_correlation` | Correlate security events across clouds by IP, account, resource, or email |
| `multicloud_secret_rotation_audit` | Cross-cloud secret and key rotation status audit |

### Utility

| Tool | Description |
|------|-------------|
| `validate_cloud_connectivity` | Health check for all configured cloud provider connections (cached 5 min) |

---

## MCP Resources

| URI | Description |
|-----|-------------|
| `security://findings/summary` | Aggregated open findings count by cloud and severity |
| `security://compliance/{framework}` | Compliance posture for CIS, NIST, SOC2, ISO27001, PCI_DSS |
| `security://iam/overprivileged` | Cross-cloud overprivileged identities |
| `security://secrets/rotation-status` | Secrets and keys overdue for rotation |
| `security://vulnerabilities/critical` | Open CVEs with CVSS >= 9.0 |

---

## Example Prompts

| Prompt | Tools Used |
|--------|-----------|
| *"Show me all CRITICAL findings across all clouds"* | `multicloud_get_critical_findings` |
| *"Which IAM roles have never been used in the last 90 days?"* | `aws_analyze_iam_access`, `azure_get_entra_risky_identities`, `gcp_get_iam_recommendations` |
| *"Are any secrets overdue for rotation?"* | `multicloud_secret_rotation_audit` |
| *"Correlate all GuardDuty and Chronicle events for IP 1.2.3.4"* | `multicloud_siem_correlation` |
| *"Run a CIS compliance check across AWS and GCP"* | `multicloud_compliance_dashboard` |
| *"What container vulnerabilities exist in our ECR and ACR registries?"* | `aws_get_ecr_vulnerabilities`, `azure_scan_container_registry` |
| *"Show me all WAF blocked requests in the last 24 hours"* | `aws_get_waf_blocked_requests`, `gcp_get_cloud_armor_events` |

---

## Security

| Feature | Detail |
|---------|--------|
| Read-only | All tools perform read-only operations — no infrastructure changes |
| Input validation | Every tool input validated with Zod schemas before SDK calls |
| Credential safety | Credentials are never logged or included in tool responses |
| Account ID masking | Account IDs masked in logs when `LOG_MASK_ACCOUNT_IDS=true` |
| Request tracing | Every invocation generates a UUID `requestId` for end-to-end tracing |
| SDK timeouts | All cloud SDK calls timeout after 30 seconds |
| Retry with backoff | Exponential backoff with jitter (100ms base, max 5 retries) for throttling |

---

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for the full list.

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | Logging verbosity (`debug`, `info`, `warn`, `error`) | `info` |
| `LOG_MASK_ACCOUNT_IDS` | Mask cloud account IDs in logs | `true` |
| `CACHE_TTL_SECONDS` | Cache TTL for connectivity checks | `300` |
| `MCP_SERVER_NAME` | Server name reported to MCP clients | `multicloud-security-mcp` |
| `MCP_SERVER_VERSION` | Server version reported to MCP clients | `1.0.0` |

---

## Testing

```bash
npm test              # run all tests (30 tests across 3 suites)
npm run test:watch    # watch mode
npm run typecheck     # type checking only
```

---

## Publishing

### npm

```bash
npm login
npm pack --dry-run    # preview what will be published
npm publish           # runs clean → build → test automatically
```

### PyPI

```bash
cd python
pip install --upgrade build twine
python -m build
twine upload dist/*
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes and add tests
4. Run `npm test && npm run typecheck` to verify
5. Commit and push your branch
6. Open a pull request

---

## License

[MIT](LICENSE)
