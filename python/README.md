# multicloud-security-mcp

[![PyPI version](https://img.shields.io/pypi/v/multicloud-security-mcp.svg)](https://pypi.org/project/multicloud-security-mcp/)
[![npm version](https://img.shields.io/npm/v/multicloud-security-mcp.svg)](https://www.npmjs.com/package/multicloud-security-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A production-ready **Model Context Protocol (MCP)** server providing unified security visibility across **AWS**, **Azure**, and **GCP**. Designed for AI agents and Claude Desktop.

**46 security tools** spanning threat detection, vulnerability management, IAM security, data protection, network security, key/secret management, container security, and compliance — all exposed through a single MCP server.

## Install

```bash
# pip
pip install multicloud-security-mcp

# uv
uv pip install multicloud-security-mcp

# pipx (isolated global install)
pipx install multicloud-security-mcp
```

> **Prerequisite:** Node.js 20+ must be available on PATH. Install from [nodejs.org](https://nodejs.org) if needed.

## Quick Start

```bash
# Run the MCP server
multicloud-security-mcp

# Or via python module
python -m multicloud_security_mcp
```

## Claude Desktop Configuration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

### Using pip installation

```json
{
  "mcpServers": {
    "multicloud-security": {
      "command": "multicloud-security-mcp",
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

### Using uvx (no install needed)

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

## What's Included

### AWS (15 tools)
SecurityHub, GuardDuty, Inspector, IAM Analyzer, Macie, CloudTrail, Detective, Config Rules, WAF, Shield, Network Firewall, Secrets Manager, KMS, ECR, SSM Patch

### Azure (13 tools)
Defender, Sentinel, Entra ID Protection, Purview DLP, Policy, Key Vault, Firewall, DDoS Protection, Container Registry, Network Watcher, Defender for Endpoint, App Service, DevOps Security

### GCP (13 tools)
Security Command Center, Chronicle, IAM Recommender, Cloud DLP, Cloud Armor, Binary Authorization, Artifact Registry, VPC Service Controls, Cloud KMS, Secret Manager, Asset Inventory, Access Transparency, Audit Logs

### Cross-Cloud (5 tools)
Critical Findings aggregation, Compliance Dashboard, IAM Blast Radius analysis, SIEM Correlation, Secret Rotation Audit

## Cloud Authentication

Set environment variables for each cloud you want to use:

```bash
# AWS
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=eu-west-1

# Azure
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_TENANT_ID=...
export AZURE_SUBSCRIPTION_ID=...

# GCP
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
export GCP_PROJECT_ID=your-project
```

## Example Prompts

- *"Show me all CRITICAL findings across all clouds"*
- *"Which IAM roles have never been used in the last 90 days?"*
- *"Are any secrets overdue for rotation?"*
- *"Correlate all GuardDuty and Chronicle events for IP 1.2.3.4"*
- *"Run a CIS compliance check across AWS and GCP"*

## Also Available via npm

```bash
npx multicloud-security-mcp
# or
npm install -g multicloud-security-mcp
```

## License

MIT
