#!/usr/bin/env node

/**
 * CLI entry point — starts the MCP server over stdio.
 *
 * Usage:
 *   npx multicloud-security-mcp          # run via npx
 *   multicloud-security-mcp              # run if installed globally
 *   node dist/index.js                   # run directly
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import dotenv from "dotenv";
import { createServer } from "./server.js";
import { logger } from "./logger.js";

dotenv.config();

async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("MCP server connected and ready");
}

main().catch((error) => {
  logger.error("Fatal error starting MCP server", { error });
  process.exit(1);
});
