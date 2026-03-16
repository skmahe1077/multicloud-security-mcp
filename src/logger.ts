import winston from "winston";

const LOG_LEVEL = process.env["LOG_LEVEL"] ?? "info";
const MASK_ACCOUNTS = process.env["LOG_MASK_ACCOUNT_IDS"] === "true";

function maskAccountId(msg: string): string {
  if (!MASK_ACCOUNTS) return msg;
  return msg.replace(/\b(\d{4})\d{4}(\d{4})\b/g, "$1****$2");
}

const maskFormat = winston.format((info) => {
  if (typeof info.message === "string") {
    info.message = maskAccountId(info.message);
  }
  return info;
});

export const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    maskFormat(),
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "multicloud-security-mcp" },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
      stderrLevels: ["error", "warn", "info", "debug"],
    }),
  ],
});
