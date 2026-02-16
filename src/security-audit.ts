/**
 * @cbrowser/mcp-guardian - Security Audit Tool Handler
 * Copyright 2026 Alexandria Eden
 * MIT License
 */

import { z } from "zod";
import {
  scanToolDefinitions,
  formatScanReport,
} from "./patterns.js";
import { scanMcpConfig, scanMcpConfigSync } from "./manifest.js";
import { loadToolManifest } from "./tool-pinning.js";
import { getDefaultConfigPath } from "./config.js";
import type { ServerScanResult, ScanSummary, ToolDefinition } from "./types.js";

/**
 * Zod schema for security_audit parameters
 */
export const SecurityAuditSchema = {
  config_path: z
    .string()
    .optional()
    .describe(
      "Path to claude_desktop_config.json. If not provided, scans the current server's tools."
    ),
  format: z
    .enum(["json", "text"])
    .optional()
    .default("json")
    .describe("Output format: json (structured) or text (human-readable)"),
  async_scan: z
    .boolean()
    .optional()
    .default(false)
    .describe("If true, actually connects to MCP servers to scan their tools. Slower but more accurate."),
};

export type SecurityAuditParams = {
  config_path?: string;
  format?: "json" | "text";
  async_scan?: boolean;
};

/**
 * Extended params for programmatic use (includes tools array)
 */
export type SecurityAuditHandlerOptions = SecurityAuditParams & {
  /** Direct tool definitions to scan (for embedding in MCP servers) */
  tools?: ToolDefinition[];
  /** Server name when scanning direct tools */
  serverName?: string;
};

/**
 * Security audit tool handler.
 *
 * Scans MCP tool definitions for potential prompt injection attacks.
 *
 * @param params - Tool parameters (or extended options with direct tools)
 * @returns MCP tool result with scan report
 */
export async function securityAuditHandler(params: SecurityAuditHandlerOptions): Promise<{
  content: Array<{ type: "text"; text: string }>;
}> {
  const { config_path, format = "json", async_scan = false, tools: directTools, serverName } = params;

  let result: ServerScanResult | ScanSummary;

  if (directTools && directTools.length > 0) {
    // Scan tools passed directly (e.g., from embedding MCP server)
    result = scanToolDefinitions(directTools, serverName || "current-server");
  } else if (config_path) {
    // Scan external MCP config
    if (async_scan) {
      result = await scanMcpConfig(config_path);
    } else {
      result = scanMcpConfigSync(config_path);
    }
  } else {
    // Scan current tools from manifest
    const manifest = loadToolManifest();

    if (!manifest) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                error: "No tool manifest found",
                hint:
                  "Provide a config_path to scan your Claude Desktop config, or the embedding server should pass its tools directly.",
                defaultConfigPath: getDefaultConfigPath(),
              },
              null,
              2
            ),
          },
        ],
      };
    }

    // Convert manifest entries to tool definitions for scanning
    // Note: We only have the tool names and metadata, not the actual descriptions
    // from the manifest. For a full scan, we'd need to query the server.
    const tools = Object.entries(manifest.tools).map(([name, entry]) => ({
      name,
      // We use a placeholder description since manifest doesn't store descriptions
      // Full scanning would require querying the actual server
      description: `Tool: ${name} (${entry.descriptionLength} chars, ${entry.parameterCount} params)`,
      schema: {},
    }));

    result = scanToolDefinitions(tools, manifest.server);

    // Add manifest info to result
    (result as ServerScanResult & { manifestInfo?: object }).manifestInfo = {
      version: manifest.version,
      pinnedAt: manifest.pinnedAt,
      toolCount: Object.keys(manifest.tools).length,
    };
  }

  // Format output
  if (format === "text" && "serverName" in result) {
    return {
      content: [
        {
          type: "text",
          text: formatScanReport(result as ServerScanResult),
        },
      ],
    };
  }

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(result, null, 2),
      },
    ],
  };
}
