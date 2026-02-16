/**
 * @cbrowser/mcp-guardian - MCP Config Manifest Parsing
 * Copyright 2026 Alexandria Eden
 * MIT License
 */

import { existsSync, readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type {
  McpConfig,
  McpServerConfig,
  ToolDefinition,
  ScanSummary,
  ServerScanResult,
} from "./types.js";
import { scanToolDefinitions } from "./patterns.js";

/**
 * Parse an MCP configuration file.
 *
 * @param configPath - Path to claude_desktop_config.json
 * @returns Parsed config or null if invalid
 */
export function parseConfig(configPath: string): McpConfig | null {
  if (!existsSync(configPath)) {
    return null;
  }

  try {
    const content = readFileSync(configPath, "utf-8");
    return JSON.parse(content) as McpConfig;
  } catch {
    return null;
  }
}

/**
 * Extract tool definitions from a running MCP server via stdio.
 *
 * @param serverConfig - Server configuration with command and args
 * @param serverName - Name of the server for logging
 * @param timeout - Connection timeout in ms (default: 10000)
 * @returns Array of tool definitions or null on error
 */
export async function extractToolsFromServer(
  serverConfig: McpServerConfig,
  serverName: string,
  timeout: number = 10000
): Promise<ToolDefinition[] | null> {
  if (!serverConfig.command) {
    console.error(`[mcp-guardian] No command for server: ${serverName}`);
    return null;
  }

  try {
    // Create stdio transport
    const mergedEnv: Record<string, string> = {};
    if (serverConfig.env) {
      // Copy process.env, filtering out undefined values
      for (const [key, value] of Object.entries(process.env)) {
        if (value !== undefined) {
          mergedEnv[key] = value;
        }
      }
      // Add server-specific env vars
      Object.assign(mergedEnv, serverConfig.env);
    }

    const transport = new StdioClientTransport({
      command: serverConfig.command,
      args: serverConfig.args || [],
      env: serverConfig.env ? mergedEnv : undefined,
    });

    // Create MCP client
    const client = new Client({
      name: "mcp-guardian",
      version: "1.0.0",
    }, {
      capabilities: {},
    });

    // Connect with timeout
    const connectPromise = client.connect(transport);
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error("Connection timeout")), timeout);
    });

    await Promise.race([connectPromise, timeoutPromise]);

    // List tools
    const response = await client.listTools();

    // Extract tool definitions
    const tools: ToolDefinition[] = response.tools.map((tool) => ({
      name: tool.name,
      description: tool.description || "",
      schema: tool.inputSchema || {},
    }));

    // Close connection
    await client.close();

    return tools;
  } catch (error) {
    console.error(`[mcp-guardian] Failed to query server ${serverName}:`, (error as Error).message);
    return null;
  }
}

/**
 * Scan all MCP servers defined in a config file.
 *
 * @param configPath - Path to claude_desktop_config.json
 * @param options - Scan options
 * @returns Scan summary with results for each server
 */
export async function scanMcpConfig(
  configPath: string,
  options: {
    /** Timeout per server in ms (default: 10000) */
    timeout?: number;
    /** Skip servers that fail to connect (default: true) */
    skipFailures?: boolean;
  } = {}
): Promise<ScanSummary> {
  const { timeout = 10000, skipFailures = true } = options;

  const config = parseConfig(configPath);
  if (!config) {
    return {
      servers: [],
      summary: { total: 0, clean: 0, warning: 0, critical: 0 },
    };
  }

  const servers: ServerScanResult[] = [];
  let total = 0;
  let clean = 0;
  let warning = 0;
  let critical = 0;

  if (!config.mcpServers) {
    return {
      servers: [],
      summary: { total: 0, clean: 0, warning: 0, critical: 0 },
    };
  }

  for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
    console.error(`[mcp-guardian] Scanning server: ${serverName}`);

    const tools = await extractToolsFromServer(serverConfig, serverName, timeout);

    if (!tools) {
      if (!skipFailures) {
        servers.push({
          serverName,
          toolCount: 0,
          status: "clean",
          issues: [],
        });
      }
      continue;
    }

    const result = scanToolDefinitions(tools, serverName);
    servers.push(result);

    total += result.toolCount;
    if (result.status === "critical") {
      critical++;
    } else if (result.status === "warning") {
      warning++;
    } else {
      clean++;
    }
  }

  return {
    servers,
    summary: {
      total,
      clean,
      warning,
      critical,
    },
  };
}

/**
 * Synchronous version that only parses config structure.
 * Does NOT query servers - use scanMcpConfig for full scanning.
 *
 * @param configPath - Path to claude_desktop_config.json
 * @returns Summary with server names but no tool data
 */
export function scanMcpConfigSync(configPath: string): ScanSummary {
  const config = parseConfig(configPath);
  if (!config) {
    return {
      servers: [],
      summary: { total: 0, clean: 0, warning: 0, critical: 0 },
    };
  }

  const servers: ServerScanResult[] = [];

  if (config.mcpServers) {
    for (const serverName of Object.keys(config.mcpServers)) {
      servers.push({
        serverName,
        toolCount: 0,
        status: "clean", // Cannot determine without querying server
        issues: [],
      });
    }
  }

  return {
    servers,
    summary: { total: 0, clean: 0, warning: 0, critical: 0 },
  };
}
