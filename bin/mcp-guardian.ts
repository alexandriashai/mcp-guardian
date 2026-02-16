#!/usr/bin/env node
/**
 * @cbrowser/mcp-guardian CLI
 * Copyright 2026 Alexandria Eden
 * MIT License
 */

import { existsSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  getDefaultConfigPath,
  getVersion,
} from "../src/config.js";
import {
  securityAuditHandler,
  SecurityAuditSchema,
} from "../src/security-audit.js";
import {
  scanMcpConfig,
  scanMcpConfigSync,
} from "../src/manifest.js";
import {
  verifyToolDefinitions,
  loadToolManifest,
  getManifestSummary,
} from "../src/tool-pinning.js";
import type { ScanSummary, ScanSeverity, ServerScanResult } from "../src/types.js";

/**
 * Exit codes for CI/CD integration
 * - 0: Clean scan (no issues)
 * - 1: Warnings detected
 * - 2: Critical issues detected
 * - 3: Configuration/runtime error
 */
const EXIT_CLEAN = 0;
const EXIT_WARNING = 1;
const EXIT_CRITICAL = 2;
const EXIT_ERROR = 3;

/**
 * CLI options interface
 */
interface CliOptions {
  mcp: boolean;
  json: boolean;
  sarif: boolean;
  sync: boolean;
  help: boolean;
  version: boolean;
  quiet: boolean;
  exitZero: boolean;
  severityThreshold: ScanSeverity;
  servers: string[];
  excludeServers: string[];
}

const VERSION = getVersion();

/**
 * Run as MCP server
 */
async function runMcpServer(): Promise<void> {
  const server = new Server(
    {
      name: "mcp-guardian",
      version: VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // List tools
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "security_audit",
        description:
          "Audit MCP tool definitions for potential prompt injection attacks. Scans tool descriptions for cross-tool instructions, privilege escalation attempts, and data exfiltration patterns.",
        inputSchema: {
          type: "object",
          properties: {
            config_path: {
              type: "string",
              description:
                "Path to claude_desktop_config.json. If not provided, scans the current server's tools.",
            },
            format: {
              type: "string",
              enum: ["json", "text"],
              default: "json",
              description: "Output format: json (structured) or text (human-readable)",
            },
            async_scan: {
              type: "boolean",
              default: false,
              description: "If true, connects to MCP servers to scan their tools (slower).",
            },
          },
        },
      },
      {
        name: "tool_pin_check",
        description:
          "Check if MCP tool definitions have changed since last verification. Uses SHA-256 hashes to detect tampering.",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
    ],
  }));

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name === "security_audit") {
      return await securityAuditHandler(args as Parameters<typeof securityAuditHandler>[0]);
    }

    if (name === "tool_pin_check") {
      const summary = getManifestSummary();
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(summary, null, 2),
          },
        ],
      };
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: `Unknown tool: ${name}` }),
        },
      ],
    };
  });

  // Start server
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error(`[mcp-guardian] MCP server v${VERSION} running on stdio`);
}

/**
 * Filter results based on severity threshold
 */
function filterBySeverity(result: ScanSummary, threshold: ScanSeverity): ScanSummary {
  if (threshold === "info") return result;

  const filteredServers = result.servers.map(server => {
    const filteredIssues = server.issues.map(tool => ({
      ...tool,
      issues: tool.issues.filter(issue => {
        if (threshold === "critical") return issue.severity === "critical";
        if (threshold === "warning") return issue.severity === "critical" || issue.severity === "warning";
        return true;
      })
    })).filter(tool => tool.issues.length > 0);

    return {
      ...server,
      issues: filteredIssues,
      status: filteredIssues.some(t => t.issues.some(i => i.severity === "critical")) ? "critical" as const :
              filteredIssues.some(t => t.issues.some(i => i.severity === "warning")) ? "warning" as const : "clean" as const
    };
  });

  return {
    servers: filteredServers,
    summary: result.summary // Keep original summary for context
  };
}

/**
 * Generate SARIF 2.1.0 output format
 */
function generateSarif(result: ScanSummary, configPath: string): object {
  const rules: Array<{ id: string; shortDescription: { text: string }; defaultConfiguration: { level: string }; properties?: { cwe?: string } }> = [];
  const ruleIds = new Set<string>();

  // Collect unique rules from findings
  for (const server of result.servers) {
    for (const tool of server.issues) {
      for (const issue of tool.issues) {
        if (!ruleIds.has(issue.pattern)) {
          ruleIds.add(issue.pattern);
          rules.push({
            id: issue.pattern,
            shortDescription: { text: issue.pattern.replace(/_/g, " ") },
            defaultConfiguration: {
              level: issue.severity === "critical" ? "error" : "warning"
            },
            ...(issue.severity === "critical" && { properties: { cwe: "CWE-94" } })
          });
        }
      }
    }
  }

  const results: Array<{
    ruleId: string;
    level: string;
    message: { text: string };
    locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region?: { startLine: number } } }>;
  }> = [];

  for (const server of result.servers) {
    for (const tool of server.issues) {
      for (const issue of tool.issues) {
        results.push({
          ruleId: issue.pattern,
          level: issue.severity === "critical" ? "error" : "warning",
          message: { text: `Detected "${issue.match}" in tool "${tool.toolName}" (server: ${server.serverName})` },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: configPath },
              ...(issue.position !== undefined && { region: { startLine: 1 } })
            }
          }]
        });
      }
    }
  }

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "mcp-guardian",
          version: VERSION,
          informationUri: "https://github.com/alexandriashai/mcp-guardian",
          rules
        }
      },
      results
    }]
  };
}

/**
 * Run CLI scan
 */
async function runCliScan(configPath: string | null, options: CliOptions): Promise<void> {
  const targetPath = configPath || getDefaultConfigPath();

  if (!existsSync(targetPath)) {
    console.error(`Config file not found: ${targetPath}`);
    console.error(`\nDefault paths by platform:`);
    console.error(`  macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json`);
    console.error(`  Windows: %APPDATA%\\Claude\\claude_desktop_config.json`);
    console.error(`  Linux:   ~/.config/Claude/claude_desktop_config.json`);
    process.exit(EXIT_ERROR);
  }

  if (!options.quiet) {
    console.error(`[mcp-guardian] Scanning: ${targetPath}`);
  }

  // Server filter options
  const filterOpts = {
    servers: options.servers.length > 0 ? options.servers : undefined,
    excludeServers: options.excludeServers.length > 0 ? options.excludeServers : undefined,
  };

  // Log server filter if active
  if (!options.quiet) {
    if (options.servers.length > 0) {
      console.error(`[mcp-guardian] Filtering to servers: ${options.servers.join(", ")}`);
    }
    if (options.excludeServers.length > 0) {
      console.error(`[mcp-guardian] Excluding servers: ${options.excludeServers.join(", ")}`);
    }
  }

  let result: ScanSummary;
  if (options.sync) {
    // Sync mode only parses config structure, doesn't query servers
    result = scanMcpConfigSync(targetPath, filterOpts);
    if (!options.quiet) {
      console.error(`[mcp-guardian] Note: --sync mode only reads config structure (no tool scanning)`);
    }
  } else {
    // Default: async mode that actually queries MCP servers
    if (!options.quiet) {
      console.error(`[mcp-guardian] Connecting to MCP servers to scan their tools...`);
    }
    result = await scanMcpConfig(targetPath, filterOpts);
  }

  // Apply severity threshold filter
  const filteredResult = filterBySeverity(result, options.severityThreshold);

  // Determine exit code based on findings
  const exitCode = result.summary.critical > 0 ? EXIT_CRITICAL
                 : result.summary.warning > 0 ? EXIT_WARNING
                 : EXIT_CLEAN;

  // Quiet mode: no output on clean scan
  if (options.quiet && exitCode === EXIT_CLEAN) {
    process.exit(options.exitZero ? EXIT_CLEAN : exitCode);
  }

  // Output results
  if (options.sarif) {
    console.log(JSON.stringify(generateSarif(filteredResult, targetPath), null, 2));
  } else if (options.json) {
    console.log(JSON.stringify(filteredResult, null, 2));
  } else {
    // Human-readable output
    console.log(`\n=== MCP Guardian Security Scan ===`);
    console.log(`Config: ${targetPath}`);
    console.log(`Servers: ${filteredResult.servers.length}`);
    console.log(`\nServers found:`);

    for (const server of filteredResult.servers) {
      const icon = server.status === "critical" ? "🔴" :
                   server.status === "warning" ? "🟡" : "🟢";
      console.log(`  ${icon} ${server.serverName} (${server.toolCount} tools)`);

      if (server.issues.length > 0) {
        for (const tool of server.issues) {
          console.log(`     └─ ${tool.toolName}:`);
          for (const issue of tool.issues) {
            const severity = issue.severity === "critical" ? "🔴 CRITICAL" : "🟡 WARNING";
            console.log(`        ${severity}: ${issue.pattern}`);
            console.log(`           Match: "${issue.match}" at position ${issue.position}`);
          }
        }
      }
    }

    console.log(`\nSummary:`);
    console.log(`  Total tools: ${result.summary.total}`);
    console.log(`  Clean: ${result.summary.clean}`);
    console.log(`  Warning: ${result.summary.warning}`);
    console.log(`  Critical: ${result.summary.critical}`);

    if (options.severityThreshold !== "warning") {
      console.log(`\n  (Filtered to ${options.severityThreshold} severity)`);
    }
  }

  // Exit with appropriate code
  process.exit(options.exitZero ? EXIT_CLEAN : exitCode);
}

/**
 * Show help
 */
function showHelp(): void {
  console.log(`
@cbrowser/mcp-guardian v${VERSION}
MCP security scanner - detect prompt injection in tool descriptions

USAGE:
  mcp-guardian [options] [config_path]

OPTIONS:
  --mcp                      Run as MCP server (for Claude Desktop integration)
  --json                     Output JSON instead of human-readable format
  --sarif                    Output SARIF 2.1.0 format (for GitHub Advanced Security)
  --sync                     Fast mode: only parse config, don't query servers
  --severity-threshold <lvl> Filter results: critical, warning (default), or info
  --server <name>            Only scan specific server(s) (can be repeated)
  --exclude-server <name>    Exclude server(s) from scan (can be repeated)
  --quiet                    Suppress output on clean scans (exit code still set)
  --exit-zero                Always exit with code 0 (for info-only mode)
  --version, -v              Show version
  --help, -h                 Show this help

EXIT CODES:
  0  Clean scan (no issues found)
  1  Warnings detected
  2  Critical issues detected
  3  Configuration or runtime error

EXAMPLES:
  # Scan all MCP servers in Claude Desktop config
  mcp-guardian

  # Scan specific config file
  mcp-guardian /path/to/claude_desktop_config.json

  # Run as MCP server for Claude Desktop
  mcp-guardian --mcp

  # JSON output
  mcp-guardian --json

  # SARIF output for GitHub Advanced Security
  mcp-guardian --sarif > results.sarif

  # Only show critical issues
  mcp-guardian --severity-threshold critical

  # CI mode: quiet on success, fail on findings
  mcp-guardian --quiet

  # Info mode: report but don't fail pipeline
  mcp-guardian --exit-zero

  # Scan only specific server
  mcp-guardian --server my-server

  # Scan all except certain servers
  mcp-guardian --exclude-server untrusted-server

CLAUDE DESKTOP INTEGRATION:
  Add to your claude_desktop_config.json:

  {
    "mcpServers": {
      "mcp-guardian": {
        "command": "npx",
        "args": ["-y", "@cbrowser/mcp-guardian", "--mcp"]
      }
    }
  }
`);
}

/**
 * Parse severity threshold from args
 */
function parseSeverityThreshold(args: string[]): ScanSeverity {
  const idx = args.indexOf("--severity-threshold");
  if (idx === -1 || idx >= args.length - 1) {
    return "warning"; // default
  }
  const value = args[idx + 1];
  if (value === "critical" || value === "warning" || value === "info") {
    return value;
  }
  console.error(`Invalid severity threshold: ${value}. Using 'warning'.`);
  return "warning";
}

/**
 * Parse repeated flag values (e.g., --server a --server b)
 */
function parseRepeatedFlag(args: string[], flag: string): string[] {
  const values: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === flag && i + 1 < args.length) {
      values.push(args[i + 1]);
    }
  }
  return values;
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // Parse options
  const options: CliOptions = {
    mcp: args.includes("--mcp"),
    json: args.includes("--json"),
    sarif: args.includes("--sarif"),
    sync: args.includes("--sync"),
    help: args.includes("--help") || args.includes("-h"),
    version: args.includes("--version") || args.includes("-v"),
    quiet: args.includes("--quiet"),
    exitZero: args.includes("--exit-zero"),
    severityThreshold: parseSeverityThreshold(args),
    servers: parseRepeatedFlag(args, "--server"),
    excludeServers: parseRepeatedFlag(args, "--exclude-server"),
  };

  // Filter out flags to get config path (skip flag values too)
  const flagsWithValues = ["--severity-threshold", "--server", "--exclude-server"];
  const positionalArgs = args.filter((arg, idx) => {
    if (arg.startsWith("-")) return false;
    // Skip values that follow flags with values
    if (idx > 0 && flagsWithValues.includes(args[idx - 1])) return false;
    return true;
  });
  const configPath = positionalArgs[0] || null;

  if (options.version) {
    console.log(VERSION);
    return;
  }

  if (options.help) {
    showHelp();
    return;
  }

  if (options.mcp) {
    await runMcpServer();
    return;
  }

  await runCliScan(configPath, options);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(EXIT_ERROR);
});
