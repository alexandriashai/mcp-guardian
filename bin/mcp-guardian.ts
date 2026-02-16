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
 * Run CLI scan
 */
async function runCliScan(configPath: string | null, options: {
  json?: boolean;
  async?: boolean;
}): Promise<void> {
  const targetPath = configPath || getDefaultConfigPath();

  if (!existsSync(targetPath)) {
    console.error(`Config file not found: ${targetPath}`);
    console.error(`\nDefault paths by platform:`);
    console.error(`  macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json`);
    console.error(`  Windows: %APPDATA%\\Claude\\claude_desktop_config.json`);
    console.error(`  Linux:   ~/.config/Claude/claude_desktop_config.json`);
    process.exit(1);
  }

  console.error(`[mcp-guardian] Scanning: ${targetPath}`);

  let result;
  if (options.async) {
    result = await scanMcpConfig(targetPath);
  } else {
    result = scanMcpConfigSync(targetPath);
    console.error(`[mcp-guardian] Note: Use --async to actually query MCP servers`);
  }

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    // Human-readable output
    console.log(`\n=== MCP Guardian Security Scan ===`);
    console.log(`Config: ${targetPath}`);
    console.log(`Servers: ${result.servers.length}`);
    console.log(`\nServers found:`);

    for (const server of result.servers) {
      const icon = server.status === "critical" ? "🔴" :
                   server.status === "warning" ? "🟡" : "🟢";
      console.log(`  ${icon} ${server.serverName} (${server.toolCount} tools)`);

      if (server.issues.length > 0) {
        for (const tool of server.issues) {
          console.log(`     └─ ${tool.toolName}: ${tool.issues.length} issue(s)`);
        }
      }
    }

    console.log(`\nSummary:`);
    console.log(`  Total tools: ${result.summary.total}`);
    console.log(`  Clean: ${result.summary.clean}`);
    console.log(`  Warning: ${result.summary.warning}`);
    console.log(`  Critical: ${result.summary.critical}`);
  }
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
  --mcp           Run as MCP server (for Claude Desktop integration)
  --json          Output JSON instead of human-readable format
  --async         Actually connect to MCP servers to scan their tools
  --version, -v   Show version
  --help, -h      Show this help

EXAMPLES:
  # Auto-detect Claude Desktop config
  mcp-guardian

  # Scan specific config file
  mcp-guardian /path/to/claude_desktop_config.json

  # Run as MCP server for Claude Desktop
  mcp-guardian --mcp

  # JSON output with async scanning
  mcp-guardian --json --async

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
 * Main entry point
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // Parse options
  const options = {
    mcp: args.includes("--mcp"),
    json: args.includes("--json"),
    async: args.includes("--async"),
    help: args.includes("--help") || args.includes("-h"),
    version: args.includes("--version") || args.includes("-v"),
  };

  // Filter out flags to get config path
  const positionalArgs = args.filter(arg => !arg.startsWith("-"));
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
  process.exit(1);
});
