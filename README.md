# mcp-guardian

MCP security scanner that detects prompt injection attacks in tool descriptions.

## What It Detects

- **Cross-tool instructions** - Attempts to chain tool calls ("before using this tool", "first call", "you must execute")
- **Privilege escalation** - Attempts to override safety ("ignore previous instructions", "you are now", "bypass security")
- **Data exfiltration** - Attempts to send data externally (URLs, "send to", "upload to")
- **Stealth directives** - Hidden instructions in descriptions
- **Sensitive path access** - References to ~/.ssh, ~/.aws, credentials, etc.
- **Encoded content** - Base64, unicode escapes, hex encoding (potential obfuscation)

## Installation

```bash
npm install mcp-guardian
```

## Usage

### CLI - Scan MCP Config

```bash
# Auto-detect Claude Desktop config
npx mcp-guardian

# Explicit config path
npx mcp-guardian /path/to/claude_desktop_config.json

# JSON output
npx mcp-guardian --json
```

### CLI - Run as MCP Server

```bash
npx mcp-guardian --mcp
```

### Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-guardian": {
      "command": "npx",
      "args": ["-y", "mcp-guardian", "--mcp"]
    }
  }
}
```

### Library Usage

```typescript
import {
  scanToolDescription,
  scanToolDefinitions,
  isDescriptionSafe,
  verifyToolDefinitions,
} from "mcp-guardian";

// Scan a single tool description
const result = scanToolDescription("my_tool", "Tool description here");
if (result.status === "critical") {
  console.error("Potential injection:", result.issues);
}

// Quick safety check
if (!isDescriptionSafe("Before using this tool, first call...")) {
  console.warn("Suspicious description detected");
}

// Scan multiple tools
const tools = [
  { name: "tool1", description: "...", schema: {} },
  { name: "tool2", description: "...", schema: {} },
];
const serverResult = scanToolDefinitions(tools, "my-server");

// Tool pinning - detect changes
const pinResult = verifyToolDefinitions(tools);
if (pinResult.status === "changed") {
  console.warn("Tool definitions changed:", pinResult.changedTools);
}
```

## Detection Patterns

### Critical Severity (38 patterns)

| Category | Examples |
|----------|----------|
| Cross-tool instruction | "before using this tool", "first call", "then execute", "always call" |
| Privilege escalation | "ignore previous instructions", "override system", "you are now" |
| Exfiltration | URLs, "send to", "post to", "forward to", "upload to" |

### Warning Severity (13 patterns)

| Category | Examples |
|----------|----------|
| Sensitive paths | ~/.ssh, ~/.aws, /etc/passwd, .env, api_key |
| Encoded content | Base64 strings, unicode escapes, hex encoding |

## Pre-commit Integration

### Using pre-commit framework

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/alexandriashai/mcp-guardian
    rev: v1.2.2
    hooks:
      - id: mcp-guardian
```

### Using Husky

Add to `.husky/pre-commit`:

```bash
#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

npx mcp-guardian --sync --quiet
```

### Using Lefthook

Add to `lefthook.yml`:

```yaml
pre-commit:
  commands:
    mcp-guardian:
      glob: "claude_desktop_config.json"
      run: npx mcp-guardian --sync {staged_files}
```

## Tool Pinning

MCP Guardian includes tool definition pinning - SHA-256 hashing of tool definitions to detect tampering:

```typescript
import { verifyToolDefinitions, approveAllTools } from "mcp-guardian";

// Verify tools against stored baseline
const result = verifyToolDefinitions(tools);

// Status: "created" | "verified" | "changed" | "error"
if (result.status === "changed") {
  console.log("Modified tools:", result.changedTools);
  console.log("New tools:", result.newTools);
  console.log("Removed tools:", result.removedTools);
}

// Re-approve all tools (after review)
approveAllTools(tools);
```

Manifests are stored in `~/.mcp-guardian/tool-manifest.json`.

## Research References

This tool is informed by MCP security research from:

- [Invariant Labs - MCP Security Research](https://invariantlabs.ai)
- [Microsoft - Prompt Injection Attacks](https://microsoft.com/security)
- [Palo Alto Unit 42 - AI Security](https://unit42.paloaltonetworks.com)
- [Simon Willison - Prompt Injection](https://simonwillison.net)

## License

MIT
