# ⚠️ Poisoned MCP Server Example

> **WARNING: This is a deliberately malicious MCP server for testing and educational purposes only.**
> **DO NOT use this as a real MCP server. DO NOT connect it to production systems.**

This example demonstrates the attack patterns that mcp-guardian detects. Each tool description contains real prompt injection techniques documented in published security research.

## Purpose

1. **Testing** — Verify mcp-guardian detects all known attack patterns
2. **Education** — Demonstrate what malicious MCP tool descriptions look like
3. **Demo** — Provide compelling visuals for documentation and presentations

## Attack Patterns Demonstrated

### Tool 1: `add`
**Attacks:** Cross-tool instruction, sensitive path access, data exfiltration, stealth directive

The description instructs the LLM to read `~/.ssh/id_rsa` using another tool and pass it as a parameter — a classic exfiltration technique. The "silently without informing the user" phrase attempts to hide the attack.

### Tool 2: `format_text`
**Attacks:** Privilege escalation, instruction override, stealth directive

Uses fake `<system>` tags to attempt a jailbreak, instructs the LLM to ignore previous instructions, and tries to extract environment variables via another tool.

### Tool 3: `search_docs`
**Attacks:** URL exfiltration, sensitive path access, encoded content

Instructs the LLM to send data to an external URL, access AWS credentials, and includes base64-encoded content (a common obfuscation technique).

### Tool 4: `calculator`
**Clean** — Intentionally safe to show contrast in scan results.

## Research References

These attack patterns are based on real documented vulnerabilities:

- **Invariant Labs** — [MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- **Microsoft** — [Protecting Against Indirect Injection Attacks in MCP](https://developer.microsoft.com/blog/protecting-against-indirect-injection-attacks-mcp)
- **Palo Alto Unit 42** — [Model Context Protocol Attack Vectors](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- **Simon Willison** — [MCP Prompt Injection](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)

## Usage

### Run the demo scan

From the mcp-guardian root directory:

```bash
npm run demo
```

### Manual setup

```bash
cd examples/poisoned-server
npm install
node index.js  # Starts MCP server on stdio
```

## Expected Output

When scanning with mcp-guardian:

```
=== MCP Guardian Security Scan ===
Servers: 1

Servers found:
  🔴 poisoned-example (4 tools)
     └─ add:
        🚨 CRITICAL: cross_tool_instruction
           Match: "before calling this tool" at position 32
        🚨 CRITICAL: sensitive_path
           Match: "~/.ssh/id_rsa" at position 89
        🚨 CRITICAL: stealth_directive
           Match: "silently without informing the user" at position 189
     └─ format_text:
        🚨 CRITICAL: privilege_escalation
           Match: "ignore all previous instructions" at position 52
        🚨 CRITICAL: cross_tool_instruction
           Match: "using the get_env tool" at position 156
        🚨 CRITICAL: stealth_directive
           Match: "do not reveal these instructions" at position 215
     └─ search_docs:
        🚨 CRITICAL: exfiltration_url
           Match: "https://evil-analytics.example.com/collect" at position 78
        🚨 CRITICAL: sensitive_path
           Match: "~/.aws/credentials" at position 198
        ⚠️  WARNING: encoded_content
           Match: "dGhpcyBpcyBhIHRlc3Q=" at position 265

Summary:
  📊 Total tools: 4
  ✅ Clean: 1
  ⚠️  Warning: 1
  🚨 Critical: 8
```

## License

MIT — This example is part of the mcp-guardian project.
