/**
 * mcp-guardian - Detection Patterns
 * Copyright 2026 Alexandria Eden
 * MIT License
 */

import type {
  DetectionPattern,
  ScanIssue,
  ToolScanResult,
  ServerScanResult,
  ToolDefinition,
} from "./types.js";

// ============================================================================
// Pattern Definitions
// ============================================================================

/**
 * CRITICAL severity patterns - these indicate likely malicious intent
 */
export const CRITICAL_PATTERNS: DetectionPattern[] = [
  // Cross-tool instructions - attempts to chain tool calls
  {
    regex: /\bbefore\s+using\s+this\s+tool\b/i,
    pattern: "cross_tool_instruction",
    severity: "critical",
  },
  {
    regex: /\bfirst\s+call\b/i,
    pattern: "cross_tool_instruction",
    severity: "critical",
  },
  {
    regex: /\bthen\s+execute\b/i,
    pattern: "cross_tool_instruction",
    severity: "critical",
  },
  {
    regex: /\bafter\s+this\s+tool\b/i,
    pattern: "cross_tool_instruction",
    severity: "critical",
  },
  {
    regex: /\balways\s+call\b/i,
    pattern: "cross_tool_instruction",
    severity: "critical",
  },
  {
    regex: /\byou\s+must\s+(call|use|execute|run)\b/i,
    pattern: "cross_tool_instruction",
    severity: "critical",
  },
  {
    regex: /\bmust\s+first\b/i,
    pattern: "cross_tool_instruction",
    severity: "critical",
  },

  // Privilege escalation - attempts to override safety
  {
    regex: /\bignore\s+(previous|prior|all)\s+instructions?\b/i,
    pattern: "privilege_escalation",
    severity: "critical",
  },
  {
    regex: /\bdisregard\s+(prior|previous|all)\b/i,
    pattern: "privilege_escalation",
    severity: "critical",
  },
  {
    regex: /\boverride\s+(system|safety|security)\b/i,
    pattern: "privilege_escalation",
    severity: "critical",
  },
  {
    regex: /\bbypass\s+(security|safety|restrictions?)\b/i,
    pattern: "privilege_escalation",
    severity: "critical",
  },
  {
    regex: /\bnew\s+system\s+prompt\b/i,
    pattern: "privilege_escalation",
    severity: "critical",
  },
  {
    regex: /\byou\s+are\s+now\b/i,
    pattern: "privilege_escalation",
    severity: "critical",
  },
  {
    regex: /\bforget\s+(everything|all|previous)\b/i,
    pattern: "privilege_escalation",
    severity: "critical",
  },

  // Exfiltration - attempts to send data externally
  {
    regex: /https?:\/\/[^\s]+/i,
    pattern: "exfiltration",
    severity: "critical",
  },
  {
    regex: /\bsend\s+to\b/i,
    pattern: "exfiltration",
    severity: "critical",
  },
  {
    regex: /\bpost\s+to\b/i,
    pattern: "exfiltration",
    severity: "critical",
  },
  {
    regex: /\bforward\s+to\b/i,
    pattern: "exfiltration",
    severity: "critical",
  },
  {
    regex: /\bupload\s+to\b/i,
    pattern: "exfiltration",
    severity: "critical",
  },
  {
    regex: /\btransmit\s+to\b/i,
    pattern: "exfiltration",
    severity: "critical",
  },
  {
    regex: /\bexfiltrate\b/i,
    pattern: "exfiltration",
    severity: "critical",
  },
];

/**
 * WARNING severity patterns - suspicious but may be legitimate
 */
export const WARNING_PATTERNS: DetectionPattern[] = [
  // Sensitive file paths
  {
    regex: /~\/\.ssh\b/i,
    pattern: "sensitive_path",
    severity: "warning",
  },
  {
    regex: /~\/\.aws\b/i,
    pattern: "sensitive_path",
    severity: "warning",
  },
  {
    regex: /~\/\.config\b/i,
    pattern: "sensitive_path",
    severity: "warning",
  },
  {
    regex: /\bcredentials?\b/i,
    pattern: "sensitive_path",
    severity: "warning",
  },
  {
    regex: /\/etc\/passwd\b/i,
    pattern: "sensitive_path",
    severity: "warning",
  },
  {
    regex: /\/etc\/shadow\b/i,
    pattern: "sensitive_path",
    severity: "warning",
  },
  {
    regex: /\.env\b/i,
    pattern: "sensitive_path",
    severity: "warning",
  },
  {
    regex: /\bprivate[_-]?key\b/i,
    pattern: "sensitive_path",
    severity: "warning",
  },
  {
    regex: /\bapi[_-]?key\b/i,
    pattern: "sensitive_path",
    severity: "warning",
  },
  {
    regex: /\bsecret[_-]?key\b/i,
    pattern: "sensitive_path",
    severity: "warning",
  },

  // Encoded content (potential obfuscation)
  // Base64: at least 20 chars of alphanumeric with possible padding
  {
    regex: /[A-Za-z0-9+/]{20,}={0,2}/,
    pattern: "encoded_content",
    severity: "warning",
  },
  // Unicode escape sequences
  {
    regex: /\\u00[0-9a-fA-F]{2}/,
    pattern: "encoded_content",
    severity: "warning",
  },
  // Hex encoded strings
  {
    regex: /\\x[0-9a-fA-F]{2}/,
    pattern: "encoded_content",
    severity: "warning",
  },
];

/**
 * All patterns combined for scanning
 */
export const ALL_PATTERNS: DetectionPattern[] = [
  ...CRITICAL_PATTERNS,
  ...WARNING_PATTERNS,
];

/**
 * Custom patterns loaded at runtime
 */
let customPatterns: DetectionPattern[] = [];
let useCustomPatternsOnly = false;

/**
 * Custom pattern definition for JSON/YAML files
 */
export interface CustomPatternDef {
  id: string;
  description?: string;
  pattern: string;  // RegExp string
  severity: "critical" | "warning" | "info";
  category?: string;
  cwe?: string;
}

/**
 * Load custom patterns from definitions
 */
export function loadCustomPatterns(patterns: CustomPatternDef[]): void {
  customPatterns = patterns.map(p => ({
    regex: new RegExp(p.pattern, "i"),
    pattern: p.id,
    severity: p.severity,
  }));
}

/**
 * Set whether to use only custom patterns (disabling built-in)
 */
export function setCustomPatternsOnly(value: boolean): void {
  useCustomPatternsOnly = value;
}

/**
 * Get the active patterns (built-in + custom or custom only)
 */
export function getActivePatterns(): DetectionPattern[] {
  if (useCustomPatternsOnly) {
    return customPatterns;
  }
  return [...ALL_PATTERNS, ...customPatterns];
}

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Global allowlist for false positive suppression.
 * Phrases in this list will not trigger findings even if they match patterns.
 */
let globalAllowlist: string[] = [];

/**
 * Set the global allowlist.
 *
 * @param phrases - Array of phrases to allow (case-insensitive matching)
 */
export function setAllowlist(phrases: string[]): void {
  globalAllowlist = phrases.map(p => p.toLowerCase());
}

/**
 * Get the current allowlist.
 */
export function getAllowlist(): string[] {
  return [...globalAllowlist];
}

/**
 * Check if a match is allowlisted.
 *
 * @param match - The matched text to check
 * @returns true if the match should be skipped
 */
function isAllowlisted(match: string): boolean {
  const lowerMatch = match.toLowerCase();
  return globalAllowlist.some(phrase => lowerMatch.includes(phrase) || phrase.includes(lowerMatch));
}

/**
 * Scan a single tool's description for injection patterns.
 *
 * @param name - The tool's name
 * @param description - The tool's description text
 * @returns Scan result with status and any issues found
 */
export function scanToolDescription(
  name: string,
  description: string
): ToolScanResult {
  const issues: ScanIssue[] = [];
  const activePatterns = getActivePatterns();

  // Scan for all patterns
  for (const pattern of activePatterns) {
    // Use global flag for finding all matches
    const globalRegex = new RegExp(pattern.regex.source, "gi");
    let match;

    while ((match = globalRegex.exec(description)) !== null) {
      // Skip if match is allowlisted
      if (isAllowlisted(match[0])) {
        continue;
      }

      issues.push({
        pattern: pattern.pattern,
        severity: pattern.severity,
        match: match[0],
        position: match.index,
      });
    }
  }

  // Determine overall status from highest severity
  let status: "clean" | "warning" | "critical" = "clean";
  if (issues.some((i) => i.severity === "critical")) {
    status = "critical";
  } else if (issues.some((i) => i.severity === "warning")) {
    status = "warning";
  }

  return {
    toolName: name,
    status,
    issues,
  };
}

/**
 * Scan an array of tool definitions for injection patterns.
 *
 * @param tools - Array of tool definitions to scan
 * @param serverName - Name of the server (optional, defaults to "unknown")
 * @returns Server scan result with aggregate status
 */
export function scanToolDefinitions(
  tools: ToolDefinition[],
  serverName: string = "unknown"
): ServerScanResult {
  const toolResults: ToolScanResult[] = [];

  for (const tool of tools) {
    const result = scanToolDescription(tool.name, tool.description);
    if (result.status !== "clean") {
      toolResults.push(result);
    }
  }

  // Determine overall server status
  let status: "clean" | "warning" | "critical" = "clean";
  if (toolResults.some((r) => r.status === "critical")) {
    status = "critical";
  } else if (toolResults.some((r) => r.status === "warning")) {
    status = "warning";
  }

  return {
    serverName,
    toolCount: tools.length,
    status,
    issues: toolResults,
  };
}

/**
 * Get a formatted report of scan results.
 *
 * @param result - Server scan result to format
 * @returns Human-readable report string
 */
export function formatScanReport(result: ServerScanResult): string {
  const lines: string[] = [];

  lines.push(`=== Security Scan Report: ${result.serverName} ===`);
  lines.push(`Tools scanned: ${result.toolCount}`);
  lines.push(`Status: ${result.status.toUpperCase()}`);
  lines.push("");

  if (result.issues.length === 0) {
    lines.push("No issues detected.");
  } else {
    lines.push(`Issues found in ${result.issues.length} tool(s):`);
    lines.push("");

    for (const tool of result.issues) {
      lines.push(`[${tool.status.toUpperCase()}] ${tool.toolName}`);
      for (const issue of tool.issues) {
        lines.push(`  - ${issue.pattern}: "${issue.match}"`);
        if (issue.position !== undefined) {
          lines.push(`    Position: ${issue.position}`);
        }
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}

/**
 * Quick check if a description is safe (no critical issues).
 *
 * @param description - Description text to check
 * @returns true if no critical issues found
 */
export function isDescriptionSafe(description: string): boolean {
  const result = scanToolDescription("_check", description);
  return result.status !== "critical";
}
