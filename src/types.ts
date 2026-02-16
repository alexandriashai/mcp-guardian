/**
 * @cbrowser/mcp-guardian - MCP Security Scanner
 * Copyright 2026 Alexandria Eden
 * MIT License
 */

// ============================================================================
// Scan Types
// ============================================================================

/**
 * Severity levels for scan issues
 * - info: Informational, not necessarily problematic
 * - warning: Potentially suspicious, warrants review
 * - critical: Highly likely malicious, should be blocked
 */
export type ScanSeverity = "info" | "warning" | "critical";

/**
 * A single issue detected in a tool description
 */
export interface ScanIssue {
  /** Pattern category that matched (e.g., "cross_tool_instruction") */
  pattern: string;
  /** Severity level of this issue */
  severity: ScanSeverity;
  /** The actual text that matched the pattern */
  match: string;
  /** Character position in the description where match was found */
  position?: number;
}

/**
 * Result of scanning a single tool's description
 */
export interface ToolScanResult {
  /** Name of the tool that was scanned */
  toolName: string;
  /** Overall status based on highest severity issue found */
  status: "clean" | "warning" | "critical";
  /** List of issues found in the description */
  issues: ScanIssue[];
}

/**
 * Result of scanning all tools on an MCP server
 */
export interface ServerScanResult {
  /** Name of the server that was scanned */
  serverName: string;
  /** Total number of tools scanned */
  toolCount: number;
  /** Overall status based on worst tool status */
  status: "clean" | "warning" | "critical";
  /** List of tools that had issues (excludes clean tools) */
  issues: ToolScanResult[];
}

/**
 * Summary of scanning multiple MCP servers
 */
export interface ScanSummary {
  /** Results for each server scanned */
  servers: ServerScanResult[];
  /** Aggregate statistics */
  summary: {
    /** Total tools scanned across all servers */
    total: number;
    /** Tools with no issues */
    clean: number;
    /** Tools with warning-level issues */
    warning: number;
    /** Tools with critical-level issues */
    critical: number;
  };
}

// ============================================================================
// Tool Pinning Types
// ============================================================================

/**
 * A tool definition for pinning purposes.
 * Extracted from MCP server tool registration.
 */
export interface ToolDefinition {
  /** Tool name (unique identifier) */
  name: string;
  /** Tool description */
  description: string;
  /** Tool input schema (Zod schema converted to JSON Schema) */
  schema: unknown;
}

/**
 * Entry for a single pinned tool in the manifest.
 */
export interface ToolPinEntry {
  /** SHA-256 hash of name + description + JSON.stringify(schema) */
  hash: string;
  /** Length of description (for quick diff detection) */
  descriptionLength: number;
  /** Number of parameters in schema (for quick diff detection) */
  parameterCount: number;
  /** ISO timestamp when this tool was pinned */
  pinnedAt: string;
}

/**
 * Per-server manifest entry in multi-server manifest.
 */
export interface ServerManifestEntry {
  /** ISO timestamp when this server's tools were pinned */
  pinnedAt: string;
  /** Map of tool name -> pin entry */
  tools: Record<string, ToolPinEntry>;
}

/**
 * The complete tool manifest stored on disk.
 * Supports multiple servers with per-server tracking.
 */
export interface ToolManifest {
  /** Package version that created this manifest */
  version: string;
  /** Multi-server manifest format indicator */
  format: "multi-server";
  /** Map of server name -> server manifest entry */
  servers: Record<string, ServerManifestEntry>;
}

/**
 * Legacy single-server manifest format (for migration).
 * @deprecated Use ToolManifest with multi-server format
 */
export interface LegacyToolManifest {
  /** Server identifier */
  server: string;
  /** Package version that created this manifest */
  version: string;
  /** ISO timestamp when manifest was created */
  pinnedAt: string;
  /** Map of tool name -> pin entry */
  tools: Record<string, ToolPinEntry>;
}

/**
 * Result of verifying tool definitions against the manifest.
 */
export interface PinningResult {
  /** Overall status */
  status: "created" | "verified" | "changed" | "error";
  /** Tools that have different hashes than pinned */
  changedTools?: string[];
  /** Tools present in definitions but not in manifest */
  newTools?: string[];
  /** Tools in manifest but not in definitions */
  removedTools?: string[];
  /** Human-readable message */
  message: string;
}

// ============================================================================
// MCP Config Types
// ============================================================================

/**
 * MCP server configuration from claude_desktop_config.json
 */
export interface McpServerConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
}

/**
 * MCP config structure for parsing claude_desktop_config.json
 */
export interface McpConfig {
  mcpServers?: Record<string, McpServerConfig>;
}

/**
 * Detection pattern definition
 */
export interface DetectionPattern {
  /** Regex pattern to match */
  regex: RegExp;
  /** Pattern category name */
  pattern: string;
  /** Severity if matched */
  severity: ScanSeverity;
}
