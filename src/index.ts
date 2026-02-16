/**
 * @cbrowser/mcp-guardian
 * MCP Security Scanner - detect prompt injection in tool descriptions
 *
 * Copyright 2026 Alexandria Eden
 * MIT License
 */

// Types
export type {
  ScanSeverity,
  ScanIssue,
  ToolScanResult,
  ServerScanResult,
  ScanSummary,
  ToolDefinition,
  ToolPinEntry,
  ServerManifestEntry,
  ToolManifest,
  LegacyToolManifest,
  PinningResult,
  McpServerConfig,
  McpConfig,
  DetectionPattern,
} from "./types.js";

// Config
export {
  getDataDir,
  getVersion,
  getDefaultConfigPath,
} from "./config.js";

// Pattern scanning
export {
  CRITICAL_PATTERNS,
  WARNING_PATTERNS,
  ALL_PATTERNS,
  scanToolDescription,
  scanToolDefinitions,
  formatScanReport,
  isDescriptionSafe,
  setAllowlist,
  getAllowlist,
  loadCustomPatterns,
  setCustomPatternsOnly,
  getActivePatterns,
  type CustomPatternDef,
} from "./patterns.js";

// Tool pinning
export {
  getManifestPath,
  getBackupDir,
  hashToolDefinition,
  createServerEntry,
  createToolManifest,
  loadToolManifest,
  saveToolManifest,
  listBackups,
  rollbackManifest,
  getManifestServers,
  verifyToolDefinitions,
  approveToolChange,
  removeToolFromManifest,
  removeServerFromManifest,
  approveAllTools,
  getManifestSummary,
  getServerSummary,
  getToolDiff,
  type ToolDiff,
  type ToolDiffEntry,
} from "./tool-pinning.js";

// MCP config scanning
export {
  parseConfig,
  extractToolsFromServer,
  scanMcpConfig,
  scanMcpConfigSync,
} from "./manifest.js";

// Security audit handler
export {
  SecurityAuditSchema,
  securityAuditHandler,
  type SecurityAuditParams,
  type SecurityAuditHandlerOptions,
} from "./security-audit.js";
