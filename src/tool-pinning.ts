/**
 * mcp-guardian - Tool Definition Pinning
 * Copyright 2026 Alexandria Eden
 * MIT License
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from "node:fs";
import { join, basename } from "node:path";
import { getDataDir, getVersion } from "./config.js";

const MAX_BACKUPS = 5;
import type {
  ToolDefinition,
  ToolPinEntry,
  ToolManifest,
  LegacyToolManifest,
  ServerManifestEntry,
  PinningResult,
} from "./types.js";

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Get the path to the tool manifest file.
 * Uses ~/.mcp-guardian/tool-manifest.json by default.
 */
export function getManifestPath(): string {
  const dataDir = getDataDir();
  return join(dataDir, "tool-manifest.json");
}

/**
 * Recursively sort object keys for consistent JSON stringification.
 */
function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj.map(sortObjectKeys);
  }

  const sorted: Record<string, unknown> = {};
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  for (const key of keys) {
    sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
  }
  return sorted;
}

/**
 * Create a SHA-256 hash of a tool definition.
 *
 * The hash includes:
 * - Tool name
 * - Tool description
 * - JSON-stringified schema (sorted keys for consistency)
 *
 * @param name - Tool name
 * @param description - Tool description
 * @param schema - Tool schema object
 * @returns 64-character hex SHA-256 hash
 */
export function hashToolDefinition(
  name: string,
  description: string,
  schema: unknown
): string {
  // Use sorted JSON for consistent hashing
  const payload = JSON.stringify({
    name,
    description,
    schema: sortObjectKeys(schema),
  });

  return createHash("sha256").update(payload).digest("hex");
}

/**
 * Count the number of parameters in a schema.
 * Assumes top-level keys are parameters.
 */
function countParameters(schema: unknown): number {
  if (schema === null || typeof schema !== "object") {
    return 0;
  }
  return Object.keys(schema as Record<string, unknown>).length;
}

/**
 * Check if a manifest is in legacy format
 */
function isLegacyManifest(data: unknown): data is LegacyToolManifest {
  const obj = data as Record<string, unknown>;
  return typeof obj.server === "string" && typeof obj.tools === "object" && !obj.format;
}

/**
 * Migrate a legacy single-server manifest to multi-server format
 */
function migrateLegacyManifest(legacy: LegacyToolManifest): ToolManifest {
  return {
    version: legacy.version,
    format: "multi-server",
    servers: {
      [legacy.server]: {
        pinnedAt: legacy.pinnedAt,
        tools: legacy.tools,
      },
    },
  };
}

/**
 * Create a tool manifest entry for a server from tool definitions.
 *
 * @param tools - Array of tool definitions
 * @returns Server manifest entry ready for storage
 */
export function createServerEntry(tools: ToolDefinition[]): ServerManifestEntry {
  const now = new Date().toISOString();
  const toolEntries: Record<string, ToolPinEntry> = {};

  for (const tool of tools) {
    toolEntries[tool.name] = {
      hash: hashToolDefinition(tool.name, tool.description, tool.schema),
      descriptionLength: tool.description.length,
      parameterCount: countParameters(tool.schema),
      pinnedAt: now,
    };
  }

  return {
    pinnedAt: now,
    tools: toolEntries,
  };
}

/**
 * Create a new multi-server tool manifest from a list of tool definitions.
 *
 * @param tools - Array of tool definitions
 * @param serverName - Server identifier (default: "mcp-guardian")
 * @returns Complete manifest ready for saving
 */
export function createToolManifest(
  tools: ToolDefinition[],
  serverName: string = "mcp-guardian"
): ToolManifest {
  return {
    version: getVersion(),
    format: "multi-server",
    servers: {
      [serverName]: createServerEntry(tools),
    },
  };
}

/**
 * Load the tool manifest from disk.
 * Automatically migrates legacy single-server format to multi-server.
 *
 * @returns Manifest if it exists and is valid, null otherwise
 */
export function loadToolManifest(): ToolManifest | null {
  const path = getManifestPath();

  if (!existsSync(path)) {
    return null;
  }

  try {
    const content = readFileSync(path, "utf-8");
    const data = JSON.parse(content);

    // Check for legacy format and migrate
    if (isLegacyManifest(data)) {
      console.error("[mcp-guardian] Migrating legacy manifest to multi-server format");
      const migrated = migrateLegacyManifest(data);
      saveToolManifest(migrated);
      return migrated;
    }

    const manifest = data as ToolManifest;

    // Basic validation for multi-server format
    if (manifest.format !== "multi-server" || !manifest.servers) {
      console.error("[mcp-guardian] Invalid manifest structure");
      return null;
    }

    return manifest;
  } catch (error) {
    console.error("[mcp-guardian] Failed to load manifest:", (error as Error).message);
    return null;
  }
}

/**
 * Get the directory for manifest backups.
 */
export function getBackupDir(): string {
  return join(getDataDir(), "backups");
}

/**
 * Create a backup of the current manifest before overwriting.
 * Keeps the last MAX_BACKUPS backups.
 */
function backupManifest(): void {
  const path = getManifestPath();
  if (!existsSync(path)) return;

  const backupDir = getBackupDir();
  if (!existsSync(backupDir)) {
    mkdirSync(backupDir, { recursive: true });
  }

  // Create backup with timestamp
  const timestamp = Date.now();
  const backupPath = join(backupDir, `tool-manifest.${timestamp}.json`);

  const content = readFileSync(path, "utf-8");
  writeFileSync(backupPath, content, "utf-8");

  // Prune old backups (keep last MAX_BACKUPS)
  pruneBackups();
}

/**
 * Remove old backups beyond MAX_BACKUPS.
 */
function pruneBackups(): void {
  const backupDir = getBackupDir();
  if (!existsSync(backupDir)) return;

  const files = readdirSync(backupDir)
    .filter(f => f.startsWith("tool-manifest.") && f.endsWith(".json"))
    .sort()
    .reverse();

  // Delete backups beyond MAX_BACKUPS
  for (let i = MAX_BACKUPS; i < files.length; i++) {
    const filePath = join(backupDir, files[i]);
    unlinkSync(filePath);
  }
}

/**
 * List available backups.
 * @returns Array of backup info sorted by timestamp (newest first)
 */
export function listBackups(): Array<{ timestamp: number; path: string; date: string }> {
  const backupDir = getBackupDir();
  if (!existsSync(backupDir)) return [];

  return readdirSync(backupDir)
    .filter(f => f.startsWith("tool-manifest.") && f.endsWith(".json"))
    .map(f => {
      const match = f.match(/tool-manifest\.(\d+)\.json/);
      const timestamp = match ? parseInt(match[1], 10) : 0;
      return {
        timestamp,
        path: join(backupDir, f),
        date: new Date(timestamp).toISOString(),
      };
    })
    .sort((a, b) => b.timestamp - a.timestamp);
}

/**
 * Rollback to a specific backup.
 * @param timestamp - Timestamp of backup to restore, or undefined for latest
 * @returns true if rollback succeeded
 */
export function rollbackManifest(timestamp?: number): { success: boolean; message: string; restoredFrom?: string } {
  const backups = listBackups();

  if (backups.length === 0) {
    return { success: false, message: "No backups available" };
  }

  let targetBackup: typeof backups[0];

  if (timestamp) {
    const found = backups.find(b => b.timestamp === timestamp);
    if (!found) {
      return { success: false, message: `Backup with timestamp ${timestamp} not found` };
    }
    targetBackup = found;
  } else {
    targetBackup = backups[0]; // Latest backup
  }

  try {
    // Backup current state before rolling back
    backupManifest();

    // Restore from backup
    const content = readFileSync(targetBackup.path, "utf-8");
    writeFileSync(getManifestPath(), content, "utf-8");

    return {
      success: true,
      message: `Restored from backup dated ${targetBackup.date}`,
      restoredFrom: targetBackup.path,
    };
  } catch (error) {
    return { success: false, message: `Rollback failed: ${(error as Error).message}` };
  }
}

/**
 * Save a tool manifest to disk.
 * Creates the directory if it doesn't exist.
 * Automatically backs up the previous manifest.
 *
 * @param manifest - The manifest to save
 */
export function saveToolManifest(manifest: ToolManifest): void {
  const path = getManifestPath();
  const dir = join(path, "..");

  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  // Backup before overwriting
  backupManifest();

  const content = JSON.stringify(manifest, null, 2);
  writeFileSync(path, content, "utf-8");
}

/**
 * Get the list of servers in the manifest.
 */
export function getManifestServers(): string[] {
  const manifest = loadToolManifest();
  if (!manifest) return [];
  return Object.keys(manifest.servers);
}

/**
 * Verify tool definitions for a specific server against the pinned manifest.
 *
 * Behavior:
 * - If no manifest exists: Creates one and returns status "created"
 * - If server not in manifest: Adds it and returns status "created"
 * - If all hashes match: Returns status "verified"
 * - If any differences: Returns status "changed" with details
 *
 * @param tools - Current tool definitions from MCP server
 * @param serverName - Server identifier
 * @returns Verification result
 */
export function verifyToolDefinitions(
  tools: ToolDefinition[],
  serverName: string = "mcp-guardian"
): PinningResult {
  let manifest = loadToolManifest();

  // No manifest exists - create one
  if (!manifest) {
    manifest = createToolManifest(tools, serverName);
    saveToolManifest(manifest);
    return {
      status: "created",
      message: `Tool manifest created for ${serverName} with ${tools.length} tools`,
    };
  }

  // Server not in manifest - add it
  if (!manifest.servers[serverName]) {
    manifest.servers[serverName] = createServerEntry(tools);
    manifest.version = getVersion();
    saveToolManifest(manifest);
    return {
      status: "created",
      message: `Server ${serverName} added to manifest with ${tools.length} tools`,
    };
  }

  const serverEntry = manifest.servers[serverName];

  // Compare current tools against server's pinned tools
  const currentToolNames = new Set(tools.map((t) => t.name));
  const pinnedToolNames = new Set(Object.keys(serverEntry.tools));

  const changedTools: string[] = [];
  const newTools: string[] = [];
  const removedTools: string[] = [];

  // Check each current tool
  for (const tool of tools) {
    const pinEntry = serverEntry.tools[tool.name];

    if (!pinEntry) {
      // Tool exists in current but not in manifest
      newTools.push(tool.name);
    } else {
      // Tool exists in both - verify hash
      const currentHash = hashToolDefinition(tool.name, tool.description, tool.schema);
      if (currentHash !== pinEntry.hash) {
        changedTools.push(tool.name);
      }
    }
  }

  // Check for removed tools
  for (const pinnedName of pinnedToolNames) {
    if (!currentToolNames.has(pinnedName)) {
      removedTools.push(pinnedName);
    }
  }

  // Determine overall status
  const hasChanges =
    changedTools.length > 0 || newTools.length > 0 || removedTools.length > 0;

  if (!hasChanges) {
    return {
      status: "verified",
      message: `All ${tools.length} tool definitions for ${serverName} verified successfully`,
    };
  }

  // Build change message
  const parts: string[] = [];
  if (changedTools.length > 0) {
    parts.push(`${changedTools.length} modified: ${changedTools.join(", ")}`);
  }
  if (newTools.length > 0) {
    parts.push(`${newTools.length} new: ${newTools.join(", ")}`);
  }
  if (removedTools.length > 0) {
    parts.push(`${removedTools.length} removed: ${removedTools.join(", ")}`);
  }

  return {
    status: "changed",
    changedTools: changedTools.length > 0 ? changedTools : undefined,
    newTools: newTools.length > 0 ? newTools : undefined,
    removedTools: removedTools.length > 0 ? removedTools : undefined,
    message: `Tool definition changes detected for ${serverName}: ${parts.join("; ")}`,
  };
}

/**
 * Approve a tool change by updating its hash in the manifest.
 * Used to re-approve a tool after intentional modification.
 *
 * @param toolName - Name of the tool to approve
 * @param tool - Current tool definition
 * @param serverName - Server the tool belongs to
 * @throws Error if no manifest or server exists
 */
export function approveToolChange(
  toolName: string,
  tool: ToolDefinition,
  serverName: string = "mcp-guardian"
): void {
  const manifest = loadToolManifest();

  if (!manifest) {
    throw new Error("Cannot approve tool change: no manifest exists");
  }

  if (!manifest.servers[serverName]) {
    throw new Error(`Cannot approve tool change: server ${serverName} not in manifest`);
  }

  const now = new Date().toISOString();

  manifest.servers[serverName].tools[toolName] = {
    hash: hashToolDefinition(tool.name, tool.description, tool.schema),
    descriptionLength: tool.description.length,
    parameterCount: countParameters(tool.schema),
    pinnedAt: now,
  };

  saveToolManifest(manifest);
}

/**
 * Remove a tool from the manifest.
 * Used when a tool is intentionally removed.
 *
 * @param toolName - Name of the tool to remove
 * @param serverName - Server the tool belongs to
 * @throws Error if no manifest exists
 */
export function removeToolFromManifest(
  toolName: string,
  serverName: string = "mcp-guardian"
): void {
  const manifest = loadToolManifest();

  if (!manifest) {
    throw new Error("Cannot remove tool: no manifest exists");
  }

  if (!manifest.servers[serverName]) {
    throw new Error(`Cannot remove tool: server ${serverName} not in manifest`);
  }

  if (manifest.servers[serverName].tools[toolName]) {
    delete manifest.servers[serverName].tools[toolName];
    saveToolManifest(manifest);
  }
}

/**
 * Remove a server from the manifest entirely.
 *
 * @param serverName - Server to remove
 * @throws Error if no manifest exists
 */
export function removeServerFromManifest(serverName: string): void {
  const manifest = loadToolManifest();

  if (!manifest) {
    throw new Error("Cannot remove server: no manifest exists");
  }

  if (manifest.servers[serverName]) {
    delete manifest.servers[serverName];
    saveToolManifest(manifest);
  }
}

/**
 * Approve all current tools for a server, replacing its entry in the manifest.
 * Use with caution - this trusts the current state completely.
 *
 * @param tools - Current tool definitions
 * @param serverName - Server identifier
 */
export function approveAllTools(
  tools: ToolDefinition[],
  serverName: string = "mcp-guardian"
): void {
  let manifest = loadToolManifest();

  if (!manifest) {
    manifest = createToolManifest(tools, serverName);
  } else {
    manifest.servers[serverName] = createServerEntry(tools);
    manifest.version = getVersion();
  }

  saveToolManifest(manifest);
}

/**
 * Get a summary of the current manifest for status display.
 * Returns aggregate information across all servers.
 */
export function getManifestSummary(): {
  exists: boolean;
  serverCount: number;
  totalToolCount: number;
  version: string | null;
  servers: Array<{ name: string; toolCount: number; pinnedAt: string }>;
} {
  const manifest = loadToolManifest();

  if (!manifest) {
    return {
      exists: false,
      serverCount: 0,
      totalToolCount: 0,
      version: null,
      servers: [],
    };
  }

  const servers = Object.entries(manifest.servers).map(([name, entry]) => ({
    name,
    toolCount: Object.keys(entry.tools).length,
    pinnedAt: entry.pinnedAt,
  }));

  const totalToolCount = servers.reduce((sum, s) => sum + s.toolCount, 0);

  return {
    exists: true,
    serverCount: servers.length,
    totalToolCount,
    version: manifest.version,
    servers,
  };
}

/**
 * Get summary for a specific server.
 */
export function getServerSummary(serverName: string): {
  exists: boolean;
  toolCount: number;
  pinnedAt: string | null;
} {
  const manifest = loadToolManifest();

  if (!manifest || !manifest.servers[serverName]) {
    return {
      exists: false,
      toolCount: 0,
      pinnedAt: null,
    };
  }

  const entry = manifest.servers[serverName];
  return {
    exists: true,
    toolCount: Object.keys(entry.tools).length,
    pinnedAt: entry.pinnedAt,
  };
}

/**
 * Tool diff entry showing what changed for a single tool
 */
export interface ToolDiffEntry {
  name: string;
  previousDescriptionLength: number;
  currentDescriptionLength: number;
  previousHash: string;
  currentHash: string;
  previousPinnedAt: string;
}

/**
 * Complete diff result between current tools and manifest for a server
 */
export interface ToolDiff {
  serverName: string;
  added: string[];
  removed: string[];
  changed: ToolDiffEntry[];
  unchanged: number;
  manifestExists: boolean;
  serverExists: boolean;
}

/**
 * Get detailed diff between current tools and the pinned manifest for a server.
 *
 * @param tools - Current tool definitions
 * @param serverName - Server to diff against
 * @returns Detailed diff showing added, removed, and changed tools
 */
export function getToolDiff(
  tools: ToolDefinition[],
  serverName: string = "mcp-guardian"
): ToolDiff {
  const manifest = loadToolManifest();

  if (!manifest) {
    return {
      serverName,
      added: tools.map(t => t.name),
      removed: [],
      changed: [],
      unchanged: 0,
      manifestExists: false,
      serverExists: false,
    };
  }

  if (!manifest.servers[serverName]) {
    return {
      serverName,
      added: tools.map(t => t.name),
      removed: [],
      changed: [],
      unchanged: 0,
      manifestExists: true,
      serverExists: false,
    };
  }

  const serverEntry = manifest.servers[serverName];
  const currentToolNames = new Set(tools.map(t => t.name));
  const pinnedToolNames = new Set(Object.keys(serverEntry.tools));

  const added: string[] = [];
  const removed: string[] = [];
  const changed: ToolDiffEntry[] = [];
  let unchanged = 0;

  // Check each current tool
  for (const tool of tools) {
    const pinEntry = serverEntry.tools[tool.name];

    if (!pinEntry) {
      added.push(tool.name);
    } else {
      const currentHash = hashToolDefinition(tool.name, tool.description, tool.schema);
      if (currentHash !== pinEntry.hash) {
        changed.push({
          name: tool.name,
          previousDescriptionLength: pinEntry.descriptionLength,
          currentDescriptionLength: tool.description.length,
          previousHash: pinEntry.hash,
          currentHash,
          previousPinnedAt: pinEntry.pinnedAt,
        });
      } else {
        unchanged++;
      }
    }
  }

  // Check for removed tools
  for (const pinnedName of pinnedToolNames) {
    if (!currentToolNames.has(pinnedName)) {
      removed.push(pinnedName);
    }
  }

  return {
    serverName,
    added,
    removed,
    changed,
    unchanged,
    manifestExists: true,
    serverExists: true,
  };
}
