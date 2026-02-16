/**
 * @cbrowser/mcp-guardian - Configuration
 * Copyright 2026 Alexandria Eden
 * MIT License
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

/**
 * Get the data directory for mcp-guardian.
 * Uses ~/.mcp-guardian/ by default.
 */
export function getDataDir(): string {
  return process.env.MCP_GUARDIAN_DATA_DIR || join(homedir(), ".mcp-guardian");
}

/**
 * Get the package version from package.json
 */
export function getVersion(): string {
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const pkgPath = join(__dirname, "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    return pkg.version || "1.0.0";
  } catch {
    // Fallback for dist directory
    try {
      const __filename = fileURLToPath(import.meta.url);
      const __dirname = dirname(__filename);
      const pkgPath = join(__dirname, "..", "..", "package.json");
      const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
      return pkg.version || "1.0.0";
    } catch {
      return "1.0.0";
    }
  }
}

/**
 * Get the default Claude Desktop config path based on platform.
 */
export function getDefaultConfigPath(): string {
  const platform = process.platform;
  const home = homedir();

  switch (platform) {
    case "darwin":
      return join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
    case "win32":
      return join(process.env.APPDATA || join(home, "AppData", "Roaming"), "Claude", "claude_desktop_config.json");
    default:
      // Linux and others
      return join(home, ".config", "Claude", "claude_desktop_config.json");
  }
}
