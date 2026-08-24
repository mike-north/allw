/**
 * Reads this package's own version from its `package.json` at runtime.
 *
 * The version is **never** a hardcoded literal: a literal silently drifts from the real release on
 * every publish, so `allw-openclaw-bridge --version` would misreport which build an operator is
 * running — exactly the diagnosis-breaking failure the no-hardcoded-versions rule exists to prevent.
 *
 * Layout: this module compiles to `dist/version.js`; the package root (holding `package.json`) is
 * one directory up (`..`). Mirrored by `packages/codex-hook/src/version.ts`.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Fallback when `package.json` is unreadable/malformed — never expected in a real install. */
const UNKNOWN_VERSION = "0.0.0";

/** Resolve the `version` field of this package's `package.json`. */
export function getVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg: unknown = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"));
    if (typeof pkg === "object" && pkg !== null && "version" in pkg) {
      const { version } = pkg;
      if (typeof version === "string") return version;
    }
    return UNKNOWN_VERSION;
  } catch {
    return UNKNOWN_VERSION;
  }
}
