/**
 * Optional private Codex denial diagnostics, separate from the human-facing reason and audit trail.
 * Only metadata created by denyOutput may reach disk; untrusted reason text is never inspected.
 * Like the SDK sequence-floor store, reject linked, foreign-owned or writable state directories.
 * Logging is best effort and cannot change a decision, even if opening or appending fails.
 *
 * @see ../../../../docs/codex-integration.md (Private denial diagnostics)
 */
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  writeSync,
  type Stats,
} from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";

import { denyLogMetadata, type CodexHookResult } from "./codex-io.js";

/** SDK-generated request ids are UUIDs; arbitrary strings are not diagnostic metadata. */
const REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Match the shared user-owned state boundary without changing the SDK's trust-state API. */
function userOwned(stat: Stats): boolean {
  return (
    process.platform === "win32" ||
    ((process.geteuid === undefined || stat.uid === process.geteuid()) && (stat.mode & 0o022) === 0)
  );
}

/** Create a real user-owned directory, refusing an existing symlink before creating children. */
function ensureDirectory(path: string): void {
  try {
    const stat = lstatSync(path);
    if (!stat.isDirectory() || !userOwned(stat)) throw new Error("unsafe log directory");
  } catch (err) {
    if (!(err instanceof Error) || !("code" in err) || err.code !== "ENOENT") throw err;
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  const stat = lstatSync(path);
  if (!stat.isDirectory() || !userOwned(stat)) throw new Error("unsafe log directory");
}

/**
 * Append one metadata-only line when ALLW_CODEX_DENY_LOG is exactly "1". Empty/unset XDG state
 * uses ~/.allw/state; a relative location is refused rather than resolved against the project.
 * Existing logs must already be private regular files; never follow links or open a blocking FIFO.
 * The injected clock keeps fixture bytes deterministic; production uses UTC ISO timestamps.
 * @internal
 */
export function appendDenyLog(
  env: NodeJS.ProcessEnv,
  output: CodexHookResult,
  timestamp: () => string = () => new Date().toISOString(),
): void {
  if (env.ALLW_CODEX_DENY_LOG !== "1" || output === null) return;
  try {
    const metadata = denyLogMetadata(output);
    if (metadata === undefined) return;
    const xdg = env.XDG_STATE_HOME;
    const root = xdg !== undefined && xdg !== "" ? xdg : join(env.HOME ?? homedir(), ".allw");
    if (!isAbsolute(root)) return;
    ensureDirectory(root);
    const dir = join(root, xdg !== undefined && xdg !== "" ? "allw" : "state");
    ensureDirectory(dir);
    // Use one descriptor for the type/owner/mode checks and append. O_NONBLOCK avoids FIFO hangs;
    // O_NOFOLLOW refuses substituted links. Multiple links could redirect writes to another file.
    const optional: Partial<typeof constants> = constants;
    const fd = openSync(
      join(dir, "codex-deny.log"),
      constants.O_WRONLY |
        constants.O_APPEND |
        constants.O_CREAT |
        (optional.O_NOFOLLOW ?? 0) |
        (optional.O_NONBLOCK ?? 0),
      0o600,
    );
    try {
      const stat = fstatSync(fd);
      if (
        !stat.isFile() ||
        !userOwned(stat) ||
        stat.nlink !== 1 ||
        (process.platform !== "win32" && (stat.mode & 0o077) !== 0)
      )
        return;
      const id = metadata.requestId;
      const request = typeof id === "string" && REQUEST_ID.test(id) ? ` request_id=${id}` : "";
      writeSync(fd, `${timestamp()} [allw] deny category=${metadata.category}${request}\n`);
    } finally {
      closeSync(fd);
    }
  } catch {
    // Optional diagnostics must never replace, suppress or throw past the explicit deny.
  }
}
