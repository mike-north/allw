#!/usr/bin/env node
/**
 * `allw-codex-hook` — Codex PreToolUse permission hook.
 *
 * Reads a Codex pending tool call from stdin, routes gated Bash/MCP actions through allw, and
 * prints a Codex `hookSpecificOutput` decision. Unexpected failures still emit a parseable `deny`
 * and exit 0 so Codex receives an explicit blocking decision instead of a hook error.
 */

import { hostname as osHostname } from "node:os";
import { appendFileSync, realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createClient, type ClientConfig } from "@allw/sdk";
import { isGatedTool, loadWasm, readConfig } from "@allw/hook";

import { decide, type RequestApprovalFn } from "./lib/decide.js";
import {
  denyOutput,
  noBlockOutput,
  parseCodexHookInput,
  type CodexHookResult,
} from "./lib/codex-io.js";
import { getVersion } from "./version.js";

/** Test-only SDK transport seams; production uses SDK defaults. */
export type RunCodexHookOverrides = Partial<
  Pick<
    ClientConfig,
    | "fetchImpl"
    | "nowImpl"
    | "webSocketFactory"
    | "pollIntervalMs"
    | "fetchTimeoutMs"
    | "scheduleImpl"
  >
>;

/** Read the whole stdin stream; Codex sends one JSON object. */
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Emit the Codex decision. `null` ("allw does not block this call") means writing nothing at all:
 * Codex's documented `PreToolUse` contract treats exit 0 with no output as a clean success, and a
 * bare `permissionDecision: "allow"` is an unsupported decision on the current release (see
 * `lib/codex-io.ts` module doc comment). A non-null decision is always an explicit `deny`.
 */
function emit(output: CodexHookResult): void {
  if (output === null) return;
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

/**
 * Append a single deny log line to `.codex/allw-hook.log` in the given directory.
 *
 * The file is created if it does not exist. Errors are swallowed: log appending must never
 * convert a deny into a process crash. The log is intentionally non-leaky — only the
 * `permissionDecisionReason` string (which already carries the machine-readable
 * `allw[<category>]: ` prefix from `denyOutput`) is written, not raw input.
 */
function appendDenyLog(cwd: string, isoTimestamp: string, permissionDecisionReason: string): void {
  try {
    const logPath = `${cwd}/.codex/allw-hook.log`;
    appendFileSync(logPath, `${isoTimestamp} [allw] deny reason=${permissionDecisionReason}\n`);
  } catch {
    // Intentionally swallowed — log failure must never affect the deny decision.
  }
}

/**
 * Run the Codex hook against raw stdin and an env map. Pure with respect to stdout for tests.
 *
 * Non-gated tools pass through before config is read, matching the Claude Code hook behavior.
 */
export async function runCodexHook(
  raw: string,
  env: NodeJS.ProcessEnv,
  overrides: RunCodexHookOverrides = {},
): Promise<CodexHookResult> {
  const parsed = parseCodexHookInput(raw);
  if (!parsed.ok) {
    return denyOutput(parsed.reason, parsed.denyReason);
  }

  if (!isGatedTool(parsed.input.toolName)) {
    return noBlockOutput();
  }

  const configResult = readConfig(env);
  if (!configResult.ok) {
    return denyOutput(configResult.reason, "config-error");
  }
  const config = configResult.config;
  const wasm = await loadWasm();
  const client = createClient({
    relayUrl: config.relayUrl,
    accountId: config.accountId,
    approverRootKey: config.approverRootKey,
    ...(config.fetchTimeoutMs !== undefined ? { fetchTimeoutMs: config.fetchTimeoutMs } : {}),
    ...overrides,
  });
  const requestApproval: RequestApprovalFn = (req) =>
    client.requestApproval(req as Parameters<typeof client.requestApproval>[0]);

  return decide(parsed.input, { wasm, config, requestApproval }, osHostname());
}

/**
 * Diagnostic, non-hook invocations the CLI answers **before** touching stdin: `--version`/`-v`
 * prints the version (read from this package's own package.json — never a hardcoded literal, see
 * ./version.ts) and exits 0. Returns `true` when it handled a flag (the caller must not proceed to
 * the stdin hook path).
 *
 * This never runs on the hook hot path: Codex invokes the hook with no argv flags and pipes the
 * tool call on stdin, so `argv` is empty there and this is a no-op.
 */
function handleDiagnosticFlags(argv: readonly string[]): boolean {
  if (argv.includes("--version") || argv.includes("-v")) {
    process.stdout.write(`${getVersion()}\n`);
    return true;
  }
  return false;
}

/** Process entrypoint: always emit an explicit decision and exit 0. */
async function main(): Promise<void> {
  if (handleDiagnosticFlags(process.argv.slice(2))) {
    process.exit(0);
  }

  let output: CodexHookResult;
  try {
    output = await runCodexHook(await readStdin(), process.env);
  } catch (err) {
    output = denyOutput(
      `allw: Codex hook failed unexpectedly (fail-closed deny): ${
        err instanceof Error ? err.message : String(err)
      }`,
      "transport-error",
    );
  }

  // Append a deny line to the project log so operators can audit without parsing stdout. `output`
  // is non-null only for an explicit `deny` (see `emit`); approvals/pass-throughs log nothing.
  if (output !== null) {
    appendDenyLog(
      process.cwd(),
      new Date().toISOString(),
      output.hookSpecificOutput.permissionDecisionReason,
    );
  }

  emit(output);
  process.exit(0);
}

const entrypoint = process.argv[1];
if (entrypoint !== undefined && isEntrypoint(entrypoint)) {
  void main();
}

/** Package-manager bins are symlinks; resolve both sides before deciding whether to run. */
function isEntrypoint(entrypoint: string): boolean {
  return (
    pathToFileURL(realpathSync(fileURLToPath(import.meta.url))).href ===
    pathToFileURL(realpathSync(entrypoint)).href
  );
}
