#!/usr/bin/env node
/**
 * `allw-codex-hook` — Codex PreToolUse permission hook.
 *
 * Reads a Codex pending tool call from stdin, routes gated Bash/MCP actions through allw, and
 * prints a Codex `hookSpecificOutput` decision. Unexpected failures still emit a parseable `deny`
 * and exit 0 so Codex receives an explicit blocking decision instead of a hook error.
 *
 * Output goes through `@allw/hook`'s deny-only writer, shared with the Claude Code hook: empty stdout
 * means "allw does not block this call", and a premature exit (the process reaching
 * `beforeExit`/`exit` before `main()` decides) prints a `deny` instead of reading as consent (#265).
 */

import { hostname as osHostname } from "node:os";
import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import { MAX_ESCAPED_DIAGNOSTIC_CHARS, commandRequest, escapeToPrintableAscii } from "@allw/sdk";
import {
  agentSafeErrorText,
  createHookClient,
  installDecisionBackstop,
  isGatedTool,
  loadWasm,
  readConfig,
  type HookClientOverrides,
} from "@allw/hook";

import { decide, type RequestApprovalFn } from "./lib/decide.js";
import {
  denyOutput,
  noBlockOutput,
  parseCodexHookInput,
  type CodexHookResult,
  type CodexPreToolUseOutput,
} from "./lib/codex-io.js";
import { appendDenyLog } from "./lib/deny-log.js";
import { getVersion } from "./version.js";

/** Test-only SDK transport seams; production uses SDK defaults. */
export type RunCodexHookOverrides = HookClientOverrides;

/** Read the whole stdin stream; Codex sends one JSON object. */
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * The deny the exit backstop prints when the process reaches exit without a finalized decision
 * (#265). Codex reads empty stdout + exit 0 as "no objection", so a premature exit must deny.
 */
export const BACKSTOP_DENY_REASON =
  "allw: Codex hook exited before reaching a decision (fail-closed deny)";

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
  // Recipients come from root-signed account state, never the relay's device list (@allw/hook).
  let client;
  try {
    client = createHookClient(config, overrides);
  } catch (err) {
    return denyOutput(
      `allw: client setup failed (fail-closed deny): ${agentSafeErrorText(wasm, err)}`,
      "config-error",
    );
  }
  const requestApproval: RequestApprovalFn = (req) =>
    client.requestApproval(req as Parameters<typeof client.requestApproval>[0]);

  return decide(parsed.input, { wasm, config, commandRequest, requestApproval }, osHostname());
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

/** Process entrypoint: write the decision (nothing, or a `deny`) and exit 0. */
async function main(): Promise<void> {
  if (handleDiagnosticFlags(process.argv.slice(2))) {
    process.exit(0);
  }

  // From here on, any exit without a finalized decision prints a deny (#265). Decisions are written
  // by `@allw/hook`'s shared deny-only writer: `null` ("allw does not block this call") writes
  // nothing — Codex's documented clean-success path — and a non-null decision is always a `deny`.
  const decision = installDecisionBackstop<CodexPreToolUseOutput>(() =>
    denyOutput(BACKSTOP_DENY_REASON, "premature-exit"),
  );

  let output: CodexHookResult;
  try {
    output = await runCodexHook(await readStdin(), process.env);
  } catch (err) {
    // An unexpected failure's message is unknown text, possibly from before the WASM core loaded,
    // so it is quoted escaped and bounded (#358).
    output = denyOutput(
      `allw: Codex hook failed unexpectedly (fail-closed deny): ${escapeToPrintableAscii(
        err instanceof Error ? err.message : String(err),
        MAX_ESCAPED_DIAGNOSTIC_CHARS,
      )}`,
      "transport-error",
    );
  }

  // Only opted-in, private metadata diagnostics; the decision is independent of disk writes.
  appendDenyLog(process.env, output);

  decision.finalize(output);
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
