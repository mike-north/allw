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
  allowOutput,
  denyOutput,
  parseCodexHookInput,
  type CodexPreToolUseOutput,
  type DenyReason,
} from "./lib/codex-io.js";

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

/** Emit one Codex decision JSON object. */
function emit(output: CodexPreToolUseOutput): void {
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

/**
 * Append a single deny-reason log line to `.codex/allw-hook.log` in the given directory.
 *
 * The file is created if it does not exist. Errors are swallowed: log appending must never
 * convert a deny into a process crash. The log is intentionally non-leaky — only the
 * `denyReason` category and the `permissionDecisionReason` string are written, not raw input.
 */
function appendDenyLog(
  cwd: string,
  isoTimestamp: string,
  denyReason: DenyReason,
  detail: string,
): void {
  try {
    const logPath = `${cwd}/.codex/allw-hook.log`;
    appendFileSync(logPath, `${isoTimestamp} [allw] deny reason=${denyReason} detail=${detail}\n`);
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
): Promise<CodexPreToolUseOutput> {
  const parsed = parseCodexHookInput(raw);
  if (!parsed.ok) {
    return denyOutput(parsed.reason, parsed.denyReason);
  }

  if (!isGatedTool(parsed.input.toolName)) {
    return allowOutput(
      `allw: tool '${parsed.input.toolName}' is not gated by allw; passing through`,
    );
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

/** Process entrypoint: always emit an explicit decision and exit 0. */
async function main(): Promise<void> {
  let output: CodexPreToolUseOutput;
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

  // Append a deny-reason line to the project log so operators can audit without parsing stdout.
  const { hookSpecificOutput } = output;
  if (
    hookSpecificOutput.permissionDecision === "deny" &&
    hookSpecificOutput.denyReason !== undefined
  ) {
    appendDenyLog(
      process.cwd(),
      new Date().toISOString(),
      hookSpecificOutput.denyReason,
      hookSpecificOutput.permissionDecisionReason,
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
