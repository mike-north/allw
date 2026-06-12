#!/usr/bin/env node
/**
 * `allw-hook` — the Claude Code **PreToolUse** permission hook (the v1 beachhead integrator).
 *
 * Reads the pending tool call as JSON on stdin, and — for a gated action (`Bash`, a direct
 * file-edit tool, or an `mcp__server__tool` call) — turns it into a phone approval: it builds the
 * `ActionRecord` via the WASM core, requests a human decision over the zero-knowledge relay
 * (`@allw/sdk`), and emits an `allow` only for a **verified** approval. Everything else
 * (non-approval, timeout, missing config, any error) emits `deny`. Non-gated tools pass through as
 * `allow` without bothering the human.
 *
 * # Runs as Node + WASM (a hard constraint)
 * This is a `node` entrypoint over the same vendored `.wasm` the SDK uses — never a standalone
 * native binary — so enterprise binary-allowlisting (Santa) and MDM cannot block the local surface
 * (`docs/architecture.md`). The `bin` is `node ./dist/cli.js`.
 *
 * # Fail-closed at the process boundary
 * The happy path prints a `hookSpecificOutput` decision JSON and exits 0 (Claude Code reads the
 * decision from stdout). If anything prevents producing that JSON — even an unexpected internal
 * throw — we print a `deny` decision and still exit 0 so Claude Code blocks the tool on a decision
 * it can parse. (Exit code 2 is Claude Code's blocking-error fallback; we prefer an explicit,
 * reasoned `deny` over relying on it, but the catch-all keeps us closed regardless.)
 *
 * @see ./lib/hook-io.ts (the verified PreToolUse wire contract)
 * @see https://code.claude.com/docs/en/hooks
 */

import { realpathSync } from "node:fs";
import { hostname as osHostname } from "node:os";
import { pathToFileURL } from "node:url";

import { createClient, type ClientConfig } from "@allw/sdk";

import { readConfig } from "./lib/config.js";
import { decide, type RequestApprovalFn } from "./lib/decide.js";
import { isGatedTool } from "./lib/gating.js";
import { allowOutput, denyOutput, parseHookInput, type PreToolUseOutput } from "./lib/hook-io.js";
import { loadWasm } from "./lib/wasm.js";
import { getVersion } from "./version.js";

/**
 * Test-only transport seams for the SDK client. Production passes none of these (the SDK uses the
 * global `fetch`/`WebSocket` and the real clock); tests inject a relay double + a fixed clock to
 * drive the full stdin→stdout path deterministically against a WASM-signed verdict.
 *
 * Every field is optional (`Partial`): `runHook`'s `overrides = {}` default must type-check, and
 * each seam is independently injectable, so a test can override just the ones it needs.
 */
export type RunHookOverrides = Partial<
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

/** Read all of stdin to a string (the hook input is a single JSON object). */
async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** Write the decision JSON to stdout. Claude Code reads the permission decision from this. */
function emit(output: PreToolUseOutput): void {
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

/**
 * Run the hook end-to-end against a raw stdin string and an environment map, returning the decision
 * output. Pure with respect to stdout (the caller emits) so it is exercised whole in tests.
 *
 * @param overrides test-only SDK transport seams (a relay double + fixed clock); omitted in prod.
 */
export async function runHook(
  raw: string,
  env: NodeJS.ProcessEnv,
  overrides: RunHookOverrides = {},
): Promise<PreToolUseOutput> {
  const parsed = parseHookInput(raw);
  if (!parsed.ok) {
    return denyOutput(parsed.reason);
  }

  // Fast path: a non-gated tool passes through as `allow` regardless of config — the hook never
  // contacts the relay for it, so a missing/misconfigured `allw` setup must not block reads, edits,
  // greps, etc. Only a *gated* call (Bash / MCP) requires config and the WASM core below.
  if (!isGatedTool(parsed.input.toolName)) {
    return allowOutput(
      `allw: tool '${parsed.input.toolName}' is not gated by allw; passing through`,
    );
  }

  const configResult = readConfig(env);
  if (!configResult.ok) {
    return denyOutput(configResult.reason);
  }
  const config = configResult.config;

  const wasm = await loadWasm();

  // Wire the real SDK client. `requestApproval` is itself fail-closed: it resolves `approved` only
  // for a verified verdict, and `denied`/`expired` (never a bare allow) otherwise. The `overrides`
  // are the SDK's own transport seams — production passes none, so the global fetch/WebSocket/clock
  // are used; tests inject a relay double to exercise the full crypto round-trip deterministically.
  const client = createClient({
    relayUrl: config.relayUrl,
    accountId: config.accountId,
    approverRootKey: config.approverRootKey,
    ...(config.fetchTimeoutMs !== undefined ? { fetchTimeoutMs: config.fetchTimeoutMs } : {}),
    ...overrides,
  });
  const requestApproval: RequestApprovalFn = (req) =>
    // The SDK's ApprovalRequest is structurally what the hook builds; the SDK validates it.
    client.requestApproval(req as Parameters<typeof client.requestApproval>[0]);

  return decide(parsed.input, { wasm, config, requestApproval }, osHostname());
}

/**
 * Diagnostic, non-hook invocations the hook answers **before** touching stdin: `--version`/`-v`
 * prints the version (read from this package's own package.json — never a hardcoded literal, see
 * ./version.ts) and exits 0. Returns `true` when it handled a flag (the caller must not proceed to
 * the stdin hook path).
 *
 * This never runs on the hook hot path: Claude Code invokes the hook with no argv flags and pipes
 * the tool call on stdin, so `argv` is empty there and this is a no-op.
 */
function handleDiagnosticFlags(argv: readonly string[]): boolean {
  if (argv.includes("--version") || argv.includes("-v")) {
    process.stdout.write(`${getVersion()}\n`);
    return true;
  }
  return false;
}

/** The process entrypoint: read stdin, decide, emit, exit 0. Any throw ⇒ a fail-closed deny. */
async function main(): Promise<void> {
  if (handleDiagnosticFlags(process.argv.slice(2))) {
    process.exit(0);
  }

  let output: PreToolUseOutput;
  try {
    const raw = await readStdin();
    output = await runHook(raw, process.env);
  } catch (err) {
    // Defense in depth: an unexpected internal failure must still produce a parseable deny.
    output = denyOutput(
      `allw: hook failed unexpectedly (fail-closed deny): ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
  emit(output);
  // Exit 0 with a decision JSON: Claude Code acts on the decision (allow or deny). A non-zero exit
  // would be a hook *error* rather than a *decision*; we always speak in explicit decisions.
  process.exit(0);
}

/**
 * Decide whether this module was invoked as the process entrypoint (run the hook) vs. imported by a
 * test (do nothing). Comparing `process.argv[1]` directly is wrong for a published install: the
 * `allw-hook` bin is a **symlink** in `node_modules/.bin`, so `argv[1]` is the symlink path while
 * `import.meta.url` is the real `dist/cli.js`, and a naive compare would never run `main()` (the bin
 * would silently print nothing). We therefore resolve `argv[1]` through `realpathSync` (following
 * the bin symlink) before comparing, and compare via a `file://` URL so it is correct cross-platform
 * (a bare path is not a valid ESM specifier on Windows). Regression-tested by the packaged-install
 * smoke test (`scripts/smoke-packaged-install.mjs`).
 */
function isMainEntrypoint() {
  const argv1 = process.argv[1];
  if (argv1 === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(argv1)).href;
  } catch {
    // `realpathSync` throws if argv[1] is not a real path (unusual); fall back to a raw compare.
    return import.meta.url === pathToFileURL(argv1).href;
  }
}

if (isMainEntrypoint()) {
  void main();
}
