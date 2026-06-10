#!/usr/bin/env node
/**
 * Locally-automatable end-to-end demo of the v0 walking skeleton (epic #42) — the genuinely-live
 * stack, NOT a CI test.
 *
 * It boots the **real** zero-knowledge relay under `wrangler dev` (workerd), pairs a **real**
 * `@allw/approver` software device against it, starts the **real** approver watch loop (auto-decision
 * mode so the run is unattended), then drives a gated destructive command through the **real**
 * `@allw/hook` `bin` as a subprocess and asserts the emitted permission decision.
 *
 * # Why this is a local gate, not CI (manual-test-design)
 * Unlike the in-process `test/e2e.test.mjs` round-trip, this exercises the relay under its real
 * workerd runtime over real WebSockets, plus the hook as a real OS subprocess. That needs
 * `wrangler dev` and several live processes — environment that a single-process CI `node --test`
 * cannot host. A developer runs `pnpm run demo:e2e` and walks away: it self-checks pass/fail and
 * exits non-zero on failure. See the README "Test layers".
 *
 * # What each layer proves
 * - relay under `wrangler dev`  → the real zero-knowledge routing path (pairing, submit, fan-out,
 *   verdict relay) actually runs under workerd, end to end.
 * - real hook `bin` subprocess  → the Node + WASM entrypoint blocks the tool call and maps the
 *   verified verdict to allow/deny at the real process boundary (stdin → stdout decision JSON).
 * - real approver watch loop    → decrypt → recompute WYSIWYS request_hash → sign over a live socket.
 *
 * Usage:
 *   node scripts/demo-e2e.mjs [--decision approve|deny|timeout] [--port 8787] [--keep]
 *   (pnpm run demo:approve | demo:deny | demo:timeout wrap the three decision modes.)
 *
 * @see ../../packages/relay        (the relay served here by `wrangler dev`)
 * @see ../../packages/approver     (the watch loop driven by src/lib/live-approver.ts)
 * @see ../../packages/hook         (the `bin` invoked as a subprocess)
 * @see ../../../docs/contract.md   (§Transport, §Lifecycle, §Invariants #6)
 */

import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const RELAY_DIR = join(REPO_ROOT, "packages", "relay");
const APPROVER_BIN = join(REPO_ROOT, "packages", "approver", "dist", "cli.js");
const HOOK_BIN = join(REPO_ROOT, "packages", "hook", "dist", "cli.js");

const ACCOUNT_ID = "demo-walking-skeleton";
const DESTRUCTIVE_COMMAND = "git push --force origin main";
const PROJECT_CWD = "/workspace/project";

/** Parse `--flag value` / `--flag` argv into a small options object. */
function parseArgs(argv) {
  const opts = { decision: "approve", port: 8787, keep: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--decision") opts.decision = argv[++i] ?? opts.decision;
    else if (arg === "--port") opts.port = Number(argv[++i] ?? opts.port);
    else if (arg === "--keep") opts.keep = true;
  }
  return opts;
}

/** Map the CLI decision word to the approver's auto-mode and the expected hook decision. */
function resolveMode(decision) {
  switch (decision) {
    case "approve":
      return { mode: "approved", expected: "allow", timeoutMs: 300_000 };
    case "deny":
      return { mode: "denied", expected: "deny", timeoutMs: 300_000 };
    case "timeout":
      // A short fail-closed deadline so the unattended run does not wait minutes.
      return { mode: "timeout", expected: "deny", timeoutMs: 4_000 };
    default:
      throw new Error(`unknown --decision '${decision}' (use approve | deny | timeout)`);
  }
}

/** Sleep helper. */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Spawn `wrangler dev` for the relay and resolve once it answers HTTP. */
async function startRelay(port) {
  const wrangler = join(RELAY_DIR, "node_modules", ".bin", "wrangler");
  const child = spawn(wrangler, ["dev", "--port", String(port), "--inspector-port", "0"], {
    cwd: RELAY_DIR,
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (d) => process.stderr.write(`[relay] ${d}`));
  child.stderr.on("data", (d) => process.stderr.write(`[relay] ${d}`));

  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 60; i++) {
    try {
      const resp = await fetch(`${base}/${ACCOUNT_ID}/devices`);
      if (resp.ok) {
        await resp.body?.cancel();
        return { child, base };
      }
    } catch {
      // not up yet
    }
    await sleep(1000);
  }
  child.kill();
  throw new Error("relay (wrangler dev) did not become ready in 60s");
}

/** Run the real `allw-approver pair` CLI and capture the printed account-root pubkey. */
async function pairApprover(relayBase, keyfilePath) {
  const out = await runCapture(
    process.execPath,
    [
      APPROVER_BIN,
      "pair",
      "--relay",
      relayBase,
      "--account",
      ACCOUNT_ID,
      "--keyfile",
      keyfilePath,
      "--label",
      "walking-skeleton-demo",
    ],
    {},
  );
  process.stderr.write(out.stdout.replace(/^/gm, "[pair] "));
  const match = /account-root pubkey:\s*([A-Za-z0-9_-]+)/.exec(out.stdout);
  if (!match)
    throw new Error(`could not parse account-root pubkey from pair output:\n${out.stdout}`);
  return match[1];
}

/** Run a command to completion, capturing stdout/stderr. Rejects on non-zero exit. */
function runCapture(cmd, args, env) {
  return new Promise((resolveP, rejectP) => {
    const child = spawn(cmd, args, {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += String(d)));
    child.stderr.on("data", (d) => (stderr += String(d)));
    child.on("error", rejectP);
    child.on("close", (code) => {
      if (code === 0) resolveP({ stdout, stderr });
      else rejectP(new Error(`${cmd} ${args.join(" ")} exited ${code}\n${stderr}`));
    });
  });
}

/** Run the hook `bin` as a subprocess, feeding the PreToolUse JSON on stdin; return the decision. */
function runHookBin(env, stdinJson) {
  return new Promise((resolveP, rejectP) => {
    const child = spawn(process.execPath, [HOOK_BIN], {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += String(d)));
    child.stderr.on("data", (d) => process.stderr.write(`[hook] ${d}`));
    child.on("error", rejectP);
    child.on("close", () => {
      try {
        resolveP(JSON.parse(stdout));
      } catch (err) {
        rejectP(new Error(`hook produced unparseable stdout: ${stdout}\n${err}`));
      }
    });
    child.stdin.write(stdinJson);
    child.stdin.end();
  });
}

/** The PreToolUse stdin payload for the gated destructive command. */
function bashStdin() {
  return JSON.stringify({
    session_id: "demo",
    transcript_path: "/tmp/transcript.jsonl",
    cwd: PROJECT_CWD,
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: DESTRUCTIVE_COMMAND },
  });
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const { mode, expected, timeoutMs } = resolveMode(opts.decision);

  process.stderr.write(
    `\n=== allw walking-skeleton live demo — decision=${opts.decision} (expect '${expected}') ===\n`,
  );

  const workdir = await mkdtemp(join(tmpdir(), "allw-demo-"));
  const keyfilePath = join(workdir, "approver-keyfile.json");
  let relay;
  let approverChild;
  let failed = false;

  try {
    relay = await startRelay(opts.port);

    // 1. Pair a real software approver against the live relay; capture the trust anchor.
    const accountRootKey = await pairApprover(relay.base, keyfilePath);
    process.stderr.write(`[demo] paired; account-root pubkey ${accountRootKey}\n`);

    // 2. Start the real approver watch loop in auto-decision mode (a child process, over a live WS).
    //    It blocks until its socket closes; we leave it running while the hook round-trips.
    approverChild = spawn(
      process.execPath,
      ["--input-type=module", "-e", liveApproverProgram(keyfilePath, mode)],
      { cwd: join(REPO_ROOT, "examples", "walking-skeleton"), stdio: ["ignore", "pipe", "pipe"] },
    );
    approverChild.stdout.on("data", (d) => process.stderr.write(`[approver] ${d}`));
    approverChild.stderr.on("data", (d) => process.stderr.write(`[approver] ${d}`));
    // Give the watch loop a moment to connect its presence socket before the hook submits.
    await sleep(2000);

    // 3. Drive the gated command through the real hook bin and read the decision.
    const env = {
      ALLW_RELAY_URL: relay.base,
      ALLW_ACCOUNT_ID: ACCOUNT_ID,
      ALLW_APPROVER_ROOT_KEY: accountRootKey,
      ALLW_TIMEOUT_MS: String(timeoutMs),
    };
    process.stderr.write(`[demo] invoking the hook for: ${DESTRUCTIVE_COMMAND}\n`);
    const output = await runHookBin(env, bashStdin());
    const decision = output.hookSpecificOutput?.permissionDecision;
    const reason = output.hookSpecificOutput?.permissionDecisionReason ?? "";
    process.stderr.write(`[demo] hook decision: ${decision} — ${reason}\n`);

    // 4. Assert the decision matches the mode (fail-closed both ways).
    if (decision !== expected) {
      failed = true;
      process.stderr.write(`\n✘ FAIL — expected '${expected}', got '${decision}'\n`);
    } else {
      process.stderr.write(`\n✔ PASS — the live stack produced '${decision}' as expected.\n`);
    }
  } catch (err) {
    failed = true;
    process.stderr.write(`\n✘ ERROR — ${err instanceof Error ? err.stack : String(err)}\n`);
  } finally {
    approverChild?.kill();
    relay?.child.kill();
    if (!opts.keep) {
      await rm(workdir, { recursive: true, force: true });
    } else {
      process.stderr.write(`[demo] kept workdir: ${workdir}\n`);
    }
  }

  process.exit(failed ? 1 : 0);
}

/**
 * A tiny inline ESM program (run via `node -e`) that imports the example's compiled live-approver
 * and runs the watch loop. Inlined so the demo needs no extra entry file; it resolves
 * `@allw/example-walking-skeleton` from the package's own `dist`.
 */
function liveApproverProgram(keyfilePath, mode) {
  const kf = JSON.stringify(keyfilePath);
  const m = JSON.stringify(mode);
  return [
    `import { runLiveApprover } from "./dist/index.js";`,
    `await runLiveApprover({ keyfilePath: ${kf}, mode: ${m} });`,
  ].join("\n");
}

await main();
