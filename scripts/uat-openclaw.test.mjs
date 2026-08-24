/**
 * Guards on the operator-run OpenClaw UAT helper.
 *
 * The helper must prepare the gate and print operator steps **without** starting — or requiring —
 * a live OpenClaw gateway, mirroring `uat-codex.sh`'s philosophy: automating a live agent runtime
 * has already proven unreliable, so the human drives the runtime.
 *
 * @see ../docs/openclaw-integration.md §3 operator prerequisites, §11 UAT checklist
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const SCRIPT_URL = new URL("./uat-openclaw.sh", import.meta.url);

async function readScript() {
  return await readFile(SCRIPT_URL, "utf8");
}

/** Drop here-doc bodies so "did the script *run* X?" is asked of executable lines only. */
function stripHereDocs(source) {
  const lines = source.split("\n");
  const kept = [];
  let terminator = null;

  for (const line of lines) {
    if (terminator !== null) {
      if (line.trim() === terminator) terminator = null;
      continue;
    }
    kept.push(line);
    const match = /<<-?\s*'?([A-Za-z0-9_]+)'?/.exec(line);
    if (match) terminator = match[1];
  }

  return kept.join("\n");
}

/** Extract the body of the here-doc that writes the throwaway OpenClaw config. */
function extractOpenClawConfig(source) {
  const match = /<<'JSON'\n([\s\S]*?)\nJSON\b/m.exec(source);
  return match ? match[1] : "";
}

test("the helper prepares the gate without invoking or requiring OpenClaw", async () => {
  const script = await readScript();
  const activeShell = stripHereDocs(script);

  assert.match(script, /pnpm run build:wasm/);
  assert.match(script, /pnpm -r build/);
  assert.match(script, /pnpm --filter @allw\/relay dev/);
  assert.match(script, /allw-approver|approver\/dist\/cli\.js/);
  assert.match(script, /openclaw-bridge\/dist\/cli\.js/);

  // The helper must never start the gateway, and must not gate itself on one existing.
  assert.doesNotMatch(
    activeShell,
    /^\s*(?:command\s+|exec\s+|env\s+[^#\n]*\s+)?openclaw(?:\s|$)/m,
    "the helper must never run the openclaw binary itself",
  );
  assert.doesNotMatch(activeShell, /\$\(\s*openclaw(?:\s|\))/);
  assert.doesNotMatch(activeShell, /`\s*openclaw(?:\s|`)/);
  assert.doesNotMatch(
    activeShell,
    /require_command\s+openclaw/,
    "a live OpenClaw install must not be a precondition for preparing the environment",
  );
});

test("the wrapper exports the bridge's configuration, including the actor label", async () => {
  const script = await readScript();

  for (const key of [
    "ALLW_RELAY_URL",
    "ALLW_ACCOUNT_ID",
    "ALLW_APPROVER_ROOT_KEY",
    "ALLW_OPENCLAW_GATEWAY_URL",
    "ALLW_OPENCLAW_GATEWAY_ID",
    "ALLW_OPENCLAW_STATE_DIR",
  ]) {
    assert.match(script, new RegExp(`export ${key}`), `wrapper must export ${key}`);
  }
  assert.match(
    script,
    /ALLW_OPENCLAW_MAX_TIMEOUT_MS/,
    "the timeout case needs a documented way to shorten the bridge's own deadline",
  );
});

test("the generated OpenClaw config carries the §3 operator prerequisites", async () => {
  const config = JSON.parse(extractOpenClawConfig(await readScript()));

  // `auto` is explicitly not acceptable: it routes misses through OpenClaw's native auto-reviewer,
  // which can approve without a human.
  assert.equal(config.tools.exec.mode, "ask");
  assert.notEqual(config.tools.exec.mode, "auto");
  assert.equal(config.tools.exec.strictInlineEval, true);
  assert.equal(config.hostApprovals.ask, "always");
  assert.equal(config.hostApprovals.askFallback, "deny");
  assert.equal(config.autoAllowSkills, false);
  // Competing approval surfaces are disabled so first-answer-wins does not race the bridge.
  assert.equal(config.approvals.exec.enabled, false);
  assert.equal(config.approvals.plugin.enabled, false);
});

test("the printed checklist covers the exec UAT steps and names the deferred ones", async () => {
  const script = await readScript();

  assert.match(script, /Approve \(exec\): PASS\/FAIL/);
  assert.match(script, /Deny \(exec\): PASS\/FAIL/);
  assert.match(script, /Timeout: PASS\/FAIL/);
  assert.match(script, /Actor identity: PASS\/FAIL/);
  assert.match(script, /Plan divergence: PASS\/FAIL/);
  assert.match(script, /openclaw:\$GATEWAY_ID/, "the inbox actor identity must be shown verbatim");
  assert.match(
    script,
    /openclaw devices approve/,
    "pairing is operator-driven and must be printed",
  );
  assert.match(
    script,
    /Deferred to a later slice/,
    "the checklist must say which upstream steps this slice does not cover",
  );
});

test("secrets stay out of the generated config file", async () => {
  const config = extractOpenClawConfig(await readScript());

  assert.doesNotMatch(config, /deviceToken/i);
  assert.doesNotMatch(config, /ACCOUNT_ROOT_KEY/);
  assert.doesNotMatch(config, /BOOTSTRAP/);
});
