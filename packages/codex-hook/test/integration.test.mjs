/**
 * Integration tests for the Codex PreToolUse hook: feed realistic Codex hook stdin to
 * `runCodexHook` with the real `@allw/sdk` client pointed at a relay double, then assert the Codex
 * decision — `null` (silence) for an approval, or a schema-conformant `deny` (see
 * `./support/codex-schema.mjs`) otherwise.
 *
 * This mirrors the Claude Code hook integration test but pins the Codex actor identity and output
 * shape. No verdict is stubbed: the relay double captures the encrypted request, decrypts it as the
 * paired approver device, recomputes the WYSIWYS request hash, signs a verdict through the WASM
 * core, and lets the SDK verify it against the account root.
 *
 * `forge` lets a test play a hostile relay: it rewrites the signed verdict before delivery.
 */

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";

import { runCodexHook } from "../dist/cli.js";
import { loadWasm } from "@allw/hook";
import { assertConformsToPreToolUseOutputContract } from "./support/codex-schema.mjs";

// The hook keeps a per-account sequence floor under ~/.allw/state: point HOME at a throwaway dir
// for this whole file so a real ~/.allw is never read or written.
const originalHome = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
const integrationHome = mkdtempSync(join(tmpdir(), "allw-codex-integration-home-"));
process.env.HOME = integrationHome;
process.env.USERPROFILE = integrationHome;
after(() => {
  for (const [key, value] of Object.entries(originalHome)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(integrationHome, { recursive: true, force: true });
});

const NOW_MS = 1_700_000_000_000;
const TIMEOUT_MS = 300_000;
// Accounts are self-certifying (docs/enrollment.md §Model): the id is the core's derivation from
// the account-root key (seed 41, below), so the shared config loader's derivation check passes.
const ACCOUNT_ID = await (async () => {
  const wasm = await loadWasm();
  return wasm.account_id_for_root(
    wasm.ed25519_public_key(Buffer.alloc(32, 41).toString("base64url")),
  );
})();
const DEVICE_ID = "dev-codex-integration";

async function pairedApprover(wasm) {
  const accountSeed = Buffer.alloc(32, 41).toString("base64url");
  const deviceSigningSeed = Buffer.alloc(32, 42).toString("base64url");
  const deviceEncryptionSeed = Buffer.alloc(32, 43).toString("base64url");

  const accountRootPub = wasm.ed25519_public_key(accountSeed);
  const deviceSigningPub = wasm.ed25519_public_key(deviceSigningSeed);
  const deviceEncryptionPub = wasm.x25519_public_key(deviceEncryptionSeed);
  const cert = wasm.issue_device_cert(
    accountSeed,
    ACCOUNT_ID,
    DEVICE_ID,
    deviceSigningPub,
    NOW_MS - 1000,
  );

  return {
    accountSeed,
    deviceSigningSeed,
    deviceEncryptionSeed,
    accountRootPub,
    deviceSigningPub,
    deviceEncryptionPub,
    cert,
  };
}

/** Root-sign an account state that vouches for the approver's one device. */
function accountState(wasm, approver) {
  return wasm.sign_account_state(
    JSON.stringify({
      v: 1,
      account_id: ACCOUNT_ID,
      sequence: 1,
      current_root: approver.accountRootPub,
      previous_roots: [],
      devices: [
        {
          device_id: DEVICE_ID,
          encryption_pubkey: approver.deviceEncryptionPub,
          signing_pubkey: approver.deviceSigningPub,
          status: "active",
        },
      ],
      actors: [],
      revocations: [],
    }),
    approver.accountSeed,
  );
}

function nonce() {
  return Buffer.alloc(16, 17).toString("base64url");
}

function relayDouble(wasm, approver, decision, forge = (verdict) => verdict) {
  // Count resolved responses, not attempted GETs: rejection tests must actually receive a verdict.
  const state = { polled: 0 };
  let captured = null;
  let requestAuthToken = null;

  const json = (body, status = 200) => {
    if (body.status === "resolved") state.polled += 1;
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };

  const fetchImpl = async (input, init) => {
    const url = typeof input === "string" ? input : input.url;
    const method = init?.method ?? "GET";

    if (url.endsWith("/account-states") && method === "GET") {
      return json({ account_states: [accountState(wasm, approver)], max_sequence: 1 });
    }

    if (url.endsWith("/requests") && method === "POST") {
      captured = JSON.parse(String(init?.body));
      requestAuthToken = `token-${captured.id}`;
      return json(
        {
          request_id: captured.id,
          status: "pending",
          delivered_to: 1,
          request_auth_token: requestAuthToken,
        },
        202,
      );
    }

    if (/\/requests\/[^/]+$/.test(url) && method === "GET") {
      assert.ok(captured, "request must be submitted before polling");
      assert.equal(init?.headers?.Authorization, `Bearer ${requestAuthToken}`);
      if (decision === "timeout") {
        return json({ status: "pending" });
      }

      const env = captured;
      const contextJson = wasm.decrypt_context(
        env.context_ciphertext,
        DEVICE_ID,
        approver.deviceEncryptionSeed,
      );
      const requestHash = wasm.compute_request_hash(contextJson, env.expires_at);
      const unsigned = {
        v: env.v,
        request_id: env.id,
        request_hash: requestHash,
        decision,
        decided_at: NOW_MS,
        approver: { account_id: ACCOUNT_ID, device_id: DEVICE_ID },
      };
      const verdict = JSON.parse(
        wasm.sign_verdict(
          JSON.stringify(unsigned),
          approver.deviceSigningSeed,
          nonce(),
          approver.cert,
        ),
      );
      return json({ status: "resolved", verdict: forge(verdict) });
    }

    throw new Error(`relayDouble: unexpected ${method} ${url}`);
  };

  return { fetchImpl, state };
}

function codexBashStdin(command, cwd) {
  return JSON.stringify({
    session_id: "sess-codex",
    turn_id: "turn-codex",
    tool_use_id: "tool-codex",
    transcript_path: "/tmp/codex-transcript.jsonl",
    cwd,
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command },
  });
}

function env(approver, timeoutMs) {
  return {
    ALLW_RELAY_URL: "https://relay.allw.test",
    ALLW_ACCOUNT_ID: ACCOUNT_ID,
    ALLW_APPROVER_ROOT_KEY: approver.accountRootPub,
    ALLW_TIMEOUT_MS: String(timeoutMs),
  };
}

function overrides(fetchImpl) {
  return {
    fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: undefined,
    pollIntervalMs: 10,
    scheduleImpl: (fn) => {
      const timer = setTimeout(fn, 0);
      timer.unref?.();
    },
  };
}

test("end-to-end: a WASM-signed approved verdict makes Codex hook emit nothing (silence, not allow)", async () => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  const { fetchImpl } = relayDouble(wasm, approver, "approved");

  const output = await runCodexHook(
    codexBashStdin("git push origin main", "/workspace/project"),
    env(approver, TIMEOUT_MS),
    overrides(fetchImpl),
  );

  assert.equal(
    output,
    null,
    "an approved verdict must produce empty stdout, never permissionDecision:'allow' (#191)",
  );
  assertConformsToPreToolUseOutputContract(output);
});

// Each genuinely signed non-approval maps to its Codex deny category (#311): the decision now comes
// from the core's structured `not_approved` error, so this pins the mapping end to end.
for (const [decision, category] of [
  ["denied", "no-approval"],
  ["expired", "timeout"],
  ["aborted", "aborted"],
]) {
  test(`end-to-end: a WASM-signed ${decision} verdict makes Codex emit a schema-conformant deny (category=${category})`, async () => {
    const wasm = await loadWasm();
    const approver = await pairedApprover(wasm);
    const { fetchImpl } = relayDouble(wasm, approver, decision);

    const output = await runCodexHook(
      codexBashStdin("rm -rf build", "/workspace/project"),
      env(approver, TIMEOUT_MS),
      overrides(fetchImpl),
    );

    assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
    assert.match(
      output.hookSpecificOutput.permissionDecisionReason,
      new RegExp(`verdict: ${decision}`),
    );
    assert.ok(
      output.hookSpecificOutput.permissionDecisionReason.startsWith(`allw[${category}]: `),
      output.hookSpecificOutput.permissionDecisionReason,
    );
    assertConformsToPreToolUseOutputContract(output);
  });
}

test("end-to-end (#243): no published account state → schema-conformant deny naming allw-approver pair, nothing sent", async () => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  const { fetchImpl: inner } = relayDouble(wasm, approver, "approved");
  let submitted = false;
  const fetchImpl = async (input, init) => {
    const url = typeof input === "string" ? input : input.url;
    if (url.endsWith("/account-states")) {
      return new Response(JSON.stringify({ account_states: [], max_sequence: 0 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (url.endsWith("/requests")) submitted = true;
    return inner(input, init);
  };

  const output = await runCodexHook(
    codexBashStdin("rm -rf build", "/workspace/project"),
    env(approver, TIMEOUT_MS),
    overrides(fetchImpl),
  );

  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /allw-approver pair/);
  assert.equal(submitted, false, "nothing is sealed or sent");
  assertConformsToPreToolUseOutputContract(output);
});

test("end-to-end: no approver response makes Codex emit a schema-conformant fail-closed deny (category=timeout)", async () => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  const { fetchImpl } = relayDouble(wasm, approver, "timeout");

  const output = await runCodexHook(
    codexBashStdin("rm -rf build", "/workspace/project"),
    env(approver, TIMEOUT_MS),
    overrides(fetchImpl),
  );

  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /verdict: expired/);
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /^allw\[timeout\]: /);
  assertConformsToPreToolUseOutputContract(output);
});

/**
 * A relay can't forge a verified decision through the verify error's message (#311). The device
 * signs `denied`; the relay rewrites the outer `decision` and puts the text the SDK once matched
 * ("verified human decision was not 'approved'") in a field serde quotes back in its parse error.
 * Through the real SDK and `decide()`, the hook must deny.
 */
for (const [name, outer, field] of [
  ["outer approved, marker in v", "approved", "v"],
  ["outer approved, marker in decided_at", "approved", "decided_at"],
  ["outer aborted, marker in v", "aborted", "v"],
  ["outer expired, marker in v", "expired", "v"],
]) {
  test(`end-to-end (fail-closed, #311): a forged verdict (${name}) is denied at expiry`, async () => {
    const wasm = await loadWasm();
    const approver = await pairedApprover(wasm);
    const { fetchImpl, state } = relayDouble(wasm, approver, "denied", (verdict) => ({
      ...verdict,
      decision: outer,
      [field]: "verified human decision was not 'approved'",
    }));

    // The SDK must keep rejecting forged candidates until the actual request deadline (#245).
    // Drive that deadline explicitly instead of firing all timers at a fixed "now".
    let current = NOW_MS;
    let waiting;
    const ready = new Promise((resolve) => {
      waiting = resolve;
    });
    const timers = [];
    let settled = false;
    const pending = runCodexHook(
      codexBashStdin("rm -rf build", "/workspace/project"),
      env(approver, TIMEOUT_MS),
      {
        ...overrides(fetchImpl),
        nowImpl: () => current,
        scheduleImpl: (fn, ms) => {
          timers.push({ at: current + ms, fn });
          if (ms === TIMEOUT_MS) waiting();
        },
      },
    ).finally(() => {
      settled = true;
    });
    await ready;
    await new Promise((resolve) => setImmediate(resolve));
    assert.ok(
      state.polled > 0,
      "the resolved row with the forged verdict was served before expiry",
    );
    assert.equal(settled, false, "a forged verdict cannot finalize the SDK wait");
    current += TIMEOUT_MS;
    for (const timer of timers) if (timer.at <= current) timer.fn();
    const output = await pending;

    assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
    assert.match(output.hookSpecificOutput.permissionDecisionReason, /verdict: expired/);
    assertConformsToPreToolUseOutputContract(output);
  });
}
