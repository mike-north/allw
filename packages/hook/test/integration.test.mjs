/**
 * Integration test for the Claude Code PreToolUse hook (issue #13): feed a realistic stdin payload
 * to the hook entrypoint (`runHook`) with the **real `@allw/sdk` client** pointed at a **relay
 * double**, and assert the emitted hook decision.
 *
 * This exercises the full crypto round-trip end-to-end through the WASM core — there is NO verdict
 * stubbing. The relay double plays the approver's role with software-held keys (mirroring
 * `@allw/approver`): it serves the device list, captures the submitted ciphertext envelope,
 * decrypts the human-shown context, recomputes the WYSIWYS `request_hash`, and signs a verdict the
 * SDK then verifies against the account-root key. The poll path is forced (no WebSocket) and the
 * clock is fixed, so the run is fully deterministic — no `Date.now()`, no real network.
 *
 * Two cases pin the fail-closed, deny-only contract end-to-end (#247):
 *   - a signed **approved** verdict → no decision (`null` ⇒ empty stdout), never `allow`;
 *   - a signed **denied** verdict   → the hook emits `deny` (a verified human "no").
 *
 * @see ../../../docs/contract.md §Transport, §Lifecycle, §Invariants #6 (fail-closed)
 * @see ../../approver/test/watch.test.mjs (the same software-keyed approver round-trip)
 * @see https://code.claude.com/docs/en/hooks (the PreToolUse stdin/stdout contract)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runHook } from "../dist/cli.js";
import { loadWasm } from "../dist/lib/wasm.js";

// ── Fixed, deterministic timeline (no Date.now in fixtures) ─────────────────────────────────────
const NOW_MS = 1_700_000_000_000;
const TIMEOUT_MS = 300_000;
// Accounts are self-certifying (docs/enrollment.md §Model): the id is the core's derivation from
// the account-root key (seed 11, below), so the config loader's derivation check passes.
const ACCOUNT_ID = await (async () => {
  const wasm = await loadWasm();
  return wasm.account_id_for_root(
    wasm.ed25519_public_key(Buffer.alloc(32, 11).toString("base64url")),
  );
})();
const DEVICE_ID = "dev-hook-integration";
const DEVICE_LABEL = "test device";

/** Build a paired software approver (account-root + device keys + device cert) via the WASM core. */
async function pairedApprover(wasm) {
  const accountSeed = Buffer.alloc(32, 11).toString("base64url");
  const deviceSigningSeed = Buffer.alloc(32, 22).toString("base64url");
  const deviceEncryptionSeed = Buffer.alloc(32, 33).toString("base64url");

  const accountRootPub = wasm.ed25519_public_key(accountSeed);
  const deviceSigningPub = wasm.ed25519_public_key(deviceSigningSeed);
  const deviceEncryptionPub = wasm.x25519_public_key(deviceEncryptionSeed);

  // Cert with no expiry — its window can't be the thing under test here.
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

/** A 16-byte high-entropy nonce (fixed for determinism; entropy is irrelevant in a single-shot test). */
function nonce() {
  return Buffer.alloc(16, 7).toString("base64url");
}

/**
 * Build a `fetchImpl` relay double. It serves `GET /:acct/devices`, accepts `POST /:acct/requests`
 * (capturing the envelope), and answers `GET /:acct/requests/:id` with a signed verdict of the
 * requested `decision`. The verdict is bound to the captured envelope + the decrypted context, so
 * the SDK's verification (against `approverRootPub`) genuinely passes/round-trips.
 *
 * `forge` lets a test play a hostile relay: it rewrites the signed verdict before delivery.
 */
function relayDouble(wasm, approver, decision, forge = (verdict) => verdict) {
  /** @type {Record<string, unknown> | null} */
  let captured = null;
  let requestAuthToken = null;

  const json = (body, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });

  const fetchImpl = async (input, init) => {
    const url = typeof input === "string" ? input : input.url;
    const method = init?.method ?? "GET";

    // GET /:acct/devices — one enrolled device (the X25519 encryption pubkey is the JWE recipient).
    if (url.endsWith("/devices") && method === "GET") {
      return json({
        devices: [
          {
            device_id: DEVICE_ID,
            pubkey: approver.deviceEncryptionPub,
            label: DEVICE_LABEL,
            created_at: NOW_MS - 10_000,
          },
        ],
      });
    }

    // POST /:acct/requests — capture the opaque envelope and issue the relay-scoped poll token.
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

    // GET /:acct/requests/:id — sign + return a verdict bound to the captured envelope.
    if (/\/requests\/[^/]+$/.test(url) && method === "GET") {
      assert.ok(captured, "the request must have been submitted before polling");
      assert.equal(
        init?.headers?.Authorization,
        `Bearer ${requestAuthToken}`,
        "polling must use the request-scoped bearer token returned by submit",
      );
      const env = captured;

      // The approver decrypts the human-shown context from the JWE it was sent (zero-knowledge
      // relay never sees plaintext) and recomputes the WYSIWYS request_hash over it + expires_at.
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
        decided_at: NOW_MS, // inside [created_at, expires_at] under the fixed clock
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

  return { fetchImpl };
}

/** A realistic PreToolUse stdin payload for a Bash command. */
function bashStdin(command, cwd) {
  return JSON.stringify({
    session_id: "sess-1",
    transcript_path: "/tmp/transcript.jsonl",
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

/** SDK transport overrides: poll-only (no WebSocket) + a fixed clock (deterministic, no Date.now). */
function overrides(fetchImpl) {
  return {
    fetchImpl,
    nowImpl: () => NOW_MS,
    webSocketFactory: undefined, // force the poll path
    pollIntervalMs: 10,
    scheduleImpl: (fn) => {
      // Run scheduled callbacks immediately (the verdict is already available on the first poll).
      setTimeout(fn, 0);
    },
  };
}

test("end-to-end: a WASM-signed approved verdict yields no decision (never allow; #247)", async () => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  const { fetchImpl } = relayDouble(wasm, approver, "approved");

  const output = await runHook(
    bashStdin("rm -rf build", "/workspace/project"),
    env(approver, TIMEOUT_MS),
    overrides(fetchImpl),
  );

  assert.equal(
    output,
    null,
    "a verified approval removes allw's objection; Claude Code's own rules still apply",
  );
});

// Each genuinely signed non-approval is reported with its signed decision (#311): the decision now
// comes from the core's structured `not_approved` error, never the outer verdict.
for (const decision of ["denied", "expired", "aborted"]) {
  test(`end-to-end (fail-closed): a WASM-signed ${decision} verdict makes the hook emit deny`, async () => {
    const wasm = await loadWasm();
    const approver = await pairedApprover(wasm);
    const { fetchImpl } = relayDouble(wasm, approver, decision);

    const output = await runHook(
      bashStdin("rm -rf build", "/workspace/project"),
      env(approver, TIMEOUT_MS),
      overrides(fetchImpl),
    );

    assert.equal(
      output.hookSpecificOutput.permissionDecision,
      "deny",
      "a verified human 'no' keeps the tool call blocked (fail-closed)",
    );
    assert.match(
      output.hookSpecificOutput.permissionDecisionReason,
      new RegExp(`\\(verdict: ${decision}\\)$`),
    );
  });
}

test("end-to-end (fail-closed): missing config (no ALLW_RELAY_URL) → deny without dialing the relay", async () => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  let dialed = false;
  const fetchImpl = () => {
    dialed = true;
    return Promise.reject(new Error("should not be called"));
  };

  const { ALLW_RELAY_URL, ...partialEnv } = env(approver, TIMEOUT_MS);
  void ALLW_RELAY_URL;
  void wasm;

  const output = await runHook(bashStdin("rm -rf build", "/w"), partialEnv, { fetchImpl });

  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.ok(/ALLW_RELAY_URL is not set/.test(output.hookSpecificOutput.permissionDecisionReason));
  assert.equal(dialed, false, "missing config fails closed before any relay dial");
});

/**
 * Point HOME at a fresh temp dir for one test, optionally holding `~/.allw/config.json`, so the
 * loader's *default* path is exercised (issue #230) and a real `~/.allw` never leaks in.
 */
function withConfigHome(t, file) {
  const home = mkdtempSync(join(tmpdir(), "allw-hook-home-"));
  const prev = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  t.after(() => {
    for (const [key, value] of Object.entries(prev)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(home, { recursive: true, force: true });
  });
  if (file !== undefined) {
    mkdirSync(join(home, ".allw"), { mode: 0o700 });
    writeFileSync(join(home, ".allw", "config.json"), JSON.stringify(file), { mode: 0o600 });
  }
  return home;
}

test("end-to-end (#230): config file only, no ALLW_* env → the hook gates; approval = no decision", async (t) => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  const { fetchImpl } = relayDouble(wasm, approver, "approved");
  withConfigHome(t, {
    version: 1,
    relay_url: "https://relay.allw.test",
    account_id: ACCOUNT_ID,
    approver_root_key: approver.accountRootPub,
  });

  const output = await runHook(
    bashStdin("rm -rf build", "/workspace/project"),
    {}, // no ALLW_* env at all: every coordinate comes from ~/.allw/config.json
    overrides(fetchImpl),
  );

  assert.equal(
    output,
    null,
    "a verified approval, with the coordinates read from the config file, makes no decision (#247)",
  );
});

test("end-to-end (#230, fail-closed): config file only, denied verdict → deny", async (t) => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  const { fetchImpl } = relayDouble(wasm, approver, "denied");
  withConfigHome(t, {
    version: 1,
    relay_url: "https://relay.allw.test",
    account_id: ACCOUNT_ID,
    approver_root_key: approver.accountRootPub,
  });

  const output = await runHook(bashStdin("rm -rf build", "/w"), {}, overrides(fetchImpl));
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
});

test("end-to-end (#230, fail-closed): neither config file nor env → deny naming both ways to configure", async (t) => {
  const home = withConfigHome(t, undefined);
  let dialed = false;
  const fetchImpl = () => {
    dialed = true;
    return Promise.reject(new Error("should not be called"));
  };

  const output = await runHook(bashStdin("rm -rf build", "/w"), {}, { fetchImpl });

  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  const reason = output.hookSpecificOutput.permissionDecisionReason;
  assert.ok(reason.includes(join(home, ".allw", "config.json")), `names the file: ${reason}`);
  assert.match(reason, /ALLW_RELAY_URL/);
  assert.match(reason, /ALLW_ACCOUNT_ID/);
  assert.match(reason, /ALLW_APPROVER_ROOT_KEY/);
  assert.equal(dialed, false, "missing config fails closed before any relay dial");
});

test("end-to-end: a non-gated tool (Read) yields no decision without dialing the relay", async () => {
  let dialed = false;
  const fetchImpl = () => {
    dialed = true;
    return Promise.reject(new Error("should not be called"));
  };
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);

  const stdin = JSON.stringify({
    hook_event_name: "PreToolUse",
    tool_name: "Read",
    tool_input: { file_path: "/etc/hosts" },
    cwd: "/w",
  });

  const output = await runHook(stdin, env(approver, TIMEOUT_MS), { fetchImpl });
  assert.equal(output, null);
  assert.equal(dialed, false, "a non-gated tool never contacts the relay");
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
  test(`end-to-end (fail-closed, #311): a forged verdict (${name}) is denied`, async () => {
    const wasm = await loadWasm();
    const approver = await pairedApprover(wasm);
    const { fetchImpl } = relayDouble(wasm, approver, "denied", (verdict) => ({
      ...verdict,
      decision: outer,
      [field]: "verified human decision was not 'approved'",
    }));

    const output = await runHook(
      bashStdin("rm -rf build", "/workspace/project"),
      env(approver, TIMEOUT_MS),
      overrides(fetchImpl),
    );

    assert.equal(
      output.hookSpecificOutput.permissionDecision,
      "deny",
      "a relay-forged verdict never opens the gate",
    );
    // Unverifiable ⇒ synthesized `denied`, never the forged `aborted`/`expired` as verified.
    assert.match(output.hookSpecificOutput.permissionDecisionReason, /\(verdict: denied\)$/);
  });
}
