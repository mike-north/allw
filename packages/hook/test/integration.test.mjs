/**
 * Integration test for the Claude Code PreToolUse hook (issue #13): feed a realistic stdin payload
 * to the hook entrypoint (`runHook`) with the **real `@allw/sdk` client** pointed at a **relay
 * double**, and assert the emitted hook decision.
 *
 * This exercises the full crypto round-trip end-to-end through the WASM core — there is NO verdict
 * stubbing. The relay double plays the approver's role with software-held keys (mirroring
 * `@allw/approver`): it serves the root-signed account state that names the device, captures the submitted ciphertext envelope,
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
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runHook } from "../dist/cli.js";
import { loadWasm } from "../dist/lib/wasm.js";

// The hook keeps a per-account sequence floor under ~/.allw/state: point HOME at a throwaway dir
// for this whole file so a real ~/.allw is never read or written (tests that need their own HOME
// override it again with `withConfigHome`).
process.env.HOME = mkdtempSync(join(tmpdir(), "allw-hook-integration-home-"));
process.env.USERPROFILE = process.env.HOME;

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

/** Root-sign an account state at `sequence` that vouches for the approver's one device. */
function accountState(wasm, approver, sequence = 1) {
  return wasm.sign_account_state(
    JSON.stringify({
      v: 1,
      account_id: ACCOUNT_ID,
      sequence,
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

/** A 16-byte high-entropy nonce (fixed for determinism; entropy is irrelevant in a single-shot test). */
function nonce() {
  return Buffer.alloc(16, 7).toString("base64url");
}

/**
 * Build a `fetchImpl` relay double. It serves `GET /:acct/account-states` (by default one
 * root-signed state naming the device; `options.accountStates` overrides it), accepts `POST /:acct/requests`
 * (capturing the envelope), and answers `GET /:acct/requests/:id` with a signed verdict of the
 * requested `decision`. The verdict is bound to the captured envelope + the decrypted context, so
 * the SDK's verification (against `approverRootPub`) genuinely passes/round-trips.
 *
 * `forge` lets a test play a hostile relay: it rewrites the signed verdict before delivery.
 */
function relayDouble(wasm, approver, decision, forge = (verdict) => verdict, options = {}) {
  const accountStates = options.accountStates ?? [accountState(wasm, approver)];
  const state = { submitted: 0 };
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

    // GET /:acct/account-states — the root-signed states that decide who may read the request.
    if (url.endsWith("/account-states") && method === "GET") {
      if (options.accountStatesStatus !== undefined) {
        return new Response(JSON.stringify({ error: "authorization required" }), {
          status: options.accountStatesStatus,
        });
      }
      return json({ account_states: accountStates, max_sequence: accountStates.length });
    }

    // POST /:acct/requests — capture the opaque envelope and issue the relay-scoped poll token.
    if (url.endsWith("/requests") && method === "POST") {
      captured = JSON.parse(String(init?.body));
      state.submitted += 1;
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

  return { fetchImpl, state };
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

// ── Root-vouched recipients and the sequence floor (#243) ───────────────────────────────────────

test("end-to-end (#243): the selected account-state sequence is recorded under ~/.allw/state", async (t) => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  const home = withConfigHome(t);
  const { fetchImpl } = relayDouble(wasm, approver, "approved", undefined, {
    accountStates: [accountState(wasm, approver, 1), accountState(wasm, approver, 2)],
  });

  const output = await runHook(
    bashStdin("rm -rf build", "/w"),
    env(approver, TIMEOUT_MS),
    overrides(fetchImpl),
  );
  assert.equal(output, null);
  const floorFile = join(home, ".allw", "state", `${ACCOUNT_ID}.floor.json`);
  assert.deepEqual(JSON.parse(readFileSync(floorFile, "utf8")), {
    v: 1,
    account_id: ACCOUNT_ID,
    sequence: 2,
  });
});

test("end-to-end (#243, fail-closed): a relay that rolls back below the floor → deny, nothing sent", async (t) => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  withConfigHome(t);
  const first = relayDouble(wasm, approver, "approved", undefined, {
    accountStates: [accountState(wasm, approver, 3)],
  });
  assert.equal(
    await runHook(bashStdin("ls", "/w"), env(approver, TIMEOUT_MS), overrides(first.fetchImpl)),
    null,
  );

  // A later run sees only an older state (one that might still list a since-revoked device).
  const rolledBack = relayDouble(wasm, approver, "approved", undefined, {
    accountStates: [accountState(wasm, approver, 2)],
  });
  const output = await runHook(
    bashStdin("rm -rf build", "/w"),
    env(approver, TIMEOUT_MS),
    overrides(rolledBack.fetchImpl),
  );
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /sequence floor|below/i);
  assert.equal(rolledBack.state.submitted, 0, "the request is never sent");
});

// Regression: against a relay deployed before account-state GET became unauthenticated, the hook
// must still deny, and the reason must tell the operator to redeploy the relay.
test("end-to-end (#243, fail-closed): a relay too old for account-state GET (401) → deny saying redeploy", async (t) => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  withConfigHome(t);
  const relay = relayDouble(wasm, approver, "approved", undefined, { accountStatesStatus: 401 });

  const output = await runHook(
    bashStdin("rm -rf build", "/w"),
    env(approver, TIMEOUT_MS),
    overrides(relay.fetchImpl),
  );
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(
    output.hookSpecificOutput.permissionDecisionReason,
    /relay is too old .*; redeploy it from current allw main, see docs\/relay-deploy\.md$/,
    "the whole fix survives the deny-reason length cap",
  );
  assert.equal(relay.state.submitted, 0);
});

test("end-to-end (#243, fail-closed): no published account state → deny naming allw-approver pair", async (t) => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  const home = withConfigHome(t);
  const relay = relayDouble(wasm, approver, "approved", undefined, { accountStates: [] });

  const output = await runHook(
    bashStdin("rm -rf build", "/w"),
    env(approver, TIMEOUT_MS),
    overrides(relay.fetchImpl),
  );
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /allw-approver pair/);
  assert.equal(relay.state.submitted, 0);
  assert.equal(
    existsSync(join(home, ".allw", "state")),
    false,
    "no floor without a sealed request",
  );
});

/**
 * Pin the configured transport budget independently of the subprocess startup slack: a slower
 * fetch timeout must not hide inside that generous process bound. A pending fetch ignores abort,
 * so only the SDK's scheduled timeout can settle this run; microtasks avoid wall-clock waiting.
 *
 * @see ../../../docs/claude-code-integration.md (ALLW_FETCH_TIMEOUT_MS and timeout ordering)
 * @see ../../../docs/contract.md §Invariants #7 (timeout/no-response must deny)
 */
test("end-to-end (#388): the configured 100 ms fetch budget schedules a fail-closed deny", async () => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  const scheduled = [];

  const output = await runHook(
    bashStdin("rm -rf build", "/workspace/project"),
    { ...env(approver, 1000), ALLW_FETCH_TIMEOUT_MS: "100" },
    {
      ...overrides(() => new Promise(() => {})),
      scheduleImpl: (fn, ms) => {
        scheduled.push(ms);
        queueMicrotask(fn);
      },
    },
  );

  assert.deepEqual(scheduled, [100], "the env-configured fetch budget must reach the scheduler");
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  // Account state loads before submission; its transport timeout must deny just as a submit timeout does.
  assert.match(
    output.hookSpecificOutput.permissionDecisionReason,
    /loading account state failed: .*timed out after 100ms \(fail-closed\)/,
  );
});

/**
 * Account-state loading and submission use separate transports. A resolved state GET must not
 * hide a missing submit budget: the hung POST must expire under the same configured timeout.
 * @see ../../../docs/claude-code-integration.md (ALLW_FETCH_TIMEOUT_MS)
 * @see ../../../docs/contract.md §Invariants #7 (timeout must deny)
 */
test("end-to-end (#388): the configured 100 ms fetch budget also bounds submit after account state loads", async (t) => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  withConfigHome(t);
  const relay = relayDouble(wasm, approver, "approved", undefined, {
    accountStates: [accountState(wasm, approver)],
  });
  const scheduled = [];
  const calls = [];
  const output = await runHook(
    bashStdin("rm -rf build", "/workspace/project"),
    { ...env(approver, 1000), ALLW_FETCH_TIMEOUT_MS: "100" },
    {
      ...overrides((input, init) => {
        const url = typeof input === "string" ? input : input.url;
        const method = init?.method ?? "GET";
        calls.push(`${method} ${new URL(url).pathname}`);
        if (url.endsWith("/requests") && method === "POST") return new Promise(() => {});
        return relay.fetchImpl(input, init);
      }),
      scheduleImpl: (fn, ms) => {
        scheduled.push(ms);
        // The GET resolves normally; only the hung submit's timeout should fire.
        if (scheduled.length === 2) queueMicrotask(fn);
      },
    },
  );
  assert.deepEqual(calls, [`GET /${ACCOUNT_ID}/account-states`, `POST /${ACCOUNT_ID}/requests`]);
  assert.deepEqual(scheduled, [100, 100], "the configured budget reaches both fetch transports");
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /\(verdict: expired\)$/);
});

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
