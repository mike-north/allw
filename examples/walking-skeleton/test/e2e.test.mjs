/**
 * CI-runnable end-to-end test for the v0 walking skeleton (epic #42).
 *
 * This wires the **real** surfaces together in one Node process and exercises the full crypto
 * round-trip with NO verdict stubbing:
 *
 *   real `@allw/hook` runHook  →  real `@allw/sdk` requestApproval  →  in-process relay  →
 *   real `@allw/approver` core (decrypt → recompute request_hash → sign_verdict)  →  back to the
 *   SDK, which verifies the signed verdict against the account-root key before returning it, and
 *   the hook maps the verified verdict to allow/deny.
 *
 * The only stand-in is the relay transport: the real relay runs under workerd while the SDK and
 * approver run under node, so a single-process `node --test` cannot host both runtimes and dial
 * real sockets between them. We therefore drive the real SDK/approver against an in-process relay
 * that mirrors the relay's observable contract exactly (`docs/contract.md` §Transport → Relay
 * routing API) and enforces the same zero-knowledge envelope-key allowlist. The genuinely-live
 * workerd stack (real `wrangler dev` + real hook bin + real approver process) is the
 * locally-automatable `pnpm run demo:e2e` script, and the relay's own zero-knowledge property is
 * independently proven by `@allw/relay`'s workers-pool suite. See the README "Decisions".
 *
 * # What this proves (epic #42 acceptance, items 1–4)
 * 1. A gated destructive command is intercepted by the hook (it builds the ActionRecord + escalates).
 * 2. The exact command + actor + risk + expiry reach the approver inside the encrypted context
 *    (asserted via the approver's recomputed WYSIWYS request_hash matching the SDK's).
 * 3. Approve → the hook emits `allow`; deny → `deny`; timeout → `deny`. Fail-closed both ways.
 * 4. The integrator independently re-verifies the signed verdict — request_id AND request_hash,
 *    no-swap — and the relay stored ONLY ciphertext + routing (zero-knowledge), never plaintext or
 *    a signing key.
 *
 * Deterministic: fixed clock (no `Date.now()` in fixtures), no real network, no WebSocket.
 *
 * @see ../../../docs/contract.md  (§Lifecycle, §Verification checklist, §Transport, §Invariants #6)
 * @see ../../../packages/hook/test/integration.test.mjs  (the hook's own real-crypto round-trip)
 * @see ../../../packages/relay/test/relay-routing.test.ts (the relay's zero-knowledge proof in workerd)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { createClient } from "@allw/sdk";
import { loadWasm } from "@allw/approver";
import { runHook } from "@allw/hook";

import { InProcessRelay } from "../dist/lib/in-process-relay.js";
import { attachAutoApprover } from "../dist/lib/approver-harness.js";
import { buildPairedApprover } from "../dist/lib/identity.js";

// ── Fixed, deterministic timeline (fixed-dates rule: never Date.now() in fixtures) ──────────────
const NOW_MS = 1_700_000_000_000;
const TIMEOUT_MS = 300_000;
const ACCOUNT_ID = "acct-walking-skeleton";
const DEVICE_ID = "dev-walking-skeleton";
const RELAY_URL = "https://relay.allw.test";
const DESTRUCTIVE_COMMAND = "git push --force origin main";
const PROJECT_CWD = "/workspace/project";

/** The fixed clock the whole round-trip shares (SDK deadline, approver expiry, verdict window). */
const now = () => NOW_MS;

/** Stand up a relay + paired approver + attached auto-decider, all on the shared fixed clock. */
async function harness(mode) {
  const wasm = await loadWasm();
  const identity = buildPairedApprover(wasm, {
    accountId: ACCOUNT_ID,
    deviceId: DEVICE_ID,
    relayUrl: RELAY_URL,
    issuedAt: NOW_MS - 1000,
    label: "walking-skeleton device",
  });

  const relay = new InProcessRelay({ now });
  relay.enrollDevice({
    device_id: DEVICE_ID,
    pubkey: identity.keyfile.device_encryption_pubkey,
    label: identity.keyfile.label ?? null,
    created_at: NOW_MS - 10_000,
  });

  const connection = relay.connectDevice();
  const { log } = attachAutoApprover(identity, connection, mode, now);

  return { wasm, identity, relay, log };
}

/** SDK transport overrides: the in-process relay's fetch, poll-only, fixed clock, immediate timers. */
function sdkOverrides(relay) {
  return {
    fetchImpl: relay.fetchImpl,
    nowImpl: now,
    webSocketFactory: undefined, // force the deterministic poll path (no real sockets)
    pollIntervalMs: 5,
    // Run scheduled callbacks on the macrotask queue so the poll/deadline race resolves promptly.
    scheduleImpl: (fn, ms) => {
      setTimeout(fn, Math.min(ms, 5));
    },
  };
}

/** A realistic PreToolUse stdin payload for a gated Bash command. */
function bashStdin(command, cwd) {
  return JSON.stringify({
    session_id: "sess-walking-skeleton",
    transcript_path: "/tmp/transcript.jsonl",
    cwd,
    permission_mode: "default",
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command },
  });
}

/** The hook's environment (relay URL + account + the approver's account-root trust anchor). */
function hookEnv(identity) {
  return {
    ALLW_RELAY_URL: RELAY_URL,
    ALLW_ACCOUNT_ID: ACCOUNT_ID,
    ALLW_APPROVER_ROOT_KEY: identity.keyfile.account_root_pubkey,
    ALLW_TIMEOUT_MS: String(TIMEOUT_MS),
  };
}

// ── Acceptance item 3: Approve → allow ──────────────────────────────────────────────────────────

test("approve: a gated destructive command → human approves → hook emits allow", async () => {
  const { identity, relay, log } = await harness("approved");

  const output = await runHook(
    bashStdin(DESTRUCTIVE_COMMAND, PROJECT_CWD),
    hookEnv(identity),
    sdkOverrides(relay),
  );

  assert.equal(output.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(
    output.hookSpecificOutput.permissionDecision,
    "allow",
    "a verified approved verdict gates the destructive command open",
  );
  // The approver saw and signed over exactly one request (WYSIWYS hash recorded).
  assert.equal(log.length, 1, "the approver handled exactly one escalated request");
  assert.equal(log[0].decision, "approved");
  assert.ok(log[0].requestHash.length > 0, "the approver recomputed a WYSIWYS request_hash");

  // Acceptance criterion #2 (WYSIWYS), asserted DIRECTLY: the plaintext the approver decrypted —
  // never seen by the relay — must be byte-for-byte the action that was sent. We read the rendered
  // command (argv / cwd / raw) out of the decrypted context, proving the human-shown content equals
  // exactly `git push --force origin main` in `/workspace/project` (not merely that *a* hash matched).
  const context = log[0].context;
  assert.ok(context, "the approver decrypted the human-shown context");
  const syntactic = context.action.syntactic;
  assert.deepEqual(
    syntactic.argv,
    ["git", "push", "--force", "origin", "main"],
    "the decrypted, human-shown argv is exactly the destructive command that was sent",
  );
  assert.equal(syntactic.cwd, PROJECT_CWD, "the decrypted, human-shown cwd matches what was sent");
  assert.equal(syntactic.raw, DESTRUCTIVE_COMMAND, "the rendered raw command line matches exactly");
});

// ── Acceptance item 3 (fail-closed): Deny → deny ─────────────────────────────────────────────────

test("deny (fail-closed): human denies → hook emits deny", async () => {
  const { identity, relay, log } = await harness("denied");

  const output = await runHook(
    bashStdin(DESTRUCTIVE_COMMAND, PROJECT_CWD),
    hookEnv(identity),
    sdkOverrides(relay),
  );

  assert.equal(
    output.hookSpecificOutput.permissionDecision,
    "deny",
    "a verified human 'no' keeps the command blocked (fail-closed)",
  );
  assert.equal(log[0].decision, "denied");
});

// ── Acceptance item 3 (fail-closed): Timeout → deny ──────────────────────────────────────────────

test("timeout (fail-closed): no human response by the deadline → hook emits deny", async () => {
  // The approver never answers; the SDK's fail-closed deadline elapses and resolves to `expired`,
  // which the hook maps to `deny`. Drive it with a near-zero timeout so the test does not wait.
  const { identity, relay, log } = await harness("timeout");

  // ~50ms is the one wall-clock dependency in the suite — short enough to stay fast, with enough
  // CI headroom that the deadline reliably elapses before assertion (less flake than a ~20ms margin).
  const env = { ...hookEnv(identity), ALLW_TIMEOUT_MS: "50" };
  // Use the real clock for the deadline race here (the request is created "now" and must expire);
  // the approver still refuses to answer, so the only terminal outcome is a fail-closed timeout.
  const output = await runHook(bashStdin(DESTRUCTIVE_COMMAND, PROJECT_CWD), env, {
    fetchImpl: relay.fetchImpl,
    webSocketFactory: undefined,
    pollIntervalMs: 5,
  });

  assert.equal(
    output.hookSpecificOutput.permissionDecision,
    "deny",
    "no response by the deadline fails closed to deny",
  );
  // The request reached the approver (it was pushed) but no verdict was sent.
  assert.equal(log.length, 1);
  assert.equal(log[0].decision, null, "the approver sent no verdict (it timed out)");
});

// ── Acceptance item 4: integrator independently re-verifies the signed verdict (no-swap) ─────────

test("integrator independently re-verifies the verdict: request_id AND request_hash (no-swap)", async () => {
  const { identity, relay } = await harness("approved");

  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: identity.keyfile.account_root_pubkey,
    ...sdkOverrides(relay),
  });

  const verdict = await client.requestApproval({
    action: {
      recordSchemaVersion: 1,
      surface: "command",
      syntactic: { argv: ["git", "push", "--force", "origin", "main"] },
      risk: "high",
    },
    summary: "force push to main",
    actor: { id: "machine:laptop", kind: "claude-code" },
    risk: "high",
    reversible: false,
    timeoutMs: TIMEOUT_MS,
  });

  assert.equal(verdict.decision, "approved", "the SDK resolved a verified approval");

  // The integrator independently re-runs full verification against the account-root key. This
  // re-checks the JWS signature, the bound request_id + request_hash (no-swap), the decision, and
  // the decided_at window — without trusting the SDK's own earlier check (contract §Verification).
  assert.equal(
    await verdict.verify(identity.keyfile.account_root_pubkey),
    true,
    "a correct verdict re-verifies against the genuine account-root key",
  );

  // No-swap / wrong-anchor: verification against a DIFFERENT account-root key must fail. This proves
  // the verdict is cryptographically bound to the approver's root, not merely shaped right.
  const wasm = await loadWasm();
  const otherRoot = wasm.ed25519_public_key(Buffer.alloc(32, 99).toString("base64url"));
  assert.equal(
    await verdict.verify(otherRoot),
    false,
    "the verdict does NOT verify against a different (attacker) root key",
  );
});

// ── Acceptance item 4: zero-knowledge — the relay stored ONLY ciphertext + routing ──────────────

test("zero-knowledge: the relay stores only the opaque ciphertext envelope + signed verdict", async () => {
  const { identity, relay } = await harness("approved");

  const client = createClient({
    relayUrl: RELAY_URL,
    accountId: ACCOUNT_ID,
    approverRootKey: identity.keyfile.account_root_pubkey,
    ...sdkOverrides(relay),
  });

  await client.requestApproval({
    action: {
      recordSchemaVersion: 1,
      surface: "command",
      syntactic: { argv: ["git", "push", "--force", "origin", "main"] },
      risk: "high",
    },
    summary: "force push to main",
    actor: { id: "machine:laptop", kind: "claude-code" },
    risk: "high",
    reversible: false,
    timeoutMs: TIMEOUT_MS,
  });

  // The SDK minted a UUIDv4 id; recover it from the relay's store.
  const [requestId] = relay.requestIds();
  assert.ok(requestId, "the relay stored exactly one request");

  const storedEnvelope = relay.storedEnvelope(requestId);
  assert.ok(storedEnvelope, "the relay stored the request envelope");

  // The envelope carries the opaque JWE ciphertext (contract.md §Messages).
  assert.equal(typeof storedEnvelope.context_ciphertext, "string");
  assert.ok(
    String(storedEnvelope.context_ciphertext).length > 0,
    "the relay holds the opaque context ciphertext",
  );

  // It carries NONE of the plaintext ApprovalContext fields — the same fields the relay's own
  // zero-knowledge test checks (packages/relay/test/relay-routing.test.ts).
  for (const plaintextField of [
    "action",
    "summary",
    "actor",
    "risk",
    "reversible",
    "constraints",
    "chain",
  ]) {
    assert.equal(
      storedEnvelope[plaintextField],
      undefined,
      `the relay must never store the plaintext '${plaintextField}' field`,
    );
  }
  // The exact human-shown command must not appear anywhere in the stored envelope JSON.
  assert.ok(
    !JSON.stringify(storedEnvelope).includes("git push"),
    "the destructive command never appears in the relay's stored envelope",
  );

  // The stored verdict is the opaque signed artifact; the relay holds no key that could forge it.
  const storedVerdict = relay.storedVerdict(requestId);
  assert.ok(storedVerdict, "the relay stored the signed verdict to route it back");
  assert.ok(
    typeof storedVerdict === "object" && storedVerdict !== null && "sig" in storedVerdict,
    "the stored verdict is a JWS-signed decision, not a relay-forgeable value",
  );
});
