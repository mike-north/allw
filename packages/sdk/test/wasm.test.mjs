/**
 * Cross-platform parity test for the WASM bindings (issue #9): the same shared vector that the
 * Rust core asserts against (`crates/allw-core/tests/fixtures/wasm_vector.json`, guarded by
 * `crates/allw-core/tests/wasm_vector.rs`) is fed through the compiled `.wasm` here. This proves
 * Rust ↔ WASM parity for `request-hash/v2` and that `verify_verdict` accepts the known-good verdict
 * and rejects a tampered one (fail-closed surfaces as a thrown error).
 *
 * Run order (the wasm must be built first):
 *   pnpm run build:wasm          # from repo root — wasm-pack build (--target web)
 *   pnpm --filter @allw/sdk test # node --test
 *
 * The `--target web` glue is loaded synchronously by compiling the `.wasm` bytes into a
 * `WebAssembly.Module` and calling `initSync` — one ESM artifact works in both node and the
 * browser/worker (docs/architecture.md: the same wasm is browser-capable).
 *
 * @see crates/allw-core/tests/fixtures/wasm_vector.json (the shared vector)
 * @see crates/allw-core/src/hash.rs (FROZEN_HASH_HEX — the request-hash/v2 anchor)
 * @see docs/contract.md §Wire encoding, §Verification checklist
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import {
  evaluatePolicyWithAccountStates,
  signAccountState,
  verifyAccountState,
  verifyPolicyRuleWithAccountStates,
  verifyVerdictWithAccountStates,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vendorDir = join(here, "..", "vendor", "allw-wasm");

/** Loads the `--target web` wasm module synchronously from on-disk bytes (node-friendly). */
async function loadWasm() {
  // Convert the filesystem path to a file:// URL — a bare path string is not a valid ESM
  // specifier on Windows (`C:\...`), so dynamic import must use a URL for cross-platform parity.
  const glue = await import(pathToFileURL(join(vendorDir, "allw_wasm.js")).href);
  const bytes = readFileSync(join(vendorDir, "allw_wasm_bg.wasm"));
  const module = new WebAssembly.Module(bytes);
  glue.initSync({ module });
  return glue;
}

/** The shared cross-platform vector (generated + guarded by the Rust side). */
function loadVector() {
  const raw = readFileSync(
    join(here, "..", "..", "..", "crates", "allw-core", "tests", "fixtures", "wasm_vector.json"),
    "utf8",
  );
  return JSON.parse(raw);
}

test("compute_request_hash reproduces the Rust request-hash/v2 vector", async () => {
  const wasm = await loadWasm();
  const v = loadVector();

  const got = wasm.compute_request_hash(v.context_json, v.expires_at);

  // (a) WASM output equals the fixture's expected base64url hash...
  assert.equal(
    got,
    v.expected_request_hash_b64,
    "WASM compute_request_hash must equal the shared vector's base64url hash",
  );

  // ...and decodes to the frozen hex (Rust ↔ WASM parity, request-hash/v2).
  const hex = Buffer.from(got.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("hex");
  assert.equal(hex, v.expected_request_hash_hex, "decoded hash must equal the frozen hex vector");
});

test("derive_number_match_challenge reproduces the Rust number-match vector", async () => {
  const wasm = await loadWasm();
  const zeroHash = Buffer.alloc(32, 0).toString("base64url");

  assert.equal(
    wasm.derive_number_match_challenge(zeroHash),
    "8729",
    "WASM number-match derivation must match the core's pinned vector",
  );
  assert.throws(
    () => wasm.derive_number_match_challenge("not-a-32-byte-hash"),
    /request_hash_b64/,
    "malformed request hash input must throw at the WASM boundary",
  );
});

test("verify_verdict accepts the known-good signed verdict", async () => {
  const wasm = await loadWasm();
  const v = loadVector();

  const resultJson = wasm.verify_verdict(
    v.verdict_json,
    v.request_json,
    v.context_json,
    v.approver_root_pubkey_b64,
    v.now_ms,
  );
  const result = JSON.parse(resultJson);

  assert.equal(result.approved, true, "the known-good verdict must verify as approved");
  assert.equal(result.device_id, "dev_wasm_vector_01", "device_id comes from the verified verdict");
  assert.equal(result.decided_at, 1700001000000, "decided_at echoes the signed claim");
});

test("verify_verdict rejects a verdict whose decision was flipped to denied", async () => {
  const wasm = await loadWasm();
  const v = loadVector();

  // Tamper the OUTER decision so it no longer matches the signed claim (still "approved").
  // The core detects the outer↔claim divergence (ClaimsMismatch) and throws — fail-closed.
  const tampered = JSON.parse(v.verdict_json);
  tampered.decision = "denied";
  const tamperedJson = JSON.stringify(tampered);

  assert.throws(
    () =>
      wasm.verify_verdict(
        tamperedJson,
        v.request_json,
        v.context_json,
        v.approver_root_pubkey_b64,
        v.now_ms,
      ),
    /verify_verdict failed/,
    "a tampered verdict must throw, not return a falsy result",
  );
});

test("verify_verdict rejects a verdict whose request_hash was mutated", async () => {
  const wasm = await loadWasm();
  const v = loadVector();

  // Replace the request_hash with a different (valid-length) base64url 32-byte value. Both the
  // outer field and the signed claim now disagree with each other / the request → reject.
  const tampered = JSON.parse(v.verdict_json);
  tampered.request_hash = Buffer.alloc(32, 0xcd).toString("base64url");
  const tamperedJson = JSON.stringify(tampered);

  assert.throws(
    () =>
      wasm.verify_verdict(
        tamperedJson,
        v.request_json,
        v.context_json,
        v.approver_root_pubkey_b64,
        v.now_ms,
      ),
    /verify_verdict failed/,
    "a mutated request_hash must break the WYSIWYS binding and throw",
  );
});

test("compute_request_hash throws on invalid context JSON", async () => {
  const wasm = await loadWasm();
  assert.throws(
    () => wasm.compute_request_hash("not json", 1700003600000),
    /invalid ApprovalContext JSON/,
    "malformed context JSON must surface as a thrown JS error",
  );
});

// ── signing surface (issue #41 unblock): derive keys → cert → sign → verify ───────────

/**
 * Build a self-contained approver: an account-root key, a device key it certifies, and a verdict
 * the device signs — all through the WASM surface. Reuses the shared vector's request/context so
 * the recomputed `request_hash` and the verify window line up with a known-good pair.
 */
function approverFixture(wasm) {
  const v = loadVector();
  const accountSeed = Buffer.alloc(32, 7).toString("base64url");
  const deviceSeed = Buffer.alloc(32, 9).toString("base64url");
  const accountRootPub = wasm.ed25519_public_key(accountSeed);
  const devicePub = wasm.ed25519_public_key(deviceSeed);

  const request = JSON.parse(v.request_json);
  const requestHash = wasm.compute_request_hash(v.context_json, request.expires_at);
  // Reuse the vector's decided_at/now_ms — a pair already known to be inside the verify window.
  const decidedAt = JSON.parse(v.verdict_json).decided_at;

  const cert = wasm.issue_device_cert(accountSeed, "acct_rt", "dev_rt", devicePub, 1700000000000);

  const unsigned = {
    v: 1,
    request_id: request.id,
    request_hash: requestHash,
    decision: "approved",
    decided_at: decidedAt,
    approver: { account_id: "acct_rt", device_id: "dev_rt" },
  };
  const nonce = Buffer.alloc(16, 3).toString("base64url");
  return { v, accountSeed, deviceSeed, accountRootPub, devicePub, cert, unsigned, nonce, request };
}

/** Policy rules are verified by chaining the rule's device cert to this account root. */
function policyFixture(wasm) {
  const accountSeed = Buffer.alloc(32, 0x07).toString("base64url");
  const deviceSeed = Buffer.alloc(32, 0x42).toString("base64url");
  const accountRootPub = wasm.ed25519_public_key(accountSeed);
  const devicePub = wasm.ed25519_public_key(deviceSeed);
  const accountId = "acct_policy";
  const deviceId = "device:phone";
  const createdAt = 1700000000000;
  const nowMs = createdAt + 1000;
  const cert = wasm.issue_device_cert(accountSeed, accountId, deviceId, devicePub, createdAt);
  return { accountId, deviceId, accountSeed, deviceSeed, accountRootPub, cert, createdAt, nowMs };
}

function signedAccountState(
  wasm,
  {
    accountSeed,
    accountId,
    currentRoot,
    sequence,
    revokedDeviceIds = [],
    revokedAt = 1700002000000,
  },
) {
  return wasm.sign_account_state(
    JSON.stringify({
      v: 1,
      account_id: accountId,
      sequence,
      current_root: currentRoot,
      previous_roots: [],
      devices: [],
      actors: [],
      revocations: revokedDeviceIds.map((id) => ({
        kind: "device",
        id,
        revoked_at: revokedAt,
        reason: "test revocation",
      })),
    }),
    accountSeed,
  );
}

test("WASM signing boundaries reject empty device_cert strings", async () => {
  const wasm = await loadWasm();
  const verdictFixture = approverFixture(wasm);
  const policy = policyFixture(wasm);
  const actor = { id: "machine:macbook", kind: "claude-code" };
  const actionJson = wasm.action_from_command("git status", null);
  const unsignedRule = {
    id: "allow-status",
    account_id: policy.accountId,
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "git", args_any_globs: ["status"] } },
    effect: "allow",
    provenance: "manual",
    tier: "syntactic",
    created_at: policy.createdAt,
  };

  assert.throws(
    () =>
      wasm.sign_verdict(
        JSON.stringify(verdictFixture.unsigned),
        verdictFixture.deviceSeed,
        verdictFixture.nonce,
        "",
      ),
    /device_cert must not be empty/,
    "verdict signing must reject an empty certificate instead of silently producing an unverifiable verdict",
  );

  assert.throws(
    () =>
      wasm.sign_policy_rule(JSON.stringify(unsignedRule), policy.deviceId, policy.deviceSeed, ""),
    /device_cert must not be empty/,
    "manual policy signing must reject an empty certificate instead of silently producing an unverifiable rule",
  );

  assert.throws(
    () =>
      wasm.policy_rule_from_approval(
        "approval-empty-cert",
        policy.accountId,
        JSON.stringify(actor),
        actionJson,
        JSON.stringify({ kind: "exact_call" }),
        policy.createdAt,
        policy.deviceId,
        policy.deviceSeed,
        "",
      ),
    /device_cert must not be empty/,
    "approval-derived policy signing must reject an empty certificate at the signing boundary",
  );
});

function unsignedAccountState({
  accountId,
  currentRoot,
  sequence,
  revokedDeviceIds = [],
  revokedAt = 1700002000000,
}) {
  return {
    v: 1,
    account_id: accountId,
    sequence,
    current_root: currentRoot,
    previous_roots: [],
    devices: [],
    actors: [],
    revocations: revokedDeviceIds.map((id) => ({
      kind: "device",
      id,
      revoked_at: revokedAt,
      reason: "test revocation",
    })),
  };
}

test("ed25519/x25519 public-key derivation returns 43-char base64url keys", async () => {
  const wasm = await loadWasm();
  const seed = Buffer.alloc(32, 1).toString("base64url");
  const ed = wasm.ed25519_public_key(seed);
  const x = wasm.x25519_public_key(seed);
  // 32 bytes → 43 base64url-unpadded chars; deterministic from the seed.
  assert.equal(ed.length, 43, "Ed25519 pubkey is 43 base64url chars");
  assert.equal(x.length, 43, "X25519 pubkey is 43 base64url chars");
  assert.equal(wasm.ed25519_public_key(seed), ed, "derivation is deterministic");
  assert.notEqual(ed, x, "Ed25519 and X25519 keys differ for the same seed");
});

test("policy_rule_from_approval signs an exact-call rule evaluate_policy can auto-allow", async () => {
  const wasm = await loadWasm();
  const f = policyFixture(wasm);
  const actor = { id: "machine:macbook", kind: "claude-code" };
  const actionJson = wasm.action_from_command("git push --force origin main", null);

  const ruleJson = wasm.policy_rule_from_approval(
    "approval-exact",
    f.accountId,
    JSON.stringify(actor),
    actionJson,
    JSON.stringify({ kind: "exact_call" }),
    f.createdAt,
    f.deviceId,
    f.deviceSeed,
    f.cert,
  );
  const rule = JSON.parse(ruleJson);
  assert.equal(rule.provenance, "from_approval", "approval-derived rules carry provenance");
  assert.equal(rule.effect, "allow", "approval-derived rules are allow rules");
  assert.match(rule.sig, /^[^.]+\.[^.]+\.[^.]+$/, "policy rule is signed as compact JWS");

  const allowed = JSON.parse(
    wasm.evaluate_policy(
      actionJson,
      JSON.stringify(actor),
      JSON.stringify([rule]),
      f.accountRootPub,
      f.nowMs,
    ),
  );
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.rule_id, "approval-exact");

  const changedActionJson = wasm.action_from_command(
    "git push --force-with-lease origin main",
    null,
  );
  const escalated = JSON.parse(
    wasm.evaluate_policy(
      changedActionJson,
      JSON.stringify(actor),
      JSON.stringify([rule]),
      f.accountRootPub,
      f.nowMs,
    ),
  );
  assert.equal(escalated.decision, "escalate", "exact-call rules must not become scoped verdicts");
});

test("policy_rule_from_approval keeps raw-only exact command rules narrow", async () => {
  const wasm = await loadWasm();
  const f = policyFixture(wasm);
  const actor = { id: "machine:macbook", kind: "claude-code" };
  const action = {
    record_schema_version: 1,
    surface: "command",
    syntactic: { raw: "git push --force origin main" },
    risk: "high",
  };

  const rule = JSON.parse(
    wasm.policy_rule_from_approval(
      "approval-raw-exact",
      f.accountId,
      JSON.stringify(actor),
      JSON.stringify(action),
      JSON.stringify({ kind: "exact_call" }),
      f.createdAt,
      f.deviceId,
      f.deviceSeed,
      f.cert,
    ),
  );
  assert.equal(
    rule.match.command.raw_exact,
    action.syntactic.raw,
    "raw-only exact rules bind to the exact raw command text",
  );

  const allowed = JSON.parse(
    wasm.evaluate_policy(
      JSON.stringify(action),
      JSON.stringify(actor),
      JSON.stringify([rule]),
      f.accountRootPub,
      f.nowMs,
    ),
  );
  assert.equal(allowed.decision, "allow");

  const changedAction = {
    ...action,
    syntactic: { raw: "git push --force-with-lease origin main" },
  };
  const escalated = JSON.parse(
    wasm.evaluate_policy(
      JSON.stringify(changedAction),
      JSON.stringify(actor),
      JSON.stringify([rule]),
      f.accountRootPub,
      f.nowMs,
    ),
  );
  assert.equal(escalated.decision, "escalate", "changed raw command text must not match");
});

test("policy_rule_from_approval rejects bin-only exact command rules", async () => {
  const wasm = await loadWasm();
  const f = policyFixture(wasm);
  const actor = { id: "machine:macbook", kind: "claude-code" };
  const action = {
    record_schema_version: 1,
    surface: "command",
    syntactic: { bin: "git" },
    risk: "high",
  };

  assert.throws(
    () =>
      wasm.policy_rule_from_approval(
        "approval-bin-only",
        f.accountId,
        JSON.stringify(actor),
        JSON.stringify(action),
        JSON.stringify({ kind: "exact_call" }),
        f.createdAt,
        f.deviceId,
        f.deviceSeed,
        f.cert,
      ),
    /exact command policy requires either argv or raw command text/,
    "bin-only commands are too broad for exact-call policy emission",
  );
});

test("evaluate_policy verifies signed rules and applies deny over ask over allow", async () => {
  const wasm = await loadWasm();
  const f = policyFixture(wasm);
  const actor = { id: "machine:macbook", kind: "claude-code" };
  const actionJson = wasm.action_from_command("git push --force origin main", null);

  const unsignedAllow = {
    id: "allow-git",
    account_id: f.accountId,
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "git" } },
    effect: "allow",
    provenance: "manual",
    tier: "syntactic",
    created_at: 1700000000000,
  };
  const unsignedAsk = {
    id: "ask-force",
    account_id: f.accountId,
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "git", args_any_globs: ["*force*"] } },
    effect: "ask",
    provenance: "manual",
    tier: "syntactic",
    created_at: 1700000000000,
  };
  const unsignedDeny = {
    id: "deny-force",
    account_id: f.accountId,
    subject: { kind: "id", id: actor.id },
    match: { surface: "command", command: { bin: "git", args_any_globs: ["*force*"] } },
    effect: "deny",
    provenance: "manual",
    tier: "syntactic",
    created_at: 1700000000000,
  };

  const allow = JSON.parse(
    wasm.sign_policy_rule(JSON.stringify(unsignedAllow), f.deviceId, f.deviceSeed, f.cert),
  );
  const ask = JSON.parse(
    wasm.sign_policy_rule(JSON.stringify(unsignedAsk), f.deviceId, f.deviceSeed, f.cert),
  );
  const deny = JSON.parse(
    wasm.sign_policy_rule(JSON.stringify(unsignedDeny), f.deviceId, f.deviceSeed, f.cert),
  );

  const askWins = JSON.parse(
    wasm.evaluate_policy(
      actionJson,
      JSON.stringify(actor),
      JSON.stringify([allow, ask]),
      f.accountRootPub,
      f.nowMs,
    ),
  );
  assert.equal(askWins.decision, "escalate");
  assert.equal(askWins.rule_id, "ask-force");

  const denyWins = JSON.parse(
    wasm.evaluate_policy(
      actionJson,
      JSON.stringify(actor),
      JSON.stringify([allow, ask, deny]),
      f.accountRootPub,
      f.nowMs,
    ),
  );
  assert.equal(denyWins.decision, "deny");
  assert.equal(denyWins.rule_id, "deny-force");

  const tampered = { ...deny, effect: "allow" };
  assert.throws(
    () =>
      wasm.evaluate_policy(
        actionJson,
        JSON.stringify(actor),
        JSON.stringify([tampered]),
        f.accountRootPub,
        f.nowMs,
      ),
    /verify_policy_rule failed/,
    "policy evaluation must fail closed on a tampered signed rule",
  );
});

test("evaluate_policy rejects policy rules with unenforced expiry or bounds", async () => {
  const wasm = await loadWasm();
  const f = policyFixture(wasm);
  const actor = { id: "machine:macbook", kind: "claude-code" };
  const actionJson = wasm.action_from_command("git push --force origin main", null);
  const unsigned = {
    id: "allow-expiring-git",
    account_id: f.accountId,
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "git" } },
    effect: "allow",
    provenance: "manual",
    tier: "syntactic",
    created_at: 1700000000000,
    expires_at: 1700000600000,
  };
  const rule = JSON.parse(
    wasm.sign_policy_rule(JSON.stringify(unsigned), f.deviceId, f.deviceSeed, f.cert),
  );

  assert.throws(
    () =>
      wasm.evaluate_policy(
        actionJson,
        JSON.stringify(actor),
        JSON.stringify([rule]),
        f.accountRootPub,
        f.nowMs,
      ),
    /expires_at\/bounds are unsupported/,
    "time-boxed policy rules must fail closed until evaluate can enforce time",
  );
});

test("evaluate_policy rejects empty predicates and token-anchors args_any_globs", async () => {
  const wasm = await loadWasm();
  const f = policyFixture(wasm);
  const actor = { id: "machine:macbook", kind: "claude-code" };

  const emptyPredicate = {
    id: "empty-predicate",
    account_id: f.accountId,
    subject: { kind: "any" },
    match: {},
    effect: "allow",
    provenance: "manual",
    tier: "syntactic",
    created_at: 1700000000000,
  };
  const signedEmpty = JSON.parse(
    wasm.sign_policy_rule(JSON.stringify(emptyPredicate), f.deviceId, f.deviceSeed, f.cert),
  );
  assert.throws(
    () =>
      wasm.evaluate_policy(
        wasm.action_from_command("git status", null),
        JSON.stringify(actor),
        JSON.stringify([signedEmpty]),
        f.accountRootPub,
        f.nowMs,
      ),
    /predicate must constrain the action/,
    "manual {} predicates must not become match-everything allow rules",
  );

  const tokenRule = {
    id: "allow-build-token",
    account_id: f.accountId,
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "rm", args_any_globs: ["build"] } },
    effect: "allow",
    provenance: "manual",
    tier: "syntactic",
    created_at: 1700000000000,
  };
  const signedTokenRule = JSON.parse(
    wasm.sign_policy_rule(JSON.stringify(tokenRule), f.deviceId, f.deviceSeed, f.cert),
  );
  const exactToken = JSON.parse(
    wasm.evaluate_policy(
      wasm.action_from_command("rm -rf build", null),
      JSON.stringify(actor),
      JSON.stringify([signedTokenRule]),
      f.accountRootPub,
      f.nowMs,
    ),
  );
  assert.equal(exactToken.decision, "allow");

  const prefixedToken = JSON.parse(
    wasm.evaluate_policy(
      wasm.action_from_command("rm -rf build-prod", null),
      JSON.stringify(actor),
      JSON.stringify([signedTokenRule]),
      f.accountRootPub,
      f.nowMs,
    ),
  );
  assert.equal(
    prefixedToken.decision,
    "escalate",
    "non-glob args_any_globs must not substring-match structured tokens",
  );

  const rawOnly = {
    record_schema_version: 1,
    surface: "command",
    syntactic: { bin: "rm", raw: "rm -rf build" },
    risk: "high",
  };
  const rawOnlyResult = JSON.parse(
    wasm.evaluate_policy(
      JSON.stringify(rawOnly),
      JSON.stringify(actor),
      JSON.stringify([signedTokenRule]),
      f.accountRootPub,
      f.nowMs,
    ),
  );
  assert.equal(
    rawOnlyResult.decision,
    "escalate",
    "args_any_globs must not match against raw shell text",
  );
});

test("verify_account_state accepts valid root-signed state and rejects wrong account/root", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);
  const valid = signedAccountState(wasm, {
    accountSeed: f.accountSeed,
    accountId: "acct_rt",
    currentRoot: f.accountRootPub,
    sequence: 3,
  });

  const verified = JSON.parse(wasm.verify_account_state(valid, "acct_rt", f.accountRootPub));
  assert.equal(verified.account_id, "acct_rt");
  assert.equal(verified.sequence, 3);

  assert.throws(
    () => wasm.verify_account_state(valid, "acct_other", f.accountRootPub),
    /account[- ]state/i,
    "account states for another account must be rejected",
  );

  const otherRootPub = wasm.ed25519_public_key(Buffer.alloc(32, 0x77).toString("base64url"));
  assert.throws(
    () => wasm.verify_account_state(valid, "acct_rt", otherRootPub),
    /account[- ]state/i,
    "account states signed for a different root must be rejected",
  );
});

test("sign_verdict + issue_device_cert produce a verdict verify_verdict accepts", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  const verdictJson = wasm.sign_verdict(JSON.stringify(f.unsigned), f.deviceSeed, f.nonce, f.cert);

  const result = JSON.parse(
    wasm.verify_verdict(
      verdictJson,
      f.v.request_json,
      f.v.context_json,
      f.accountRootPub,
      f.v.now_ms,
    ),
  );
  assert.equal(result.approved, true, "the freshly signed verdict must verify as approved");
  assert.equal(result.device_id, "dev_rt", "device_id comes from the verified verdict");
});

test("verify_verdict enforces optional expected account ids", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);
  const verdictJson = wasm.sign_verdict(JSON.stringify(f.unsigned), f.deviceSeed, f.nonce, f.cert);

  const result = JSON.parse(
    wasm.verify_verdict(
      verdictJson,
      f.v.request_json,
      f.v.context_json,
      f.accountRootPub,
      f.v.now_ms,
      f.accountId,
    ),
  );
  assert.equal(result.approved, true, "a matching expected account id must still verify");

  const emptyExpectedResult = JSON.parse(
    wasm.verify_verdict(
      verdictJson,
      f.v.request_json,
      f.v.context_json,
      f.accountRootPub,
      f.v.now_ms,
      "",
    ),
  );
  assert.equal(
    emptyExpectedResult.approved,
    true,
    "an empty expected account id is treated like no expected-account constraint",
  );

  const emptyExpectedWithStates = JSON.parse(
    wasm.verify_verdict_with_account_states(
      verdictJson,
      f.v.request_json,
      f.v.context_json,
      f.accountRootPub,
      f.v.now_ms,
      JSON.stringify([]),
      "",
    ),
  );
  assert.equal(
    emptyExpectedWithStates.approved,
    true,
    "account-state-aware verdict verification also treats empty expected account id as omitted",
  );

  assert.throws(
    () =>
      wasm.verify_verdict(
        verdictJson,
        f.v.request_json,
        f.v.context_json,
        f.accountRootPub,
        f.v.now_ms,
        "acct_wrong_namespace",
      ),
    /expected account_id/,
    "a wrong caller-supplied expected account id must fail closed",
  );
});

test("verify_verdict_with_account_states rejects revoked devices and stale rollback", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);
  const verdictJson = wasm.sign_verdict(JSON.stringify(f.unsigned), f.deviceSeed, f.nonce, f.cert);
  const staleWithoutRevocation = signedAccountState(wasm, {
    accountSeed: f.accountSeed,
    accountId: "acct_rt",
    currentRoot: f.accountRootPub,
    sequence: 4,
  });
  const newerRevocation = signedAccountState(wasm, {
    accountSeed: f.accountSeed,
    accountId: "acct_rt",
    currentRoot: f.accountRootPub,
    sequence: 5,
    revokedDeviceIds: ["dev_rt"],
  });

  assert.throws(
    () =>
      wasm.verify_verdict_with_account_states(
        verdictJson,
        f.v.request_json,
        f.v.context_json,
        f.accountRootPub,
        f.v.now_ms,
        JSON.stringify([newerRevocation]),
      ),
    /device id is revoked/,
    "a revoked signing device must not verify",
  );

  assert.throws(
    () =>
      wasm.verify_verdict_with_account_states(
        verdictJson,
        f.v.request_json,
        f.v.context_json,
        f.accountRootPub,
        f.v.now_ms,
        JSON.stringify([newerRevocation, staleWithoutRevocation]),
      ),
    /device id is revoked/,
    "a lower-sequence state must not roll back a newer revocation",
  );
});

// ── revoked_device_ids (issue #204 fix 1: sender-side recipient filtering) ──────────────

test("revoked_device_ids resolves highest-sequence revocations and ignores stale rollback", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);
  const staleWithoutRevocation = signedAccountState(wasm, {
    accountSeed: f.accountSeed,
    accountId: "acct_rt",
    currentRoot: f.accountRootPub,
    sequence: 4,
  });
  const newerRevocation = signedAccountState(wasm, {
    accountSeed: f.accountSeed,
    accountId: "acct_rt",
    currentRoot: f.accountRootPub,
    sequence: 5,
    revokedDeviceIds: ["dev_rt"],
  });

  const revokedAtHighest = JSON.parse(
    wasm.revoked_device_ids(JSON.stringify([newerRevocation]), "acct_rt", f.accountRootPub),
  );
  assert.deepEqual(revokedAtHighest, ["dev_rt"], "the highest-sequence revocation is resolved");

  const revokedWithStaleMixedIn = JSON.parse(
    wasm.revoked_device_ids(
      JSON.stringify([newerRevocation, staleWithoutRevocation]),
      "acct_rt",
      f.accountRootPub,
    ),
  );
  assert.deepEqual(
    revokedWithStaleMixedIn,
    ["dev_rt"],
    "a lower-sequence document that omits a revocation must not roll it back",
  );

  const noneRevoked = JSON.parse(
    wasm.revoked_device_ids(JSON.stringify([]), "acct_rt", f.accountRootPub),
  );
  assert.deepEqual(noneRevoked, [], "no account states supplied ⇒ no known revocations");
});

test("revoked_device_ids fails closed on a substituted wrong-root account state", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);
  const wrongRootSeed = Buffer.alloc(32, 0x79).toString("base64url");
  const wrongRootState = signedAccountState(wasm, {
    accountSeed: wrongRootSeed,
    accountId: "acct_rt",
    currentRoot: wasm.ed25519_public_key(wrongRootSeed),
    sequence: 6,
    revokedDeviceIds: ["dev_rt"],
  });

  assert.throws(
    () => wasm.revoked_device_ids(JSON.stringify([wrongRootState]), "acct_rt", f.accountRootPub),
    /revoked_device_ids failed/,
    "a substituted wrong-root account state must fail closed, not be silently ignored",
  );
});

test("verify_verdict_with_account_states rejects substituted wrong-root account state", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);
  const verdictJson = wasm.sign_verdict(JSON.stringify(f.unsigned), f.deviceSeed, f.nonce, f.cert);
  const wrongRootSeed = Buffer.alloc(32, 0x77).toString("base64url");
  const wrongRootState = signedAccountState(wasm, {
    accountSeed: wrongRootSeed,
    accountId: "acct_rt",
    currentRoot: wasm.ed25519_public_key(wrongRootSeed),
    sequence: 6,
    revokedDeviceIds: ["dev_rt"],
  });

  assert.throws(
    () =>
      wasm.verify_verdict_with_account_states(
        verdictJson,
        f.v.request_json,
        f.v.context_json,
        f.accountRootPub,
        f.v.now_ms,
        JSON.stringify([wrongRootState]),
      ),
    /account state is invalid/,
    "substituted wrong-root account state must fail closed, not be ignored",
  );
});

test("verify_policy_rule_with_account_states rejects revoked signing devices", async () => {
  const wasm = await loadWasm();
  const f = policyFixture(wasm);
  const unsigned = {
    id: "allow-status",
    account_id: f.accountId,
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "git", args_any_globs: ["status"] } },
    effect: "allow",
    provenance: "manual",
    tier: "syntactic",
    created_at: f.createdAt,
  };
  const signedRule = wasm.sign_policy_rule(
    JSON.stringify(unsigned),
    f.deviceId,
    f.deviceSeed,
    f.cert,
  );
  const revoked = signedAccountState(wasm, {
    accountSeed: f.accountSeed,
    accountId: f.accountId,
    currentRoot: f.accountRootPub,
    sequence: 2,
    revokedDeviceIds: [f.deviceId],
  });

  assert.throws(
    () =>
      wasm.verify_policy_rule_with_account_states(
        signedRule,
        f.accountRootPub,
        f.nowMs,
        JSON.stringify([revoked]),
      ),
    /policy-rule signing device is revoked/,
    "policy rules signed by revoked devices must be rejected",
  );

  assert.throws(
    () =>
      wasm.evaluate_policy_with_account_states(
        wasm.action_from_command("git status", null),
        JSON.stringify({ id: "machine:macbook", kind: "claude-code" }),
        JSON.stringify([JSON.parse(signedRule)]),
        f.accountRootPub,
        f.nowMs,
        JSON.stringify([revoked]),
      ),
    /policy-rule signing device is revoked/,
    "policy evaluation must fail closed when a signed rule's device is revoked",
  );
});

test("verify_policy_rule_with_account_states rejects substituted wrong-root account state", async () => {
  const wasm = await loadWasm();
  const f = policyFixture(wasm);
  const unsigned = {
    id: "allow-status-wrong-root-state",
    account_id: f.accountId,
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "git", args_any_globs: ["status"] } },
    effect: "allow",
    provenance: "manual",
    tier: "syntactic",
    created_at: f.createdAt,
  };
  const signedRule = wasm.sign_policy_rule(
    JSON.stringify(unsigned),
    f.deviceId,
    f.deviceSeed,
    f.cert,
  );
  const wrongRootSeed = Buffer.alloc(32, 0x78).toString("base64url");
  const wrongRootState = signedAccountState(wasm, {
    accountSeed: wrongRootSeed,
    accountId: f.accountId,
    currentRoot: wasm.ed25519_public_key(wrongRootSeed),
    sequence: 3,
    revokedDeviceIds: [f.deviceId],
  });

  assert.throws(
    () =>
      wasm.verify_policy_rule_with_account_states(
        signedRule,
        f.accountRootPub,
        f.nowMs,
        JSON.stringify([wrongRootState]),
      ),
    /account state is invalid/,
    "substituted wrong-root account state must fail closed, not be ignored",
  );
});

test("policy verification enforces optional expected account ids", async () => {
  const wasm = await loadWasm();
  const f = policyFixture(wasm);
  const unsigned = {
    id: "allow-status-expected-account",
    account_id: f.accountId,
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "git", args_any_globs: ["status"] } },
    effect: "allow",
    provenance: "manual",
    tier: "syntactic",
    created_at: f.createdAt,
  };
  const signedRule = wasm.sign_policy_rule(
    JSON.stringify(unsigned),
    f.deviceId,
    f.deviceSeed,
    f.cert,
  );
  const actionJson = wasm.action_from_command("git status", null);
  const actorJson = JSON.stringify({ id: "machine:macbook", kind: "claude-code" });

  const verified = JSON.parse(
    wasm.verify_policy_rule_with_account_states(
      signedRule,
      f.accountRootPub,
      f.nowMs,
      JSON.stringify([]),
      f.accountId,
    ),
  );
  assert.equal(verified.rule.account_id, f.accountId, "a matching expected account id must verify");

  const verifiedEmptyExpected = JSON.parse(
    wasm.verify_policy_rule_with_account_states(
      signedRule,
      f.accountRootPub,
      f.nowMs,
      JSON.stringify([]),
      "",
    ),
  );
  assert.equal(
    verifiedEmptyExpected.rule.account_id,
    f.accountId,
    "an empty expected account id is treated like no policy-rule account constraint",
  );

  const emptyExpectedEvaluation = JSON.parse(
    wasm.evaluate_policy(
      actionJson,
      actorJson,
      JSON.stringify([JSON.parse(signedRule)]),
      f.accountRootPub,
      f.nowMs,
      "",
    ),
  );
  assert.equal(
    emptyExpectedEvaluation.decision,
    "allow",
    "policy evaluation treats empty expected account id as omitted",
  );

  const emptyExpectedEvaluationWithStates = JSON.parse(
    wasm.evaluate_policy_with_account_states(
      actionJson,
      actorJson,
      JSON.stringify([JSON.parse(signedRule)]),
      f.accountRootPub,
      f.nowMs,
      JSON.stringify([]),
      "",
    ),
  );
  assert.equal(
    emptyExpectedEvaluationWithStates.decision,
    "allow",
    "account-state-aware policy evaluation treats empty expected account id as omitted",
  );

  assert.throws(
    () =>
      wasm.verify_policy_rule_with_account_states(
        signedRule,
        f.accountRootPub,
        f.nowMs,
        JSON.stringify([]),
        "acct_wrong_namespace",
      ),
    /expected account_id/,
    "a wrong expected account id must reject the policy rule",
  );

  assert.throws(
    () =>
      wasm.evaluate_policy(
        actionJson,
        actorJson,
        JSON.stringify([JSON.parse(signedRule)]),
        f.accountRootPub,
        f.nowMs,
        "acct_wrong_namespace",
      ),
    /expected account_id/,
    "policy evaluation must fail closed when a rule does not match the expected account id",
  );
});

test("@allw/sdk account-state helpers verify documents and reject revoked verdicts", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);
  const state = unsignedAccountState({
    accountId: "acct_rt",
    currentRoot: f.accountRootPub,
    sequence: 7,
  });
  const stateJws = await signAccountState(state, f.accountSeed);

  const verifiedState = await verifyAccountState(stateJws, "acct_rt", f.accountRootPub);
  assert.equal(verifiedState.account_id, "acct_rt");
  assert.equal(verifiedState.sequence, 7);

  const verdict = JSON.parse(
    wasm.sign_verdict(JSON.stringify(f.unsigned), f.deviceSeed, f.nonce, f.cert),
  );
  const request = JSON.parse(f.v.request_json);
  const context = JSON.parse(f.v.context_json);
  const verifiedVerdict = await verifyVerdictWithAccountStates({
    verdict,
    request,
    context,
    approverRootKey: f.accountRootPub,
    nowMs: f.v.now_ms,
    accountStates: [stateJws],
    expectedAccountId: "acct_rt",
  });
  assert.equal(verifiedVerdict.approved, true);
  assert.equal(verifiedVerdict.deviceId, "dev_rt");

  const emptyExpectedVerdict = await verifyVerdictWithAccountStates({
    verdict,
    request,
    context,
    approverRootKey: f.accountRootPub,
    nowMs: f.v.now_ms,
    accountStates: [stateJws],
    expectedAccountId: "",
  });
  assert.equal(
    emptyExpectedVerdict.approved,
    true,
    "SDK verdict helper treats empty expectedAccountId as omitted",
  );

  await assert.rejects(
    () =>
      verifyVerdictWithAccountStates({
        verdict,
        request,
        context,
        approverRootKey: f.accountRootPub,
        nowMs: f.v.now_ms,
        accountStates: [stateJws],
        expectedAccountId: "acct_wrong_namespace",
      }),
    /expected account_id/,
    "SDK verdict verification must reject a wrong expected account id",
  );

  const revokedStateJws = await signAccountState(
    unsignedAccountState({
      accountId: "acct_rt",
      currentRoot: f.accountRootPub,
      sequence: 8,
      revokedDeviceIds: ["dev_rt"],
    }),
    f.accountSeed,
  );
  await assert.rejects(
    () =>
      verifyVerdictWithAccountStates({
        verdict,
        request,
        context,
        approverRootKey: f.accountRootPub,
        nowMs: f.v.now_ms,
        accountStates: [revokedStateJws, stateJws],
      }),
    /device id is revoked/,
    "SDK verdict verification must enforce highest-sequence account-state revocation",
  );
});

test("@allw/sdk policy helpers reject rules from revoked devices", async () => {
  const wasm = await loadWasm();
  const f = policyFixture(wasm);
  const actor = { id: "machine:macbook", kind: "claude-code" };
  const action = JSON.parse(wasm.action_from_command("git status", null));
  const unsigned = {
    id: "allow-status-sdk",
    account_id: f.accountId,
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "git", args_any_globs: ["status"] } },
    effect: "allow",
    provenance: "manual",
    tier: "syntactic",
    created_at: f.createdAt,
  };
  const signedRule = JSON.parse(
    wasm.sign_policy_rule(JSON.stringify(unsigned), f.deviceId, f.deviceSeed, f.cert),
  );
  const activeState = await signAccountState(
    unsignedAccountState({
      accountId: f.accountId,
      currentRoot: f.accountRootPub,
      sequence: 1,
    }),
    f.accountSeed,
  );

  const verifiedRule = await verifyPolicyRuleWithAccountStates({
    rule: signedRule,
    accountRootKey: f.accountRootPub,
    nowMs: f.nowMs,
    accountStates: [activeState],
    expectedAccountId: f.accountId,
  });
  assert.equal(verifiedRule.deviceId, f.deviceId);

  const emptyExpectedRule = await verifyPolicyRuleWithAccountStates({
    rule: signedRule,
    accountRootKey: f.accountRootPub,
    nowMs: f.nowMs,
    accountStates: [activeState],
    expectedAccountId: "",
  });
  assert.equal(
    emptyExpectedRule.deviceId,
    f.deviceId,
    "SDK policy-rule helper treats empty expectedAccountId as omitted",
  );

  const evaluation = await evaluatePolicyWithAccountStates({
    action,
    actor,
    signedRules: [signedRule],
    accountRootKey: f.accountRootPub,
    nowMs: f.nowMs,
    accountStates: [activeState],
    expectedAccountId: f.accountId,
  });
  assert.equal(evaluation.decision, "allow");
  assert.equal(evaluation.ruleId, "allow-status-sdk");

  const emptyExpectedSdkEvaluation = await evaluatePolicyWithAccountStates({
    action,
    actor,
    signedRules: [signedRule],
    accountRootKey: f.accountRootPub,
    nowMs: f.nowMs,
    accountStates: [activeState],
    expectedAccountId: "",
  });
  assert.equal(
    emptyExpectedSdkEvaluation.decision,
    "allow",
    "SDK policy evaluation treats empty expectedAccountId as omitted",
  );

  await assert.rejects(
    () =>
      verifyPolicyRuleWithAccountStates({
        rule: signedRule,
        accountRootKey: f.accountRootPub,
        nowMs: f.nowMs,
        accountStates: [activeState],
        expectedAccountId: "acct_wrong_namespace",
      }),
    /expected account_id/,
    "SDK policy-rule verification must reject a wrong expected account id",
  );
  await assert.rejects(
    () =>
      evaluatePolicyWithAccountStates({
        action,
        actor,
        signedRules: [signedRule],
        accountRootKey: f.accountRootPub,
        nowMs: f.nowMs,
        accountStates: [activeState],
        expectedAccountId: "acct_wrong_namespace",
      }),
    /expected account_id/,
    "SDK policy evaluation must reject a wrong expected account id",
  );

  const revokedState = await signAccountState(
    unsignedAccountState({
      accountId: f.accountId,
      currentRoot: f.accountRootPub,
      sequence: 2,
      revokedDeviceIds: [f.deviceId],
    }),
    f.accountSeed,
  );
  await assert.rejects(
    () =>
      verifyPolicyRuleWithAccountStates({
        rule: signedRule,
        accountRootKey: f.accountRootPub,
        nowMs: f.nowMs,
        accountStates: [revokedState, activeState],
      }),
    /policy-rule signing device is revoked/,
    "SDK policy-rule verification must enforce account-state revocation",
  );
  await assert.rejects(
    () =>
      evaluatePolicyWithAccountStates({
        action,
        actor,
        signedRules: [signedRule],
        accountRootKey: f.accountRootPub,
        nowMs: f.nowMs,
        accountStates: [revokedState, activeState],
      }),
    /policy-rule signing device is revoked/,
    "SDK policy evaluation must fail closed when a signed rule's device is revoked",
  );
});

test("verify rejects a verdict whose signing key the device-cert did not certify", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  // Sign with a DIFFERENT device seed than the cert certifies — the cert binds dev_rt to f.devicePub,
  // so a signature from another key must not chain to the account root. Fail-closed → throw.
  const wrongDeviceSeed = Buffer.alloc(32, 0x5a).toString("base64url");
  const forged = wasm.sign_verdict(JSON.stringify(f.unsigned), wrongDeviceSeed, f.nonce, f.cert);

  assert.throws(
    () =>
      wasm.verify_verdict(forged, f.v.request_json, f.v.context_json, f.accountRootPub, f.v.now_ms),
    /verify_verdict failed/,
    "a verdict signed by an uncertified key must not verify",
  );
});

test("sign_verdict throws on a non-32-byte device seed", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);
  assert.throws(
    () => wasm.sign_verdict(JSON.stringify(f.unsigned), "tooshort", f.nonce, f.cert),
    /device_seed_b64 must decode to exactly 32 bytes/,
    "a malformed signing seed must surface as a thrown JS error",
  );
});

test("sign_verdict carries an optional note through to a verifiable verdict", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  // Exercise the "sign optional fields only when present" path through the wasm boundary.
  const unsigned = { ...f.unsigned, note: "approved from the cabin" };
  const verdictJson = wasm.sign_verdict(JSON.stringify(unsigned), f.deviceSeed, f.nonce, f.cert);

  const verdict = JSON.parse(verdictJson);
  assert.equal(
    verdict.note,
    "approved from the cabin",
    "the optional note is carried on the verdict",
  );

  const result = JSON.parse(
    wasm.verify_verdict(
      verdictJson,
      f.v.request_json,
      f.v.context_json,
      f.accountRootPub,
      f.v.now_ms,
    ),
  );
  assert.equal(result.approved, true, "a verdict carrying an optional note still verifies");
});

test("verify rejects a verdict whose device-cert has expired", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  // Cert that expired long before now_ms (issued_at=1000, expires_at=2000 ms — both in 1970).
  // This is the only test that threads issue_device_cert's 6th (expires_at) parameter.
  const expiredCert = wasm.issue_device_cert(
    f.accountSeed,
    "acct_rt",
    "dev_rt",
    f.devicePub,
    1000,
    2000,
  );
  const verdictJson = wasm.sign_verdict(
    JSON.stringify(f.unsigned),
    f.deviceSeed,
    f.nonce,
    expiredCert,
  );

  assert.throws(
    () =>
      wasm.verify_verdict(
        verdictJson,
        f.v.request_json,
        f.v.context_json,
        f.accountRootPub,
        f.v.now_ms,
      ),
    /verify_verdict failed/,
    "an expired device-cert must break the chain to the account root",
  );
});

test("verify rejects a verdict whose device-cert was tampered", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  // Flip one char of the cert's payload segment → its account-root signature no longer verifies.
  const parts = f.cert.split(".");
  const last = parts[1].slice(-1);
  parts[1] = parts[1].slice(0, -1) + (last === "A" ? "B" : "A");
  const tamperedCert = parts.join(".");
  const verdictJson = wasm.sign_verdict(
    JSON.stringify(f.unsigned),
    f.deviceSeed,
    f.nonce,
    tamperedCert,
  );

  assert.throws(
    () =>
      wasm.verify_verdict(
        verdictJson,
        f.v.request_json,
        f.v.context_json,
        f.accountRootPub,
        f.v.now_ms,
      ),
    /verify_verdict failed/,
    "a tampered device-cert must not verify under the account root",
  );
});

test("verify rejects a device-cert presented as the verdict signature (typ domain separation)", async () => {
  const wasm = await loadWasm();
  const f = approverFixture(wasm);

  const verdict = JSON.parse(
    wasm.sign_verdict(JSON.stringify(f.unsigned), f.deviceSeed, f.nonce, f.cert),
  );
  // Swap the verdict JWS for the device-cert JWS: wrong `typ` (device-cert vs verdict) AND wrong
  // signing key (root vs device). Either alone must reject — pins domain separation across the FFI.
  verdict.sig = f.cert;

  assert.throws(
    () =>
      wasm.verify_verdict(
        JSON.stringify(verdict),
        f.v.request_json,
        f.v.context_json,
        f.accountRootPub,
        f.v.now_ms,
      ),
    /verify_verdict failed/,
    "a device-cert used as a verdict signature must be rejected",
  );
});

// ── actor attestation (issue #16: verified request origin via the WASM core) ──────────────────

/**
 * Build an actor + its enrolled key, a root-signed account-state document anchoring that key, and a
 * correctly-signed attestation — all through the WASM surface. Reuses the shared vector's
 * request/context so `request_hash`/`request_id`/`account_id` line up with a known set.
 *
 * The actor key is root-anchored in account state (NOT a relay-supplied key): a malicious relay
 * cannot mint a verified origin. `docs/enrollment.md` §Account State.
 */
function actorAttestationFixture(wasm) {
  const v = loadVector();
  const request = JSON.parse(v.request_json);
  const requestHash = wasm.compute_request_hash(v.context_json, request.expires_at);
  const accountId = request.approver; // the vector's account id
  const requestId = request.id;

  // The account root that signs account state, and the actor key it enrolls.
  const rootSeed = Buffer.alloc(32, 0x66).toString("base64url");
  const rootPub = wasm.ed25519_public_key(rootSeed);
  const actorSeed = Buffer.alloc(32, 0x44).toString("base64url");
  const actorPub = wasm.ed25519_public_key(actorSeed);
  const actorId = "machine:macbook-pro";
  const actorKind = "claude-code";

  const accountState = (actorPubkey, status = "active", revoke = false) => {
    const state = {
      v: 1,
      account_id: accountId,
      sequence: 1,
      current_root: rootPub,
      previous_roots: [],
      devices: [],
      actors: [{ actor_id: actorId, kind: actorKind, pubkey: actorPubkey, status }],
      revocations: revoke ? [{ kind: "actor", id: actorId, revoked_at: 1700000000000 }] : [],
    };
    return wasm.sign_account_state(JSON.stringify(state), rootSeed);
  };
  const enrolledStates = JSON.stringify([accountState(actorPub)]);

  const attestation = wasm.sign_actor_attestation(
    accountId,
    actorId,
    actorKind,
    requestId,
    requestHash,
    actorSeed,
  );
  const actor = { id: actorId, kind: actorKind, attestation };
  const verify = (actorJson, states = enrolledStates) =>
    wasm.verify_actor_attestation(actorJson, accountId, requestId, requestHash, states, rootPub);
  return {
    v,
    requestHash,
    requestId,
    accountId,
    rootSeed,
    rootPub,
    actorSeed,
    actorPub,
    actorId,
    actorKind,
    actor,
    accountState,
    enrolledStates,
    verify,
  };
}

test("sign_actor_attestation → verify_actor_attestation round-trip (root-anchored verified origin)", async () => {
  const wasm = await loadWasm();
  const f = actorAttestationFixture(wasm);

  const result = JSON.parse(f.verify(JSON.stringify(f.actor)));
  assert.equal(result.verified, true, "a correctly-signed, root-anchored attestation verifies");
  assert.equal(result.actor_id, f.actorId, "actor_id echoes the verified attestation");
  assert.equal(result.actor_kind, f.actorKind, "actor_kind echoes the verified attestation");
  // docs/contract.md §Identity & keys: the verified origin renders "{kind} · {id}".
  assert.equal(
    result.origin,
    "claude-code · machine:macbook-pro",
    "the human-readable verified origin is '{kind} · {id}'",
  );
});

test("verify_actor_attestation throws when the attestation is absent (fail-closed)", async () => {
  const wasm = await loadWasm();
  const f = actorAttestationFixture(wasm);

  // An actor with NO attestation must be rejected — origin is unverifiable plaintext (never shown
  // as verified).
  const noAttestation = { id: f.actorId, kind: f.actorKind };
  assert.throws(
    () => f.verify(JSON.stringify(noAttestation)),
    /verify_actor_attestation failed/,
    "an absent attestation must throw, not return a verified origin",
  );
});

test("verify_actor_attestation throws when the actor key is NOT root-anchored (forged/relay key)", async () => {
  const wasm = await loadWasm();
  const f = actorAttestationFixture(wasm);

  // THE blocker: an attestation signed by a key the account root never enrolled cannot verify, even
  // though it is self-consistent. Account state enrolls only the real key → the forged key fails.
  const attackerSeed = Buffer.alloc(32, 0x55).toString("base64url");
  const forged = wasm.sign_actor_attestation(
    f.accountId,
    f.actorId,
    f.actorKind,
    f.requestId,
    f.requestHash,
    attackerSeed,
  );
  const actor = { id: f.actorId, kind: f.actorKind, attestation: forged };
  assert.throws(
    () => f.verify(JSON.stringify(actor)),
    /verify_actor_attestation failed/,
    "a non-root-anchored (forged/relay) key must not drive a verified origin",
  );
});

test("verify_actor_attestation throws when account state enrolls a DIFFERENT key (relay substitution)", async () => {
  const wasm = await loadWasm();
  const f = actorAttestationFixture(wasm);

  // The real key signed the attestation, but account state enrolls the OTHER key for this actor —
  // modeling a substituted enrollment. The signature cannot verify under the enrolled key.
  const otherSeed = Buffer.alloc(32, 0x55).toString("base64url");
  const otherPub = wasm.ed25519_public_key(otherSeed);
  const substituted = JSON.stringify([f.accountState(otherPub)]);
  assert.throws(
    () => f.verify(JSON.stringify(f.actor), substituted),
    /verify_actor_attestation failed/,
    "an enrolled key that did not sign the attestation must be rejected",
  );
});

test("verify_actor_attestation throws with no account state (no root anchor, fail-closed)", async () => {
  const wasm = await loadWasm();
  const f = actorAttestationFixture(wasm);

  assert.throws(
    () => f.verify(JSON.stringify(f.actor), JSON.stringify([])),
    /verify_actor_attestation failed/,
    "with no root-signed account state there is no trust anchor → reject",
  );
});

test("verify_actor_attestation throws for a revoked actor (fail-closed)", async () => {
  const wasm = await loadWasm();
  const f = actorAttestationFixture(wasm);

  const revoked = JSON.stringify([f.accountState(f.actorPub, "active", /* revoke */ true)]);
  assert.throws(
    () => f.verify(JSON.stringify(f.actor), revoked),
    /verify_actor_attestation failed/,
    "a revoked actor must not be shown as verified",
  );
});

test("verify_actor_attestation throws on a spoofed actor id (origin spoofing)", async () => {
  const wasm = await loadWasm();
  const f = actorAttestationFixture(wasm);

  // Sign for a DIFFERENT (attacker) actor id, but present an outer actor claiming the trusted id.
  // The signed actor_id ≠ the rendered actor.id → rejected. This is the core "verified origin"
  // guarantee: a benign-looking plaintext id cannot ride a signature for a different actor.
  const attackerAttestation = wasm.sign_actor_attestation(
    f.accountId,
    "machine:attacker",
    f.actorKind,
    f.requestId,
    f.requestHash,
    f.actorSeed,
  );
  const spoofed = { id: f.actorId, kind: f.actorKind, attestation: attackerAttestation };
  assert.throws(
    () => f.verify(JSON.stringify(spoofed)),
    /verify_actor_attestation failed/,
    "a spoofed outer actor.id must be rejected",
  );
});

test("verify_actor_attestation throws when the request_id binding is wrong (no swap)", async () => {
  const wasm = await loadWasm();
  const f = actorAttestationFixture(wasm);

  // Signed over a DIFFERENT request_id (same hash) — a lift onto a content-identical sibling. The
  // request_id binding (not just request_hash) catches it.
  const lifted = wasm.sign_actor_attestation(
    f.accountId,
    f.actorId,
    f.actorKind,
    "req-other-0002",
    f.requestHash,
    f.actorSeed,
  );
  const actor = { id: f.actorId, kind: f.actorKind, attestation: lifted };
  assert.throws(
    () => f.verify(JSON.stringify(actor)),
    /verify_actor_attestation failed/,
    "an attestation bound to a different request_id must be rejected",
  );
});

test("verify_actor_attestation throws when the request_hash binding is altered (lift/replay)", async () => {
  const wasm = await loadWasm();
  const f = actorAttestationFixture(wasm);

  // Signed over a DIFFERENT request_hash (a different request the device is rendering) → reject.
  const otherHash = Buffer.alloc(32, 0xcd).toString("base64url");
  const lifted = wasm.sign_actor_attestation(
    f.accountId,
    f.actorId,
    f.actorKind,
    f.requestId,
    otherHash,
    f.actorSeed,
  );
  const actor = { id: f.actorId, kind: f.actorKind, attestation: lifted };
  assert.throws(
    () => f.verify(JSON.stringify(actor)),
    /verify_actor_attestation failed/,
    "an attestation bound to a different request_hash must be rejected",
  );
});

test("verify_actor_attestation throws when a verdict/cert JWS is presented as an attestation (typ separation)", async () => {
  const wasm = await loadWasm();
  const f = actorAttestationFixture(wasm);

  // Domain separation: a device-cert / verdict JWS used in the attestation slot has the wrong `typ`
  // and must be rejected before any identity check. Reuse a cert as a stand-in foreign JWS
  // (b64url-encode its UTF-8 bytes to match the attestation wire encoding).
  const deviceSeed = Buffer.alloc(32, 9).toString("base64url");
  const devicePub = wasm.ed25519_public_key(deviceSeed);
  const cert = wasm.issue_device_cert(f.rootSeed, f.accountId, "dev_rt", devicePub, 1700000000000);
  const certAsAttestation = Buffer.from(cert, "utf8").toString("base64url");
  const actor = { id: f.actorId, kind: f.actorKind, attestation: certAsAttestation };

  assert.throws(
    () => f.verify(JSON.stringify(actor)),
    /verify_actor_attestation failed/,
    "a device-cert JWS in the attestation slot must be rejected (wrong typ)",
  );
});

// ── ActionRecord builders (issue #13: the hook's syntactic substrate via the WASM core) ───────

test("action_from_command builds a command ActionRecord (surface=command, tokenized + cwd)", async () => {
  const wasm = await loadWasm();

  const json = wasm.action_from_command("git push --force origin main", "/home/dev/repo");
  const record = JSON.parse(json);

  // policy-seam.md §The three tiers (T1): the command surface captures the syntactic substrate.
  assert.equal(record.surface, "command", "surface must be 'command'");
  assert.equal(record.record_schema_version, 1, "v1 record schema version");
  assert.equal(record.syntactic.bin, "git", "bin is argv[0]");
  assert.deepEqual(
    record.syntactic.argv,
    ["git", "push", "--force", "origin", "main"],
    "argv is the full token vector",
  );
  assert.ok(
    record.syntactic.flags.includes("--force"),
    "flags include the force flag (starts with '-')",
  );
  assert.deepEqual(
    record.syntactic.positionals,
    ["push", "origin", "main"],
    "positionals are the non-flag tokens after argv[0]",
  );
  assert.equal(record.syntactic.cwd, "/home/dev/repo", "cwd is threaded through from the hook");
  assert.equal(record.syntactic.raw, "git push --force origin main", "raw is the original command");
  // git push --force → High (command.rs risk heuristic).
  assert.equal(record.risk, "high", "git push --force is High risk");
  // T1 forward-compat: semantic slots reserved (policy-seam.md §forward-compat req #3). A `None`
  // serializes as an ABSENT key (skip_serializing_if), so the keys must not be present at all.
  assert.ok(!("capabilities" in record), "capabilities reserved (absent) in v1");
  assert.ok(!("scope" in record), "scope reserved (absent) in v1");
});

test("action_from_command omits cwd when not provided (cwd unknown)", async () => {
  const wasm = await loadWasm();

  // Passing no cwd (undefined) maps to Rust `None` → the substrate's cwd is absent.
  const record = JSON.parse(wasm.action_from_command("ls -la"));
  assert.equal(record.surface, "command");
  assert.ok(
    record.syntactic.cwd === undefined || record.syntactic.cwd === null,
    "cwd is absent when the caller does not supply one",
  );
});

test("action_from_command throws on a malformed command (unmatched quote)", async () => {
  const wasm = await loadWasm();

  // Fail-closed at the boundary: an unmatched quote is invalid shell syntax → the hook denies.
  assert.throws(
    () => wasm.action_from_command('echo "hello world', "/tmp"),
    /action_from_command failed/,
    "an unmatched quote must surface as a thrown JS error (fail-closed)",
  );
});

test("action_from_mcp_tool_call builds an mcp ActionRecord (surface=mcp_tool_call, params verbatim)", async () => {
  const wasm = await loadWasm();

  const params = { project_id: "abc", list: "Agent Inbox" };
  const record = JSON.parse(
    wasm.action_from_mcp_tool_call("omnifocus", "delete_project", JSON.stringify(params)),
  );

  assert.equal(record.surface, "mcp_tool_call", "surface must be 'mcp_tool_call'");
  assert.equal(record.record_schema_version, 1, "v1 record schema version");
  assert.equal(record.syntactic.server, "omnifocus", "server is preserved");
  assert.equal(record.syntactic.tool, "delete_project", "tool is preserved");
  assert.deepEqual(
    record.syntactic.params,
    params,
    "params are preserved verbatim (instance-distinguishing values stay matchable)",
  );
  // delete* prefix → High (mcp.rs risk heuristic).
  assert.equal(record.risk, "high", "delete_project → High risk");
  assert.ok(!("capabilities" in record), "capabilities reserved (absent) in v1");
  assert.ok(!("scope" in record), "scope reserved (absent) in v1");
});

test("action_from_mcp_tool_call throws on malformed params JSON (fail-closed)", async () => {
  const wasm = await loadWasm();

  assert.throws(
    () => wasm.action_from_mcp_tool_call("server", "tool", "{not json"),
    /invalid MCP tool params JSON/,
    "unparseable params must surface as a thrown JS error (fail-closed)",
  );
});

test("action_from_file_edit builds a file_edit ActionRecord with paths and diff hash", async () => {
  const wasm = await loadWasm();
  const patch = [
    "*** Begin Patch",
    "*** Update File: src/app.ts",
    "@@",
    "-old",
    "+new",
    "*** End Patch",
    "",
  ].join("\n");
  const record = JSON.parse(
    wasm.action_from_file_edit("patch", JSON.stringify(["src/app.ts"]), "patch src/app.ts", patch),
  );

  assert.equal(record.surface, "file_edit", "surface must be 'file_edit'");
  assert.equal(record.record_schema_version, 1, "v1 record schema version");
  assert.equal(record.syntactic.operation, "patch", "operation is preserved");
  assert.deepEqual(record.syntactic.paths, ["src/app.ts"], "target paths are preserved");
  assert.equal(record.syntactic.diff_summary, "patch src/app.ts", "summary is preserved");
  assert.equal(record.syntactic.raw, patch, "raw carries the exact patch text for display");
  assert.equal(typeof record.syntactic.diff_hash, "string", "diff hash is present");
  assert.equal(record.syntactic.diff_hash.length, 43, "SHA-256 base64url hash length");
  assert.equal(record.risk, "high", "file edits are high risk in v1");
});

test("action_from_file_edit throws on empty paths (fail-closed)", async () => {
  const wasm = await loadWasm();

  assert.throws(
    () => wasm.action_from_file_edit("patch", "[]", "pathless patch", "patch bytes"),
    /file edit paths must not be empty/,
    "pathless edits must be denied before they reach approval",
  );
});
