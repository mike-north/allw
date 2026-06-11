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
  const deviceSeed = Buffer.alloc(32, 0x42).toString("base64url");
  const devicePubkey = wasm.ed25519_public_key(deviceSeed);
  const actor = { id: "machine:macbook", kind: "claude-code" };
  const actionJson = wasm.action_from_command("git push --force origin main", null);

  const ruleJson = wasm.policy_rule_from_approval(
    "approval-exact",
    JSON.stringify(actor),
    actionJson,
    JSON.stringify({ kind: "exact_call" }),
    1700000000000,
    "device:phone",
    deviceSeed,
  );
  const rule = JSON.parse(ruleJson);
  assert.equal(rule.provenance, "from_approval", "approval-derived rules carry provenance");
  assert.equal(rule.effect, "allow", "approval-derived rules are allow rules");
  assert.match(rule.sig, /^[^.]+\.[^.]+\.[^.]+$/, "policy rule is signed as compact JWS");

  const allowed = JSON.parse(
    wasm.evaluate_policy(actionJson, JSON.stringify(actor), JSON.stringify([rule]), devicePubkey),
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
      devicePubkey,
    ),
  );
  assert.equal(escalated.decision, "escalate", "exact-call rules must not become scoped verdicts");
});

test("evaluate_policy verifies signed rules and applies deny over ask over allow", async () => {
  const wasm = await loadWasm();
  const deviceSeed = Buffer.alloc(32, 0x42).toString("base64url");
  const devicePubkey = wasm.ed25519_public_key(deviceSeed);
  const actor = { id: "machine:macbook", kind: "claude-code" };
  const actionJson = wasm.action_from_command("git push --force origin main", null);

  const unsignedAllow = {
    id: "allow-git",
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "git" } },
    effect: "allow",
    provenance: "manual",
    tier: "syntactic",
    created_at: 1700000000000,
  };
  const unsignedAsk = {
    id: "ask-force",
    subject: { kind: "any" },
    match: { surface: "command", command: { bin: "git", args_any_globs: ["*force*"] } },
    effect: "ask",
    provenance: "manual",
    tier: "syntactic",
    created_at: 1700000000000,
  };
  const unsignedDeny = {
    id: "deny-force",
    subject: { kind: "id", id: actor.id },
    match: { surface: "command", command: { bin: "git", args_any_globs: ["*force*"] } },
    effect: "deny",
    provenance: "manual",
    tier: "syntactic",
    created_at: 1700000000000,
  };

  const allow = JSON.parse(
    wasm.sign_policy_rule(JSON.stringify(unsignedAllow), "device:phone", deviceSeed),
  );
  const ask = JSON.parse(
    wasm.sign_policy_rule(JSON.stringify(unsignedAsk), "device:phone", deviceSeed),
  );
  const deny = JSON.parse(
    wasm.sign_policy_rule(JSON.stringify(unsignedDeny), "device:phone", deviceSeed),
  );

  const askWins = JSON.parse(
    wasm.evaluate_policy(
      actionJson,
      JSON.stringify(actor),
      JSON.stringify([allow, ask]),
      devicePubkey,
    ),
  );
  assert.equal(askWins.decision, "escalate");
  assert.equal(askWins.rule_id, "ask-force");

  const denyWins = JSON.parse(
    wasm.evaluate_policy(
      actionJson,
      JSON.stringify(actor),
      JSON.stringify([allow, ask, deny]),
      devicePubkey,
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
        devicePubkey,
      ),
    /verify_policy_rule failed/,
    "policy evaluation must fail closed on a tampered signed rule",
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
