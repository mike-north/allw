/**
 * Core round-trip tests for the v0 stand-in approver (issue #41).
 *
 * Proves the cryptographic heart of the approver against the **real WASM core** (no mocks for
 * crypto): given a `context_ciphertext` encrypted in-test to the device key, the approver
 *   1. decrypts it,
 *   2. recomputes the matching WYSIWYS `request_hash` (identical to the integrator's pre-send hash),
 *   3. signs a verdict that PASSES `verify_verdict` against the account-root pubkey (id +
 *      request_hash, no-swap) — the full approver↔integrator round-trip.
 * Plus the `denied` path and a malformed-ciphertext fail-closed path.
 *
 * The approver is exercised through its built `dist/` ESM (the package's public surface), and the
 * WASM is the same vendored `--target web` artifact the SDK test loads (built by
 * `pnpm run build:wasm` from the repo root) — so this is an integration test of the approver core
 * over the audited Rust crypto, not a unit test against stubs.
 *
 * Run order:
 *   pnpm run build:wasm               # from repo root — wasm-pack build (--target web)
 *   pnpm --filter @allw/approver build
 *   pnpm --filter @allw/approver test
 *
 * @see ../../sdk/test/wasm.test.mjs (the loader + fixture pattern this mirrors)
 * @see ../../../docs/contract.md §Lifecycle, §Messages, §Verification checklist, §Wire encoding
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { loadWasm } from "../dist/index.js";
import { generateKeyfile } from "../dist/lib/keyfile.js";
import { prepareRequest, signDecision } from "../dist/lib/approver-core.js";
import { renderRequest } from "../dist/lib/render.js";

// ── Deterministic fixtures (fixed timestamps; never Date.now() in test data) ─────────────────

const ACCOUNT_ID = "acct-approver-test";
const DEVICE_ID = "dev-approver-test";
const REQUEST_ID = "req-approver-test-1";
/** 2023-11-14T22:13:20Z — cert issuance. */
const ISSUED_AT = 1700000000000;
/** 2023-11-14T23:13:20Z — request deadline (bound into request_hash). */
const EXPIRES_AT = 1700003600000;
/** 2023-11-14T22:30:00Z — when the human decided (inside the verify window). */
const DECIDED_AT = 1700001000000;
/** 2023-11-14T22:38:20Z — verifier's "now" (after decided_at, before expiry). */
const NOW_MS = 1700001500000;

/**
 * The canonical human-shown context for these tests. Built by hand from `docs/contract.md`
 * §Messages → ApprovalContext (NOT captured from program output).
 */
const CONTEXT = {
  action: {
    record_schema_version: 1,
    surface: "command",
    syntactic: { bin: "git", raw: "git push --force origin main" },
    risk: "high",
  },
  summary: "force push to main",
  actor: { id: "machine:laptop", kind: "claude-code" },
  risk: "high",
  reversible: false,
  constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
};
const CONTEXT_JSON = JSON.stringify(CONTEXT);

/** The relay-visible envelope the integrator submits (minus the ciphertext, filled per-test). */
function makeEnvelope(contextCiphertext, overrides = {}) {
  return {
    v: 1,
    id: overrides.id ?? REQUEST_ID,
    created_at: ISSUED_AT,
    expires_at: overrides.expires_at ?? EXPIRES_AT,
    approver: ACCOUNT_ID,
    context_ciphertext: contextCiphertext,
  };
}

/** The integrator-side ApprovalRequest JSON (no ciphertext) passed to verify_verdict. */
function makeRequestJson() {
  return JSON.stringify({
    v: 1,
    id: REQUEST_ID,
    created_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    approver: ACCOUNT_ID,
  });
}

/**
 * Build a fully-paired approver keyfile: a fresh identity whose account-root certifies the device
 * signing key, with relay/account/device populated. Returns { keyfile, jwe } where `jwe` encrypts
 * CONTEXT to the device's X25519 key (the integrator's encrypt step).
 */
function pairedApprover(wasm) {
  const fresh = generateKeyfile(wasm);
  const cert = wasm.issue_device_cert(
    fresh.account_root_seed,
    ACCOUNT_ID,
    DEVICE_ID,
    fresh.device_signing_pubkey,
    ISSUED_AT,
  );
  const keyfile = {
    ...fresh,
    relay_url: "https://relay.allw.test",
    account_id: ACCOUNT_ID,
    device_id: DEVICE_ID,
    device_cert: cert,
  };
  const recipients = JSON.stringify([
    { device_id: DEVICE_ID, public_key_b64: fresh.device_encryption_pubkey },
  ]);
  const jwe = wasm.encrypt_context(CONTEXT_JSON, recipients);
  return { keyfile, jwe };
}

// ── Round-trip: decrypt → recompute hash → sign → verify ─────────────────────────────────────

test("approved round-trip: decrypt → recompute request_hash → sign → verify_verdict accepts", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);

  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);

  // (a) The recomputed WYSIWYS hash equals the integrator's pre-send hash (no separate digest).
  const integratorHash = wasm.compute_request_hash(CONTEXT_JSON, EXPIRES_AT);
  assert.equal(
    prepared.requestHash,
    integratorHash,
    "device-recomputed request_hash must equal the integrator's pre-send hash (WYSIWYS)",
  );
  assert.equal(prepared.requestId, REQUEST_ID, "the prepared request id comes from the envelope");
  assert.equal(prepared.context.summary, CONTEXT.summary, "the decrypted context round-trips");

  // (b) Sign an approval and verify it against the ACCOUNT-ROOT pubkey (id + request_hash, no swap).
  const verdict = signDecision(wasm, keyfile, prepared, "approved", DECIDED_AT);
  assert.equal(verdict.decision, "approved", "the signed verdict carries the approved decision");
  assert.equal(verdict.request_id, REQUEST_ID, "the verdict binds to the request id");

  const result = JSON.parse(
    wasm.verify_verdict(
      JSON.stringify(verdict),
      makeRequestJson(),
      CONTEXT_JSON,
      keyfile.account_root_pubkey,
      NOW_MS,
    ),
  );
  assert.equal(result.approved, true, "the approver's verdict must verify under the account root");
  assert.equal(result.device_id, DEVICE_ID, "verified device_id matches the paired device");
  assert.equal(result.decided_at, DECIDED_AT, "verified decided_at echoes the signed claim");
});

test("denied round-trip: a signed denial verifies as a verified 'no' (verify_verdict throws)", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);

  const verdict = signDecision(wasm, keyfile, prepared, "denied", DECIDED_AT);
  assert.equal(verdict.decision, "denied", "the signed verdict carries the denied decision");

  // Per the WASM FFI contract, a VERIFIED non-approval is reported as a thrown error (fail-closed),
  // not `approved: false` — so the integrator's gate stays closed. The throw proves the denial was
  // authentic (it parsed, the signature + binding checked out, the decision was simply 'denied').
  assert.throws(
    () =>
      wasm.verify_verdict(
        JSON.stringify(verdict),
        makeRequestJson(),
        CONTEXT_JSON,
        keyfile.account_root_pubkey,
        NOW_MS,
      ),
    /verify_verdict failed/,
    "a verified denial surfaces as a thrown error (deny-by-default), not a falsy result",
  );
});

// ── Fail-closed: malformed / wrong-key ciphertext ────────────────────────────────────────────

test("fail-closed: a malformed ciphertext aborts the request (throws, no verdict)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // A structurally invalid JWE — the device key cannot decrypt it; prepareRequest must throw so the
  // approver emits no verdict and the integrator's gate stays closed.
  const envelope = makeEnvelope("eyJhbGciOiJFQ0RILUVTK0EyNTZLVyJ9.NOT-A-REAL.JWE");
  assert.throws(
    () => prepareRequest(wasm, keyfile, envelope, NOW_MS),
    /decrypt/i,
    "a malformed ciphertext must throw (fail-closed), never yield a forged context",
  );
});

test("fail-closed: a ciphertext encrypted to a DIFFERENT device key cannot be decrypted", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // Encrypt to a stranger's X25519 key — our device key must not be able to unwrap the CEK.
  const strangerSeed = Buffer.alloc(32, 0x5a).toString("base64url");
  const strangerPub = wasm.x25519_public_key(strangerSeed);
  const jweForStranger = wasm.encrypt_context(
    CONTEXT_JSON,
    JSON.stringify([{ device_id: "dev-stranger", public_key_b64: strangerPub }]),
  );

  assert.throws(
    () => prepareRequest(wasm, keyfile, makeEnvelope(jweForStranger), NOW_MS),
    /decrypt/i,
    "a context encrypted to another device must fail to decrypt (fail-closed)",
  );
});

test("fail-closed: an envelope missing context_ciphertext is rejected before any crypto", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);
  const envelope = makeEnvelope("placeholder");
  delete envelope.context_ciphertext;

  assert.throws(
    () => prepareRequest(wasm, keyfile, envelope, NOW_MS),
    /context_ciphertext/,
    "a malformed envelope must be rejected fail-closed",
  );
});

test("fail-closed: signing is refused when the keyfile has no device_cert", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);

  // Strip the cert — without it the verdict cannot chain to the account root, so we must refuse to
  // sign rather than emit an unverifiable verdict.
  const certless = { ...keyfile, device_cert: undefined };
  assert.throws(
    () => signDecision(wasm, certless, prepared, "approved", DECIDED_AT),
    /device_cert/,
    "signing without a device_cert must be refused (the verdict could never verify)",
  );
});

// ── Device-side fail-closed expiry (review fix #2) ───────────────────────────────────────────

test("fail-closed expiry: prepareRequest refuses an expired request (no decrypt, no prompt)", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);

  // now == expires_at: at-or-past the deadline must be refused (boundary is inclusive: <=).
  assert.throws(
    () => prepareRequest(wasm, keyfile, makeEnvelope(jwe), EXPIRES_AT),
    /expired/,
    "a request at its deadline must be refused (device-side fail-closed, not just the relay)",
  );
  // now well past the deadline: also refused.
  assert.throws(
    () => prepareRequest(wasm, keyfile, makeEnvelope(jwe), EXPIRES_AT + 60_000),
    /expired/,
    "a request past its deadline must be refused",
  );
});

test("fail-closed expiry: a request one ms before the deadline is still accepted", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  // Boundary: now = expires_at - 1 is still live, so prepare succeeds and yields a renderable.
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), EXPIRES_AT - 1);
  assert.equal(prepared.requestId, REQUEST_ID, "a not-yet-expired request prepares normally");
});

// ── Fail-closed: WYSIWYS tamper between encrypt and render (review fix, non-blocking) ─────────

test("tamper-mismatch: a mutated context yields a request_hash that fails the integrator's check", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // Simulate tampering between encrypt and render: the human-shown context the device decrypts
  // differs from what the integrator hashed pre-send (here the cwd/summary were altered). The
  // device recomputes the hash over the bytes it actually saw — which must NOT equal the
  // integrator's hash of the ORIGINAL context, so the eventual verify_verdict (which binds the
  // integrator's original request_hash) cannot accept it. Proves the WYSIWYS binding catches a swap.
  const tamperedContext = {
    ...CONTEXT,
    summary: "innocuous: list files",
    action: {
      ...CONTEXT.action,
      syntactic: { bin: "git", raw: "git push --force origin main", cwd: "/etc" },
    },
  };
  const tamperedJson = JSON.stringify(tamperedContext);
  const jwe = wasm.encrypt_context(
    tamperedJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );

  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);

  // The integrator's pre-send hash was computed over the ORIGINAL context; the device's recomputed
  // hash is over the tampered one → they differ, so the binding is broken (no silent acceptance).
  const integratorHashOriginal = wasm.compute_request_hash(CONTEXT_JSON, EXPIRES_AT);
  assert.notEqual(
    prepared.requestHash,
    integratorHashOriginal,
    "a tampered context must produce a DIFFERENT request_hash than the integrator's original",
  );

  // And concretely: a verdict the device signs over its (tampered) hash fails verify_verdict when
  // the integrator verifies against the ORIGINAL context it holds — fail-closed end to end.
  const verdict = signDecision(wasm, keyfile, prepared, "approved", DECIDED_AT);
  assert.throws(
    () =>
      wasm.verify_verdict(
        JSON.stringify(verdict),
        makeRequestJson(),
        CONTEXT_JSON, // integrator's ORIGINAL context
        keyfile.account_root_pubkey,
        NOW_MS,
      ),
    /verify_verdict failed/,
    "a verdict bound to a tampered context must not verify against the integrator's original",
  );
});

// ── WYSIWYS render shows the EXACT action ────────────────────────────────────────────────────

test("renderRequest shows the exact action, actor, risk, expiry, and request_hash", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);

  const rendered = renderRequest(prepared);
  // Every WYSIWYS field the human signs over must appear verbatim in the rendered block.
  assert.match(rendered, /git push --force origin main/, "the exact action/argv is shown");
  assert.match(rendered, /force push to main/, "the summary is shown");
  assert.match(rendered, /machine:laptop \(claude-code\)/, "the actor id + kind are shown");
  assert.match(rendered, /Risk:\s+high/, "the risk tier is shown");
  assert.match(rendered, /Reversible: no/, "reversibility is shown");
  assert.match(rendered, /2023-11-14T23:13:20\.000Z/, "the expiry is shown (ISO-8601 UTC)");
  assert.ok(
    rendered.includes(prepared.requestHash),
    "the request_hash is shown verbatim for out-of-band verification",
  );
  // With no origin verification supplied (prepared.origin undefined), the actor origin must be
  // marked ⚠ UNVERIFIED — a failed/absent attestation is never shown as trusted (#16).
  assert.match(
    rendered,
    /⚠ UNVERIFIED/,
    "the actor origin is shown as unverified when no attestation verified (#16)",
  );
  assert.doesNotMatch(
    rendered,
    /✓ VERIFIED/,
    "an unverified origin must NOT render the verified marker",
  );
});

test("renderRequest surfaces cwd and env_refs (WYSIWYS completeness — review fix #1)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // A command whose meaning hinges on cwd + env_refs — both bound into request_hash, so both MUST
  // appear in the rendered output (the TOCTOU gap a `raw`-only summary would reopen).
  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "command",
      syntactic: {
        bin: "rm",
        argv: ["rm", "-rf", "build"],
        raw: "rm -rf build",
        cwd: "/etc",
        env_refs: ["AWS_SECRET_ACCESS_KEY", "DEPLOY_TOKEN"],
      },
      risk: "critical",
    },
    summary: "remove the build directory",
    actor: { id: "machine:ci", kind: "claude-code" },
    risk: "critical",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  assert.match(
    rendered,
    /Cwd:\s+\/etc/,
    "the cwd is rendered (a /etc vs /tmp distinction matters)",
  );
  assert.match(
    rendered,
    /Env refs:\s+AWS_SECRET_ACCESS_KEY, DEPLOY_TOKEN/,
    "the referenced env var names are rendered",
  );
});

test("renderRequest surfaces MCP params (not hidden behind raw) — review fix #1", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "mcp_tool_call",
      syntactic: {
        server: "filesystem",
        tool: "write_file",
        params: { path: "/etc/passwd", contents: "pwned" },
      },
      risk: "critical",
    },
    summary: "write a file via MCP",
    actor: { id: "machine:agent", kind: "claude-code" },
    risk: "critical",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  // The headline shows server :: tool; the full params (the entire payload) are shown explicitly.
  assert.match(rendered, /filesystem :: write_file/, "the MCP server/tool headline is shown");
  assert.match(rendered, /\/etc\/passwd/, "the MCP params payload is shown in full, not elided");
});

test("renderRequest surfaces MCP server/tool even when a benign raw masks them, no params (#56)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // THE #56 ATTACK (MCP mirror of #51): a benign `raw` ("echo hello") paired with a divergent,
  // dangerous `server`/`tool` (`fs :: delete_all_files`) and NO `params`. Both server and tool are
  // bound into request_hash (the full ActionRecord is hashed), but the old renderer short-circuited
  // on `raw` for the headline and never rendered server/tool on any detail line (only `params` was),
  // so the human would see only "echo hello". The device must surface the hash-bound server/tool.
  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "mcp_tool_call",
      syntactic: {
        server: "fs",
        tool: "delete_all_files",
        raw: "echo hello",
      },
      risk: "critical",
    },
    summary: "say hello",
    actor: { id: "machine:agent", kind: "claude-code" },
    risk: "critical",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  // The benign raw may be the headline, but the dangerous hash-bound server/tool must be surfaced.
  assert.match(rendered, /Action:\s+echo hello/, "the raw headline is shown");
  assert.match(
    rendered,
    /MCP:\s+fs :: delete_all_files/,
    "the hash-bound MCP server/tool is surfaced, not hidden behind the benign raw",
  );
  // Specifically: the dangerous tool token must be visible somewhere in the block.
  assert.match(rendered, /delete_all_files/, "the dangerous MCP tool token is visible");
});

test("renderRequest surfaces file-edit paths, operation, summary, and diff hash (#106)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "file_edit",
      syntactic: {
        operation: "patch",
        paths: ["src/app.ts"],
        diff_summary: "patch src/app.ts (+1 -1)",
        diff_hash: "d".repeat(43),
        raw: "patch src/app.ts (+1 -1)",
      },
      risk: "high",
    },
    summary: "edit app source",
    actor: { id: "machine:agent", kind: "codex" },
    risk: "high",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  assert.match(rendered, /Action:\s+patch src\/app\.ts/, "the file-edit summary is visible");
  assert.match(rendered, /File edit:\s+patch/, "the edit operation is visible");
  assert.match(rendered, /Paths:\s+src\/app\.ts/, "the target path is visible");
  assert.match(rendered, /Diff summary:\s+patch src\/app\.ts \(\+1 -1\)/);
  assert.match(rendered, new RegExp(`Diff hash:\\s+${"d".repeat(43)}`));
});

test("renderRequest disambiguates argv args containing whitespace (WYSIWYS — review item #1)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // An argv where one arg contains a space: `["rm","-rf","my dir"]`. Bare space-join would render
  // `rm -rf my dir` — indistinguishable from three args. The human must see the arg boundary.
  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "command",
      syntactic: { argv: ["rm", "-rf", "my dir"] },
      risk: "high",
    },
    summary: "remove a directory whose name has a space",
    actor: { id: "machine:ci", kind: "claude-code" },
    risk: "high",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  // The space-containing arg is quoted so its boundary is visible; plain args stay unquoted.
  assert.match(rendered, /rm -rf 'my dir'/, "an arg with a space is quoted to disambiguate it");
  assert.doesNotMatch(rendered, /rm -rf my dir/, "the ambiguous bare-join form must NOT appear");
});

test("renderRequest includes bin when the substrate carries it separately from argv (review item #1)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // Substrate with `bin` separate from argv that does NOT lead with the binary: the human must see
  // the program name, not just the args (per docs/policy-seam.md, bin and argv are distinct).
  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "command",
      syntactic: { bin: "git", argv: ["push", "--force", "origin", "main"] },
      risk: "high",
    },
    summary: "force push",
    actor: { id: "machine:ci", kind: "claude-code" },
    risk: "high",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  // The fully-qualified command line leads with the binary name.
  assert.match(
    rendered,
    /Action:\s+git push --force origin main/,
    "the binary name is prepended when argv omits it",
  );
});

test("renderRequest does not double the bin when argv already leads with it (review item #1)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "command",
      syntactic: { bin: "git", argv: ["git", "status"] },
      risk: "low",
    },
    summary: "git status",
    actor: { id: "machine:ci", kind: "claude-code" },
    risk: "low",
    reversible: true,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  assert.match(rendered, /Action:\s+git status/, "argv that already includes bin is not doubled");
  assert.doesNotMatch(rendered, /git git status/, "the binary name must not be duplicated");
});

test("renderRequest surfaces a divergent argv even when raw masks it (WYSIWYS anti-divergence — #51)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // THE #51 ATTACK: a benign `raw` ("git status") paired with a divergent, dangerous `argv`
  // (`git push --force …`). BOTH are bound into request_hash (hash.rs: the full ActionRecord), but
  // the old renderer short-circuited on `raw` and showed only "git status" — the human would
  // approve a benign string while signing over the force-push. The device must surface the
  // reconstructed argv so the divergence is visible.
  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "command",
      syntactic: {
        bin: "git",
        argv: ["git", "push", "--force", "origin", "main"],
        raw: "git status",
      },
      risk: "critical",
    },
    summary: "check repo status",
    actor: { id: "machine:agent", kind: "claude-code" },
    risk: "critical",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  // The benign raw is still the headline (it is what the integrator labelled the action)…
  assert.match(rendered, /Action:\s+git status/, "the raw headline is shown");
  // …but the dangerous, hash-bound argv is surfaced verbatim on its own labeled line — the human
  // can no longer be shown only the benign string.
  assert.match(
    rendered,
    /Argv:\s+git push --force origin main/,
    "the divergent hash-bound argv is surfaced, not hidden behind the benign raw",
  );
});

test("renderRequest does NOT add a redundant Argv line when raw matches the reconstruction (#51)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // Honest integrator: `raw` is consistent with `bin`/`argv` (the core's `from_command` builder
  // produces exactly this). No divergence → no redundant `Argv:` line, just the headline.
  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "command",
      syntactic: {
        bin: "git",
        argv: ["git", "push", "--force", "origin", "main"],
        raw: "git push --force origin main",
      },
      risk: "high",
    },
    summary: "force push to main",
    actor: { id: "machine:ci", kind: "claude-code" },
    risk: "high",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  assert.match(rendered, /Action:\s+git push --force origin main/, "the raw headline is shown");
  assert.doesNotMatch(
    rendered,
    /Argv:/,
    "no redundant Argv line when raw already equals the reconstructed command",
  );
});

test("renderRequest surfaces flags and positionals as labeled lines when present (#51)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // `flags` and `positionals` are bound into request_hash (hash.rs) but were never rendered on any
  // path before #51. They must appear as their own labeled lines, quoted for boundary clarity.
  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "command",
      syntactic: {
        bin: "git",
        argv: ["git", "push", "--force", "origin", "main"],
        flags: ["--force"],
        positionals: ["origin", "main"],
        raw: "git push --force origin main",
      },
      risk: "high",
    },
    summary: "force push to main",
    actor: { id: "machine:ci", kind: "claude-code" },
    risk: "high",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  assert.match(rendered, /Flags:\s+--force/, "the parsed flags are surfaced on a labeled line");
  assert.match(
    rendered,
    /Positionals:\s+origin main/,
    "the parsed positionals are surfaced on a labeled line",
  );
});

test("renderRequest quotes flags/positionals containing whitespace (boundary clarity — #51)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // A positional whose value contains a space must be quoted so its boundary is visible (same
  // disambiguation guarantee the argv line already provides).
  const ctx = {
    action: {
      record_schema_version: 1,
      surface: "command",
      syntactic: {
        bin: "grep",
        positionals: ["hello world", "file.txt"],
        flags: ["--include=md"],
        raw: "grep 'hello world' file.txt",
      },
      risk: "low",
    },
    summary: "search files",
    actor: { id: "machine:ci", kind: "claude-code" },
    risk: "low",
    reversible: true,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
  };
  const ctxJson = JSON.stringify(ctx);
  const jwe = wasm.encrypt_context(
    ctxJson,
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
  const rendered = renderRequest(prepared);

  assert.match(
    rendered,
    /Positionals:\s+'hello world' file\.txt/,
    "a space-containing positional is quoted to disambiguate its boundary",
  );
  // `=` is intentionally NOT in the quote set (no whitespace ambiguity) — the flag stays legible.
  assert.match(rendered, /Flags:\s+--include=md/, "a flag with `=` renders without quoting");
});

test("quoteToken pins the display-quoting of representative tokens (table-driven — #51 nit)", async () => {
  const wasm = await loadWasm();
  const { keyfile } = pairedApprover(wasm);

  // Render a single-token argv and read back the produced `Action:` line, so we exercise the real
  // quoteToken through the public render surface (it is not exported). Each row pins one token →
  // its expected display form, documenting WHY each is or isn't quoted (the hand-curated set).
  const renderToken = (token) => {
    const ctx = {
      action: {
        record_schema_version: 1,
        surface: "command",
        syntactic: { argv: [token] },
        risk: "low",
      },
      summary: "token quoting probe",
      actor: { id: "machine:ci", kind: "claude-code" },
      risk: "low",
      reversible: true,
      constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
    };
    const jwe = wasm.encrypt_context(
      JSON.stringify(ctx),
      JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
    );
    const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);
    const line = renderRequest(prepared)
      .split("\n")
      .find((l) => l.startsWith("  Action:"));
    return line.replace(/^ {2}Action:\s+/, "");
  };

  /** [input token, expected display form, why]. */
  const cases = [
    ["--force", "--force", "plain flag — no metacharacters, stays bare"],
    ["origin", "origin", "plain word — stays bare"],
    ["my dir", "'my dir'", "whitespace splits tokens — must be quoted"],
    ["", "''", "empty token would vanish — rendered as explicit ''"],
    ["a'b", "'a'\\''b'", "embedded single quote — POSIX close/escape/reopen"],
    ["$(rm -rf /)", "'$(rm -rf /)'", "shell substitution — quoted (also has whitespace)"],
    ["a;b", "'a;b'", "command separator — quoted"],
    ["a|b", "'a|b'", "pipe — quoted"],
    ["wild*", "'wild*'", "glob star — quoted"],
    // Intentionally OMITTED from the quote set (no whitespace ambiguity, not shell structure):
    ["KEY=value", "KEY=value", "`=` omitted — stays bare and legible"],
    ["a:b", "a:b", "`:` omitted — stays bare"],
    ["a,b", "a,b", "`,` omitted — stays bare"],
    ["user@host", "user@host", "`@` omitted — stays bare"],
    ["50%", "50%", "`%` omitted — stays bare"],
  ];

  for (const [input, expected, why] of cases) {
    assert.equal(renderToken(input), expected, why);
  }
});

test("nonce is a fresh, high-entropy (≥16-byte) value per verdict", async () => {
  const wasm = await loadWasm();
  const { keyfile, jwe } = pairedApprover(wasm);
  const prepared = prepareRequest(wasm, keyfile, makeEnvelope(jwe), NOW_MS);

  // Two signatures over the same unsigned verdict differ because each carries a fresh random nonce
  // — proving anti-replay nonces are generated per verdict (not reused).
  const v1 = signDecision(wasm, keyfile, prepared, "approved", DECIDED_AT);
  const v2 = signDecision(wasm, keyfile, prepared, "approved", DECIDED_AT);
  assert.notEqual(v1.sig, v2.sig, "each verdict signs a fresh random nonce (anti-replay)");
});
