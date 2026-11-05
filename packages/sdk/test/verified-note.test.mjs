/**
 * The SDK exposes only the core-authenticated note for audit consumers. Shared signed vectors
 * exercise real verification; a substituted WASM boundary exercises malformed result handling.
 * @see ../../../docs/contract.md (§AuditRecord, §Invariants: fail-closed)
 * @see https://github.com/mike-north/allw/issues/312
 */
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

import { verifyVerdictWithAccountStates } from "../dist/index.js";

/** Frozen Rust/WASM inputs keep signatures and verification time deterministic. */
const vector = JSON.parse(
  readFileSync(
    new URL("../../../crates/allw-core/tests/fixtures/wasm_vector.json", import.meta.url),
    "utf8",
  ),
);
const request = JSON.parse(vector.request_json);
const input = {
  request,
  context: JSON.parse(vector.context_json),
  approverRootKey: vector.approver_root_pubkey_b64,
  nowMs: vector.now_ms,
  expectedAccountId: request.approver,
};

test("SDK verification returns the signed shared vector's note verbatim", async () => {
  const result = await verifyVerdictWithAccountStates({
    ...input,
    verdict: JSON.parse(vector.noted_verdict_json),
  });
  assert.equal(result.note, vector.noted_verdict_note);
});

test("SDK verification omits note for the note-less shared vector", async () => {
  const result = await verifyVerdictWithAccountStates({
    ...input,
    verdict: JSON.parse(vector.verdict_json),
  });
  assert.equal(Object.hasOwn(result, "note"), false);
});

test("SDK rejects non-string notes from WASM before accepting the nonce", async (t) => {
  // A private copy substitutes only the FFI boundary, leaving the shipped vendor untouched.
  const root = mkdtempSync(join(tmpdir(), "allw-verified-note-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  cpSync(new URL("../dist/", import.meta.url), join(root, "dist"), { recursive: true });
  writeFileSync(join(root, "package.json"), JSON.stringify({ type: "module" }));
  writeFileSync(
    join(root, "dist", "wasm.js"),
    `
    export function loadWasmSync() { return {
      verify_verdict_with_account_states: (verdict) => JSON.stringify({
        approved: true, device_id: "device", decided_at: 1700001000000,
        nonce_b64: "nonce", note: JSON.parse(verdict).note,
      }),
    }; }
    export async function loadWasm() { return loadWasmSync(); }
  `,
  );
  const sdk = await import(pathToFileURL(join(root, "dist", "index.js")).href);
  for (const note of [null, 42, false, {}, []]) {
    await assert.rejects(
      sdk.verifyVerdictWithAccountStates({
        ...input,
        verdict: { note },
        nonceStore: {
          checkAndInsert() {
            assert.fail("malformed results cannot consume a nonce");
          },
        },
      }),
      /verify_verdict result.*note/,
    );
  }
  const empty = await sdk.verifyVerdictWithAccountStates({ ...input, verdict: { note: "" } });
  assert.equal(empty.note, "", "an empty signed note remains a string, not absence");
});
