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
 */

import assert from "node:assert/strict";
import test from "node:test";

import { runCodexHook } from "../dist/cli.js";
import { loadWasm } from "@allw/hook";
import { assertConformsToPreToolUseOutputContract } from "./support/codex-schema.mjs";

const NOW_MS = 1_700_000_000_000;
const TIMEOUT_MS = 300_000;
const ACCOUNT_ID = "acct-codex-integration";
const DEVICE_ID = "dev-codex-integration";
const DEVICE_LABEL = "codex test device";

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
    deviceSigningSeed,
    deviceEncryptionSeed,
    accountRootPub,
    deviceEncryptionPub,
    cert,
  };
}

function nonce() {
  return Buffer.alloc(16, 17).toString("base64url");
}

function relayDouble(wasm, approver, decision) {
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
      return json({ status: "resolved", verdict });
    }

    throw new Error(`relayDouble: unexpected ${method} ${url}`);
  };

  return { fetchImpl };
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

test("end-to-end: a WASM-signed denied verdict makes Codex emit a schema-conformant deny (category=no-approval)", async () => {
  const wasm = await loadWasm();
  const approver = await pairedApprover(wasm);
  const { fetchImpl } = relayDouble(wasm, approver, "denied");

  const output = await runCodexHook(
    codexBashStdin("rm -rf build", "/workspace/project"),
    env(approver, TIMEOUT_MS),
    overrides(fetchImpl),
  );

  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /verdict: denied/);
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /^allw\[no-approval\]: /);
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
