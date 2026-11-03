/**
 * Display-safety tests for the web approver (#246).
 *
 * The web approver writes request text with `textContent`, so HTML injection is already impossible —
 * but bidi overrides (U+202E, Trojan Source / CVE-2021-42574) and zero-width characters can still
 * reorder or hide what the human reads. These tests run the **real** path end to end: the context
 * is encrypted to the device, `createWasmRuntime` decrypts it and builds the view from the core's
 * `display_model`, and `mountWebApprover` renders it into a jsdom DOM. They assert that the escaped
 * form (not the raw control character) is what reaches the DOM, and that the warning badge shows.
 *
 * Expected escaped strings are written by hand from the notation in
 * `crates/allw-core/src/display.rs` (`⟨U+202E⟩`, `\x1b`), not captured from program output.
 *
 * @see https://www.unicode.org/reports/tr9/ §2 (explicit bidi formatting characters)
 * @see ../../../docs/threat-model.md R3 (WYSIWYS completeness)
 * @see ../../../docs/contract.md §Invariants #3 (WYSIWYS)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { JSDOM } from "jsdom";

import { mountWebApprover } from "../dist/browser.js";
import { createWasmRuntime } from "../dist/index.js";
import { loadTestWasm } from "./wasm-helper.mjs";

const ACCOUNT_ID = "acct-web-display-test";
const DEVICE_ID = "dev-web-display-test";
const ISSUED_AT = 1700000000000;
const EXPIRES_AT = 1700003600000;
const NOW_MS = 1700001500000;

const RLO = "‮";
const ZWSP = "​";
// eslint-disable-next-line no-control-regex
const RAW_HIDDEN = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f؜​-‏‪-‮⁠⁦-⁩﻿]/;

function pairedIdentity(wasm) {
  const accountRootSeed = Buffer.alloc(32, 0x11).toString("base64url");
  const deviceSigningSeed = Buffer.alloc(32, 0x22).toString("base64url");
  const deviceEncryptionSeed = Buffer.alloc(32, 0x33).toString("base64url");
  const deviceEncryptionPubkey = wasm.x25519_public_key(deviceEncryptionSeed);
  const identity = {
    accountId: ACCOUNT_ID,
    deviceId: DEVICE_ID,
    deviceEncryptionSeed,
    deviceSigningSeed,
    deviceCert: wasm.issue_device_cert(
      accountRootSeed,
      ACCOUNT_ID,
      DEVICE_ID,
      wasm.ed25519_public_key(deviceSigningSeed),
      ISSUED_AT,
    ),
    accountRootPubkey: wasm.ed25519_public_key(accountRootSeed),
    deviceAuthToken: "relay-bearer-test-token",
  };
  const encryptTo = (context) =>
    wasm.encrypt_context(
      JSON.stringify(context),
      JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: deviceEncryptionPubkey }]),
    );
  return { identity, encryptTo };
}

function envelope(id, ciphertext) {
  return {
    v: 1,
    id,
    created_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    approver: ACCOUNT_ID,
    context_ciphertext: ciphertext,
  };
}

function context(syntactic, overrides = {}) {
  return {
    action: { record_schema_version: 1, surface: "command", syntactic, risk: "high" },
    summary: "open the invoice",
    actor: { id: "machine:laptop", kind: "claude-code" },
    risk: "high",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
    ...overrides,
  };
}

/** Mount the real web approver over the real WASM runtime and return the rendered root. */
async function mountWith(contexts) {
  const wasm = await loadTestWasm();
  const { identity, encryptTo } = pairedIdentity(wasm);
  const envelopes = contexts.map((ctx, i) => envelope(`req-display-${String(i)}`, encryptTo(ctx)));
  const dom = new JSDOM('<div id="app"></div>', { url: "https://approver.local/" });
  const root = dom.window.document.getElementById("app");
  const saved = {
    document: globalThis.document,
    window: globalThis.window,
    HTMLButtonElement: globalThis.HTMLButtonElement,
  };
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  globalThis.HTMLButtonElement = dom.window.HTMLButtonElement;
  try {
    await mountWebApprover({
      root,
      nowMs: () => NOW_MS,
      fetchInbox: async () => envelopes,
      runtime: createWasmRuntime({ wasm, identity, nowMs: () => NOW_MS }),
    });
    return root;
  } finally {
    globalThis.document = saved.document;
    globalThis.window = saved.window;
    globalThis.HTMLButtonElement = saved.HTMLButtonElement;
  }
}

test("a U+202E bidi override renders escaped in the DOM with the warning badge (#246)", async () => {
  // Trojan-Source-style filename: displayed raw, `invoice‮fdp.exe` reads as `invoiceexe.pdf`.
  const root = await mountWith([
    context({ argv: ["open", `invoice${RLO}fdp.exe`], raw: `open invoice${RLO}fdp.exe` }),
  ]);
  const text = root.textContent ?? "";
  assert.doesNotMatch(text, RAW_HIDDEN, "no raw bidi/control character reaches the DOM");
  assert.ok(text.includes("open invoice⟨U+202E⟩fdp.exe"), "the escaped form is in the DOM");
  const badge = root.querySelector(".hidden-chars-warning");
  assert.ok(badge, "the hidden-character warning badge is present");
  assert.match(badge.textContent ?? "", /hidden\/control characters/);
  assert.equal(badge.getAttribute("role"), "alert");
});

test("zero-width characters in the actor and cwd are escaped in the DOM", async () => {
  const root = await mountWith([
    context(
      { argv: ["ls"], raw: "ls", cwd: `/srv/${ZWSP}app` },
      {
        summary: `list files\u001b[2K`,
        actor: { id: `machine:${ZWSP}laptop`, kind: "claude-code" },
      },
    ),
  ]);
  const text = root.textContent ?? "";
  assert.doesNotMatch(text, RAW_HIDDEN);
  assert.ok(text.includes("cwd: /srv/⟨U+200B⟩app"));
  assert.ok(text.includes("machine:⟨U+200B⟩laptop (claude-code)"));
  assert.ok(root.querySelector(".hidden-chars-warning"));
});

test("MCP params with a bidi override are escaped in the DOM", async () => {
  const root = await mountWith([
    {
      ...context({}),
      action: {
        record_schema_version: 1,
        surface: "mcp_tool_call",
        syntactic: { server: "fs", tool: "write", params: { path: `/tmp/${RLO}txt.exe` } },
        risk: "high",
      },
    },
  ]);
  const text = root.textContent ?? "";
  assert.doesNotMatch(text, RAW_HIDDEN);
  assert.ok(text.includes(`"path": "/tmp/⟨U+202E⟩txt.exe"`));
  assert.ok(root.querySelector(".hidden-chars-warning"));
});

test("a clean request renders without the warning badge", async () => {
  const root = await mountWith([
    context({ argv: ["git", "status"], raw: "git status", cwd: "/repo" }),
  ]);
  assert.ok((root.textContent ?? "").includes("git status"));
  assert.equal(root.querySelector(".hidden-chars-warning"), null);
});
