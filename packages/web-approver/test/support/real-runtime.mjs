/**
 * Shared fixtures for web-approver tests that run the **real** path: a context is encrypted to a
 * paired test device, `createWasmRuntime` decrypts it and builds the view from the core's
 * `display_model`, and `mountWebApprover` renders it into a jsdom DOM.
 */

import { JSDOM } from "jsdom";

import { mountWebApprover } from "../../dist/browser.js";
import { createWasmRuntime } from "../../dist/index.js";
import { loadTestWasm } from "../wasm-helper.mjs";

export const ACCOUNT_ID = "acct-web-display-test";
export const DEVICE_ID = "dev-web-display-test";
export const ISSUED_AT = 1700000000000;
export const EXPIRES_AT = 1700003600000;
export const NOW_MS = 1700001500000;

export function pairedIdentity(wasm) {
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

export function envelope(id, ciphertext) {
  return {
    v: 1,
    id,
    created_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    approver: ACCOUNT_ID,
    context_ciphertext: ciphertext,
  };
}

/** Mount the real web approver over the real WASM runtime and return the rendered root. */
export async function mountWith(contexts) {
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
