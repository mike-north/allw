/**
 * "This device" panel tests (#381): the web approver shows its device id, both public keys and the
 * core's fingerprints, so the root holder can run `allw-approver vouch` and compare screens.
 *
 * The model is built with the real vendored WASM core, so the fingerprints asserted here are the
 * same ones `allw-approver vouch` prints for the same keys. Rendering runs in jsdom.
 *
 * @see ../../../docs/enrollment.md §Interim vouching
 */

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, test } from "node:test";

import { JSDOM } from "jsdom";

import { deviceDetailsModel, mountDeviceDetails } from "../dist/device-details.js";
import { loadTestWasm } from "./wasm-helper.mjs";

const DEVICE_ID = "0f8c1e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";

function identity(deviceId = DEVICE_ID) {
  return {
    deviceId,
    deviceEncryptionSeed: randomBytes(32).toString("base64url"),
    deviceSigningSeed: randomBytes(32).toString("base64url"),
  };
}

let dom;
let savedDocument;
beforeEach(() => {
  dom = new JSDOM(`<!doctype html><div id="device"></div>`);
  savedDocument = globalThis.document;
  globalThis.document = dom.window.document;
});
afterEach(() => {
  globalThis.document = savedDocument;
});

test("the model derives the public keys and core fingerprints from the stored seeds", async () => {
  const wasm = await loadTestWasm();
  const id = identity();
  const model = deviceDetailsModel(wasm, id);
  const enc = wasm.x25519_public_key(id.deviceEncryptionSeed);
  const sig = wasm.ed25519_public_key(id.deviceSigningSeed);
  assert.equal(model.encryptionPubkey, enc);
  assert.equal(model.signingPubkey, sig);
  assert.equal(model.encryptionFingerprint, wasm.device_key_fingerprint("encryption", enc));
  assert.equal(model.signingFingerprint, wasm.device_key_fingerprint("signing", sig));
  assert.match(model.encryptionFingerprint, /^([0-9a-f]{4} ){7}[0-9a-f]{4}$/);
  assert.equal(
    model.vouchCommand,
    `allw-approver vouch --device-id ${DEVICE_ID} --encryption-pubkey ${enc} --signing-pubkey ${sig}`,
  );
  assert.equal(model.problem, null);
  const text = JSON.stringify(model);
  assert.ok(
    !text.includes(id.deviceEncryptionSeed) && !text.includes(id.deviceSigningSeed),
    "no seed is shown",
  );
});

test("a device id the core refuses is shown escaped, with no vouch command", async () => {
  const wasm = await loadTestWasm();
  const model = deviceDetailsModel(wasm, identity("dev\u001b[2J‮evil"));
  assert.equal(model.vouchCommand, null);
  assert.match(model.problem, /device id must be/);
  assert.ok(!model.deviceIdDisplay.includes("\u001b") && !model.deviceIdDisplay.includes("‮"));

  const host = document.getElementById("device");
  mountDeviceDetails({ host, model, copy: null });
  assert.ok(!host.textContent.includes("\u001b"), "no raw escape reaches the DOM");
  assert.match(host.textContent, /cannot be vouched for/);
  assert.equal(host.querySelectorAll("button").length, 0);
});

test("the panel renders every value, collapsed, with copy buttons for keys and the command", async () => {
  const wasm = await loadTestWasm();
  const model = deviceDetailsModel(wasm, identity());
  const host = document.getElementById("device");
  const copied = [];
  mountDeviceDetails({
    host,
    model,
    copy: (text) => {
      copied.push(text);
      return Promise.resolve();
    },
  });
  const details = host.querySelector("details.device-details");
  assert.ok(details);
  assert.equal(details.open, false, "collapsed by default");
  for (const value of [
    DEVICE_ID,
    model.encryptionPubkey,
    model.encryptionFingerprint,
    model.signingPubkey,
    model.signingFingerprint,
    model.vouchCommand,
  ]) {
    assert.ok(host.textContent.includes(value), value);
  }
  assert.match(host.textContent, /allw-approver vouch/);
  // Review-387 F1(c)/F10: never vouch the CLI's own device; copy only from this panel.
  const warning = host.querySelector(".device-details-warning")?.textContent ?? "";
  assert.match(warning, /Do not vouch for this device if it was set up from the CLI keyfile/);
  assert.match(warning, /Copy these values only from this panel/);
  // Review-387 F3: vouching grants read access only.
  assert.match(host.textContent, /approvals are denied until it holds a device certificate/);
  const buttons = [...host.querySelectorAll("button")];
  assert.deepEqual(
    buttons.map((b) => b.textContent),
    ["Copy", "Copy", "Copy", "Copy command"],
  );
  for (const button of buttons) button.click();
  await Promise.resolve();
  assert.deepEqual(copied, [
    DEVICE_ID,
    model.encryptionPubkey,
    model.signingPubkey,
    model.vouchCommand,
  ]);
});
