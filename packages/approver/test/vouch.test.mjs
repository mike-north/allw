/**
 * `allw-approver vouch` tests (#381): the account-root holder vouches for a device that has its own
 * keys, after a human compares its fingerprints.
 *
 * `runVouch` runs against a small in-Node relay that serves the device registry
 * (`GET /:acct/devices`) and account state (`GET`/`POST /:acct/account-states`, every published
 * document verified against the root with the real core, as the relay does). The confirmer is
 * injected, so each test controls whether a terminal is present and what the human answers. A
 * last test drives the built CLI as a subprocess with a non-TTY stdin.
 *
 * Every refusal is checked for its fail-closed effect, not only its message: nothing published,
 * the keyfile's floor unchanged, and the human never asked when the refusal comes first.
 *
 * @see ../../../docs/enrollment.md §Interim vouching
 * @see ../../../docs/relay-api.md §3 (GET /devices, account state)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "../dist/index.js";
import { generateKeyfile, readKeyfile, writeKeyfile } from "../dist/lib/keyfile.js";
import { runVouch } from "../dist/commands/vouch.js";

const here = dirname(fileURLToPath(import.meta.url));
const CLI_DEVICE_ID = "dev-cli";
const PHONE_DEVICE_ID = "0f8c1e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";

/** Distinct fixed seeds make CLI parsing and key-conflict outcomes reproducible. */
function deviceKeys(wasm, encryptionByte = 55, signingByte = 56) {
  return {
    encryptionPubkey: wasm.x25519_public_key(
      Buffer.alloc(32, encryptionByte).toString("base64url"),
    ),
    signingPubkey: wasm.ed25519_public_key(Buffer.alloc(32, signingByte).toString("base64url")),
  };
}

/** The CLI keyfile's own device, as `pair` listed it. */
function cliEntry(keyfile) {
  return {
    device_id: CLI_DEVICE_ID,
    encryption_pubkey: keyfile.device_encryption_pubkey,
    signing_pubkey: keyfile.device_signing_pubkey,
    status: "active",
  };
}

/**
 * A relay holding one published state (sequence 1; by default only the CLI's own device) and a
 * device registry. Returns { url, requests, published(), close }.
 */
async function startRelay(wasm, keyfile, registry, devices = [cliEntry(keyfile)]) {
  const accountId = keyfile.account_id;
  let current = {
    account_states: [
      wasm.sign_account_state(
        JSON.stringify({
          v: 1,
          account_id: accountId,
          sequence: 1,
          current_root: keyfile.account_root_pubkey,
          previous_roots: [],
          devices,
          actors: [],
          revocations: [],
        }),
        keyfile.account_root_seed,
      ),
    ],
    max_sequence: 1,
  };
  const requests = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      requests.push(`${req.method} ${req.url}`);
      const reply = (status, payload) => {
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(payload));
      };
      if (req.url !== `/${accountId}/devices` && req.url !== `/${accountId}/account-states`) {
        return reply(404, { error: "not found" });
      }
      if (req.method === "GET" && req.url.endsWith("/devices")) {
        return reply(200, { devices: registry });
      }
      if (req.method === "GET") return reply(200, current);
      const docs = JSON.parse(body).account_states;
      let highest = -1;
      for (const jws of docs) {
        try {
          const state = JSON.parse(
            wasm.verify_account_state(jws, accountId, keyfile.account_root_pubkey),
          );
          highest = Math.max(highest, state.sequence);
        } catch {
          return reply(403, { error: "did not verify" });
        }
      }
      if (highest <= current.max_sequence) return reply(409, { error: "not above current" });
      current = { account_states: docs, max_sequence: highest };
      return reply(200, current);
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    requests,
    /** The verified AccountState the relay now serves. */
    published: () =>
      JSON.parse(
        wasm.verify_account_state(
          current.account_states[0],
          accountId,
          keyfile.account_root_pubkey,
        ),
      ),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** A confirmer that records each question and answers `answer`. */
function confirmer(answer, interactive = true) {
  const asked = [];
  return {
    interactive,
    asked,
    confirm: (question) => {
      asked.push(question);
      return Promise.resolve(answer);
    },
  };
}

/**
 * Run `fn` with a paired CLI keyfile (floor 1), a phone with its own keys, and a relay. `registry`
 * builds the relay's device list (default: the phone, registered honestly); `stateDevices` builds
 * the devices of the relay's sequence-1 account state (default: only the CLI's own device).
 */
async function withSetup(
  fn,
  registry = (phone) => [registered(PHONE_DEVICE_ID, phone)],
  stateDevices = (keyfile) => [cliEntry(keyfile)],
) {
  const wasm = await loadWasm();
  const dir = mkdtempSync(join(tmpdir(), "allw-vouch-"));
  const keyfilePath = join(dir, "keyfile.json");
  const base = generateKeyfile(wasm);
  const accountId = wasm.account_id_for_root(base.account_root_pubkey);
  const keyfile = {
    ...base,
    account_id: accountId,
    device_id: CLI_DEVICE_ID,
    account_state_highest_sequence: 1,
  };
  const phone = deviceKeys(wasm);
  const relay = await startRelay(
    wasm,
    keyfile,
    registry(phone, keyfile),
    stateDevices(keyfile, phone),
  );
  writeKeyfile(keyfilePath, { ...keyfile, relay_url: relay.url });
  const lines = [];
  try {
    await fn({
      wasm,
      keyfilePath,
      keyfile,
      phone,
      relay,
      lines,
      log: (line) => lines.push(line),
    });
  } finally {
    await relay.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

function registered(deviceId, keys, label = "Mike's iPhone") {
  return { device_id: deviceId, pubkey: keys.encryptionPubkey, label, created_at: 1 };
}

function vouchOptions(keyfilePath, phone, deviceId = PHONE_DEVICE_ID) {
  return { keyfilePath, deviceId, ...phone };
}

/** Assert a refusal left everything as it was: nothing published, floor unchanged. */
function assertNothingChanged(relay, keyfilePath) {
  assert.ok(
    !relay.requests.includes(`POST /${readKeyfile(keyfilePath).account_id}/account-states`),
  );
  assert.equal(relay.published().sequence, 1, "the relay still serves sequence 1");
  assert.equal(readKeyfile(keyfilePath).account_state_highest_sequence, 1, "floor unchanged");
}

test("vouch lists the device after the human confirms, showing core fingerprints (#381)", async () => {
  await withSetup(async ({ wasm, keyfilePath, phone, relay, lines, log }) => {
    const ask = confirmer(true);
    const sequence = await runVouch(wasm, vouchOptions(keyfilePath, phone), ask, log);
    assert.equal(sequence, 2);
    assert.equal(ask.asked.length, 1, "asked exactly once");
    const state = relay.published();
    assert.equal(state.sequence, 2);
    assert.deepEqual(
      state.devices.map((d) => [d.device_id, d.encryption_pubkey, d.signing_pubkey, d.status]),
      [
        [
          CLI_DEVICE_ID,
          readKeyfile(keyfilePath).device_encryption_pubkey,
          readKeyfile(keyfilePath).device_signing_pubkey,
          "active",
        ],
        [PHONE_DEVICE_ID, phone.encryptionPubkey, phone.signingPubkey, "active"],
      ],
    );
    assert.equal(readKeyfile(keyfilePath).account_state_highest_sequence, 2, "floor follows");
    const text = lines.join("\n");
    assert.match(text, new RegExp(`device id: +${PHONE_DEVICE_ID}`));
    assert.match(text, /relay label: +Mike's iPhone/);
    const encFp = wasm.device_key_fingerprint("encryption", phone.encryptionPubkey);
    const sigFp = wasm.device_key_fingerprint("signing", phone.signingPubkey);
    assert.match(encFp, /^([0-9a-f]{4} ){7}[0-9a-f]{4}$/);
    assert.ok(text.includes(`encryption key:  ${encFp}`));
    assert.ok(text.includes(`signing key:     ${sigFp}`));
    assert.match(text, /The new account state \(sequence 2\):/);
    assert.ok(text.includes(`recipients:      ${CLI_DEVICE_ID}, ${PHONE_DEVICE_ID}`));
    assert.doesNotMatch(text, /replaces:/, "a plain add replaces nothing");
    // Review-387 F3: success says the device can decrypt but cannot yet approve.
    assert.match(text, /approvals are denied until it holds a device certificate/);
  });
});

test("vouch shows every id the new state replaces and its recipients before asking (review-387 F1)", async () => {
  // The phone re-paired: the relay gave its same keys a new id. The state still lists the old id,
  // which the #378 rule replaces. The human must see that before confirming.
  const OLD_PHONE_ID = "dev-phone-old";
  await withSetup(
    async ({ wasm, keyfilePath, phone, relay, lines, log }) => {
      let shownAtAsk = "";
      const ask = {
        interactive: true,
        confirm: () => {
          shownAtAsk = lines.join("\n");
          return Promise.resolve(true);
        },
      };
      await runVouch(wasm, vouchOptions(keyfilePath, phone), ask, log);
      assert.ok(
        shownAtAsk.includes(`replaces:        ${OLD_PHONE_ID} (same keys`),
        "the replaced id is shown before the question",
      );
      assert.ok(shownAtAsk.includes(`recipients:      ${CLI_DEVICE_ID}, ${PHONE_DEVICE_ID}`));
      assert.match(shownAtAsk, /sequence 2/);
      assert.deepEqual(
        relay.published().devices.map((d) => d.device_id),
        [CLI_DEVICE_ID, PHONE_DEVICE_ID],
        "what was shown is what was published",
      );
    },
    (phone) => [registered(PHONE_DEVICE_ID, phone)],
    (keyfile, phone) => [
      cliEntry(keyfile),
      {
        device_id: OLD_PHONE_ID,
        encryption_pubkey: phone.encryptionPubkey,
        signing_pubkey: phone.signingPubkey,
        status: "active",
      },
    ],
  );
});

for (const [kind, ownField] of [
  ["encryption", "encryptionPubkey"],
  ["signing", "signingPubkey"],
]) {
  test(`vouch refuses when only the pasted ${kind} key is this keyfile's own (#381)`, async () => {
    await withSetup(async ({ wasm, keyfilePath, keyfile, phone, relay, log }) => {
      const own = {
        encryptionPubkey: keyfile.device_encryption_pubkey,
        signingPubkey: keyfile.device_signing_pubkey,
      };
      // The phone's keys, except one taken from this keyfile.
      const pasted = { ...phone, [ownField]: own[ownField] };
      const ask = confirmer(true);
      await assert.rejects(
        () => runVouch(wasm, { keyfilePath, deviceId: PHONE_DEVICE_ID, ...pasted }, ask, log),
        (err) => {
          assert.match(err.message, /these are this keyfile's own keys — use pair/);
          assert.match(err.message, new RegExp(`pasted ${kind} key matches`));
          return true;
        },
      );
      assert.equal(ask.asked.length, 0, "refused before asking");
      assert.deepEqual(relay.requests, [], "refused before contacting the relay");
      assertNothingChanged(relay, keyfilePath);
    });
  });
}

test("vouch refuses a state that would replace this keyfile's device, even with other keys (review-387 F1)", async () => {
  // Defence in depth behind the own-keys check: the state lists this keyfile's device id with the
  // phone's keys (not the keyfile's), so the pasted keys are not this keyfile's own, but composing
  // would still replace this keyfile's device. That is refused too.
  await withSetup(
    async ({ wasm, keyfilePath, phone, relay, log }) => {
      const ask = confirmer(true);
      await assert.rejects(
        () => runVouch(wasm, vouchOptions(keyfilePath, phone), ask, log),
        /lists for this keyfile's device dev-cli: vouching it would replace this keyfile's device.*Use pair/s,
      );
      assert.equal(ask.asked.length, 0, "refused before asking");
      assertNothingChanged(relay, keyfilePath);
    },
    (phone) => [registered(PHONE_DEVICE_ID, phone)],
    (_keyfile, phone) => [
      {
        device_id: CLI_DEVICE_ID,
        encryption_pubkey: phone.encryptionPubkey,
        signing_pubkey: phone.signingPubkey,
        status: "active",
      },
    ],
  );
});

test("vouch refuses a device carrying this keyfile's own keys under a stale id (review-387 F1)", async () => {
  // After a re-pair the state lists the CLI under its current id, but the relay still registers
  // the old id with the same keys. A browser set up from the keyfile before the re-pair shows that
  // old id. Vouching it would replace the CLI's own entry, so the CLI would stop decrypting.
  const STALE_ID = "dev-cli-before-repair";
  await withSetup(
    async ({ wasm, keyfilePath, keyfile, relay, log }) => {
      const ask = confirmer(true);
      await assert.rejects(
        () =>
          runVouch(
            wasm,
            {
              keyfilePath,
              deviceId: STALE_ID,
              encryptionPubkey: keyfile.device_encryption_pubkey,
              signingPubkey: keyfile.device_signing_pubkey,
            },
            ask,
            log,
          ),
        /these are this keyfile's own keys — use pair/,
      );
      assert.equal(ask.asked.length, 0, "refused before asking");
      assert.deepEqual(relay.requests, [], "refused before contacting the relay");
      assertNothingChanged(relay, keyfilePath);
      assert.deepEqual(
        relay.published().devices.map((d) => d.device_id),
        [CLI_DEVICE_ID, PHONE_DEVICE_ID],
        "the CLI's own entry is untouched",
      );
    },
    (phone, keyfile) => [
      registered(PHONE_DEVICE_ID, phone),
      registered(STALE_ID, { encryptionPubkey: keyfile.device_encryption_pubkey }, "browser"),
    ],
    (keyfile, phone) => [
      cliEntry(keyfile),
      {
        device_id: PHONE_DEVICE_ID,
        encryption_pubkey: phone.encryptionPubkey,
        signing_pubkey: phone.signingPubkey,
        status: "active",
      },
    ],
  );
});

test("vouch refuses a device id the relay never registered, before asking (#381)", async () => {
  await withSetup(
    async ({ wasm, keyfilePath, phone, relay, log }) => {
      const ask = confirmer(true);
      await assert.rejects(
        () => runVouch(wasm, vouchOptions(keyfilePath, phone), ask, log),
        /is not registered at the relay/,
      );
      assert.equal(ask.asked.length, 0);
      assertNothingChanged(relay, keyfilePath);
    },
    () => [],
  );
});

test("vouch refuses when the relay registered the id with a different encryption key (#381)", async () => {
  const decoy = deviceKeys(await loadWasm(), 66, 67);
  await withSetup(
    async ({ wasm, keyfilePath, phone, relay, log }) => {
      const ask = confirmer(true);
      await assert.rejects(
        () => runVouch(wasm, vouchOptions(keyfilePath, phone), ask, log),
        /registered device .* with a different encryption key/,
      );
      assert.equal(ask.asked.length, 0);
      assertNothingChanged(relay, keyfilePath);
    },
    () => [registered(PHONE_DEVICE_ID, decoy)],
  );
});

test("vouch refuses without an interactive terminal, before reading anything (#381)", async () => {
  await withSetup(async ({ wasm, keyfilePath, phone, relay, log }) => {
    const ask = confirmer(true, false);
    await assert.rejects(
      () => runVouch(wasm, vouchOptions(keyfilePath, phone), ask, log),
      /needs an interactive terminal/,
    );
    assert.equal(ask.asked.length, 0);
    assert.deepEqual(relay.requests, [], "the relay is never contacted");
    assertNothingChanged(relay, keyfilePath);
  });
});

test("vouch publishes nothing when the human declines (#381)", async () => {
  await withSetup(async ({ wasm, keyfilePath, phone, relay, log }) => {
    const ask = confirmer(false);
    await assert.rejects(
      () => runVouch(wasm, vouchOptions(keyfilePath, phone), ask, log),
      /not confirmed: nothing was signed or published/,
    );
    assert.equal(ask.asked.length, 1);
    assertNothingChanged(relay, keyfilePath);
  });
});

test("vouch refuses invalid pasted material before contacting the relay (#381)", async () => {
  await withSetup(async ({ wasm, keyfilePath, phone, relay, log }) => {
    const smallOrder = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for (const [options, message] of [
      [{ ...vouchOptions(keyfilePath, phone), encryptionPubkey: smallOrder }, /small-order/],
      [
        { ...vouchOptions(keyfilePath, phone), signingPubkey: `${phone.signingPubkey}=` },
        /signing key must be the canonical/,
      ],
      [vouchOptions(keyfilePath, phone, "dev\u001b[2J"), /device id must be/],
    ]) {
      await assert.rejects(() => runVouch(wasm, options, confirmer(true), log), message);
    }
    assert.deepEqual(relay.requests, [], "the relay is never contacted");
    assertNothingChanged(relay, keyfilePath);
  });
});

test("vouch refuses an id already listed with other keys, naming rotation as #199's job", async () => {
  await withSetup(
    async ({ wasm, keyfilePath, phone, relay, log }) => {
      // The CLI's own id, pasted with the phone's keys, and registered that way by the relay.
      const ask = confirmer(true);
      await assert.rejects(
        () => runVouch(wasm, vouchOptions(keyfilePath, phone, CLI_DEVICE_ID), ask, log),
        /already listed with different keys.*#199/,
      );
      assert.equal(ask.asked.length, 0, "refused before asking");
      assertNothingChanged(relay, keyfilePath);
    },
    (phone) => [registered(CLI_DEVICE_ID, phone)],
  );
});

test("vouch escapes the relay's label before showing it (#381)", async () => {
  await withSetup(
    async ({ wasm, keyfilePath, phone, lines, log }) => {
      await runVouch(wasm, vouchOptions(keyfilePath, phone), confirmer(true), log);
      const text = lines.join("\n");
      assert.ok(!text.includes("\u001b"), "no raw escape character reaches the terminal");
      assert.ok(!text.includes("\u202e"), "no raw bidi override reaches the terminal");
      assert.match(text, /relay label: +.*\\x1b/, "the escape is shown in core notation");
    },
    (phone) => [registered(PHONE_DEVICE_ID, phone, "phone\u001b[2J\u202eevil")],
  );
});

test("the vouch CLI refuses with exit 1 when stdin is not a terminal (#381)", async () => {
  const wasm = await loadWasm();
  const dir = mkdtempSync(join(tmpdir(), "allw-vouch-cli-"));
  try {
    const keyfilePath = join(dir, "keyfile.json");
    writeKeyfile(keyfilePath, generateKeyfile(wasm));
    const phone = deviceKeys(wasm);
    const result = spawnSync(
      process.execPath,
      [
        join(here, "..", "dist", "cli.js"),
        "vouch",
        "--keyfile",
        keyfilePath,
        "--device-id",
        PHONE_DEVICE_ID,
        "--encryption-pubkey",
        phone.encryptionPubkey,
        "--signing-pubkey",
        phone.signingPubkey,
      ],
      { input: "y\n", encoding: "utf8" },
    );
    assert.equal(result.status, 1);
    assert.match(result.stderr, /allw-approver: vouch needs an interactive terminal/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** @see ../../../docs/enrollment.md §Interim vouching (pasted public keys) */
test("vouch leading-dash public key: equals form reaches TTY refusal; space form fails closed", async () => {
  await withSetup(async ({ wasm, keyfilePath, relay }) => {
    // X25519 seed = 32 bytes of 101 gives a canonical public key beginning with '-'.
    const phone = deviceKeys(wasm, 101, 102);
    assert.equal(phone.encryptionPubkey, "-0Gx_PdcEif6CIdgVqXtB6xE_gwRbsLegLjlI5WdeCQ");
    assert.ok(phone.encryptionPubkey.startsWith("-"));
    const cli = join(here, "..", "dist", "cli.js");
    for (const equals of [true, false]) {
      const options = [
        ["device-id", PHONE_DEVICE_ID],
        ["encryption-pubkey", phone.encryptionPubkey],
        ["signing-pubkey", phone.signingPubkey],
      ].flatMap(([name, value]) => (equals ? [`--${name}=${value}`] : [`--${name}`, value]));
      const result = spawnSync(
        process.execPath,
        [cli, "vouch", "--keyfile", keyfilePath, ...options],
        {
          input: "y\n",
          encoding: "utf8",
        },
      );
      assert.equal(result.status, 1);
      assert.match(result.stderr, equals ? /vouch needs an interactive terminal/ : /ambiguous/);
      assertNothingChanged(relay, keyfilePath);
      assert.deepEqual(relay.requests, [], "neither refusal reaches the relay");
    }
  });
});
