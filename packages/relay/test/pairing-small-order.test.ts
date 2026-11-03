/**
 * `POST /{acct}/pairing/complete` refuses small-order X25519 device keys (#248).
 *
 * A device's `pubkey` is the X25519 key integrators JWE-encrypt every request to. For a
 * small-order point, X25519 with any scalar gives a publicly known shared secret, and the core's
 * `encrypt_context` refuses the whole request rather than encrypt to it. Rejecting the key at
 * enrollment keeps it out of the device registry, so it can never be listed as a recipient.
 *
 * The cases come from the core's shared vector (`x25519_small_order.json`, libsodium's
 * `has_small_order` list copied by hand). The Rust and WASM tests already assert it matches the
 * core's denylist, and this suite asserts the relay applies that same list through WASM. Each
 * point is also tried with bit 255 set, since X25519 masks it (RFC 7748 §5).
 *
 * @see https://www.rfc-editor.org/rfc/rfc7748#section-5
 * @see https://www.rfc-editor.org/rfc/rfc7748#section-6.1
 * @see ../../../crates/allw-core/tests/fixtures/x25519_small_order.json
 * @see ../../../docs/relay-api.md §3 Pairing (`POST /{acct}/pairing/complete`)
 */

import { exports } from "cloudflare:workers";
import { describe, it, expect, vi } from "vitest";
import * as glue from "@allw/sdk/vendor/allw-wasm/allw_wasm.js";
import smallOrderVectorText from "../../../crates/allw-core/tests/fixtures/x25519_small_order.json?raw";
import { pairingStartBody, testAccount } from "./support/accounts.js";
import { DEVICE_X25519_PUBKEY } from "./support/keys.js";

interface VectorEntry {
  readonly name: string;
  readonly hex: string;
  readonly b64url: string;
}

interface SmallOrderVector {
  readonly small_order: readonly VectorEntry[];
  readonly not_small_order: readonly VectorEntry[];
}

const VECTOR = JSON.parse(smallOrderVectorText) as SmallOrderVector;

/** The exact 400 body for a key that is not the canonical base64url encoding of 32 bytes. */
const SHAPE_ERROR = { error: "'pubkey' must be a base64url-unpadded 32-byte public key" };

/**
 * 43-symbol keys whose last symbol has one of its 2 unused low bits set. `atob` drops those bits,
 * so they decode to 32 bytes; the core's decoder rejects them ("Invalid last symbol").
 * - 32 × 0x00 (the zero point), last symbol `A` → `B`;
 * - the RFC 7748 Alice key ({@link DEVICE_X25519_PUBKEY}), last symbol `o` → `p`.
 */
const NON_CANONICAL_KEYS = [
  {
    label: "the zero point with a stray bit",
    pubkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
  },
  {
    label: "the Alice key with a stray bit",
    pubkey: "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmp",
  },
];

/** The exact 400 body for a small-order key. */
const SMALL_ORDER_ERROR = {
  error: "'pubkey' is a small-order X25519 key, which can never be an encryption target",
};

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return bytes;
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** The same u-coordinate with bit 255 (the top bit of the last byte) set. */
function withBit255Set(hex: string): string {
  const bytes = hexToBytes(hex);
  bytes[31] = (bytes[31] ?? 0) | 0x80;
  return b64url(bytes);
}

function url(accountId: string, subPath: string): string {
  return `https://relay.allw.test/${accountId}${subPath}`;
}

interface PairingStart {
  readonly code: string;
  readonly pairing_auth_token: string;
}

async function startPairing(accountId: string): Promise<PairingStart> {
  const resp = await exports.default.fetch(url(accountId, "/pairing/start"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(pairingStartBody(accountId)),
  });
  expect(resp.status).toBe(201);
  return await resp.json<PairingStart>();
}

async function completePairing(
  accountId: string,
  start: PairingStart,
  pubkey: string,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const resp = await exports.default.fetch(url(accountId, "/pairing/complete"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${start.pairing_auth_token}`,
    },
    body: JSON.stringify({ code: start.code, pubkey }),
  });
  return { status: resp.status, body: await resp.json<Record<string, unknown>>() };
}

async function listDevicePubkeys(accountId: string): Promise<string[]> {
  const resp = await exports.default.fetch(url(accountId, "/devices"));
  expect(resp.status).toBe(200);
  const body = await resp.json<{ devices: { pubkey: string }[] }>();
  return body.devices.map((device) => device.pubkey);
}

/** Every small-order case: each vector point as written, and with bit 255 set. */
const SMALL_ORDER_CASES = VECTOR.small_order.flatMap((entry) => [
  { label: entry.name, pubkey: entry.b64url },
  { label: `${entry.name}, bit 255 set`, pubkey: withBit255Set(entry.hex) },
]);

describe("pairing/complete — small-order X25519 device keys (#248)", () => {
  it("covers exactly the core's exported denylist", () => {
    // The relay must apply the core's list, not a copy. This pins the vector this suite
    // iterates to the denylist the relay's WASM binding actually holds.
    const corePoints = JSON.parse(glue.x25519_small_order_points()) as string[];
    expect(new Set(VECTOR.small_order.map((entry) => entry.b64url))).toEqual(new Set(corePoints));
    expect(corePoints).toHaveLength(7);
  });

  it.each(SMALL_ORDER_CASES)(
    "rejects $label with a 400, enrolling nothing and leaving the code usable",
    async ({ label, pubkey }) => {
      const accountId = testAccount(`acct-small-order-${label}`);
      const start = await startPairing(accountId);

      const rejected = await completePairing(accountId, start, pubkey);
      expect(rejected.status).toBe(400);
      expect(rejected.body).toEqual(SMALL_ORDER_ERROR);
      expect(await listDevicePubkeys(accountId)).toEqual([]);

      // The check runs before the code is looked up, so the same code still pairs a real key.
      const retried = await completePairing(accountId, start, DEVICE_X25519_PUBKEY);
      expect(retried.status).toBe(201);
      expect(await listDevicePubkeys(accountId)).toEqual([DEVICE_X25519_PUBKEY]);
    },
  );

  it.each(VECTOR.not_small_order)("accepts the near miss $name", async ({ name, b64url }) => {
    const accountId = testAccount(`acct-not-small-order-${name}`);
    const start = await startPairing(accountId);

    const accepted = await completePairing(accountId, start, b64url);
    expect(accepted.status).toBe(201);
    expect(await listDevicePubkeys(accountId)).toEqual([b64url]);
  });

  it("still rejects a key that is not 32 base64url bytes with the shape error", async () => {
    const accountId = testAccount("acct-small-order-bad-shape");
    const start = await startPairing(accountId);

    const rejected = await completePairing(accountId, start, "A".repeat(42));
    expect(rejected.status).toBe(400);
    expect(rejected.body).toEqual(SHAPE_ERROR);
  });
});

/**
 * Regression (#354 review): a non-canonical key passed `atob`, then the core's decoder threw, and
 * that throw was reported as a 500 "core unavailable" with an operator log line, reachable without
 * credentials. It is the caller's bad input: a 400.
 */
describe("pairing/complete — non-canonical base64url keys", () => {
  it.each(NON_CANONICAL_KEYS)(
    "rejects $label with the 400 shape error, no error log, and a usable code",
    async ({ label, pubkey }) => {
      const errors = vi.spyOn(console, "error");
      try {
        const accountId = testAccount(`acct-non-canonical-${label}`);
        const start = await startPairing(accountId);

        const rejected = await completePairing(accountId, start, pubkey);
        expect(rejected).toEqual({ status: 400, body: SHAPE_ERROR });
        expect(await listDevicePubkeys(accountId)).toEqual([]);
        expect(errors).not.toHaveBeenCalled();

        const retried = await completePairing(accountId, start, DEVICE_X25519_PUBKEY);
        expect(retried.status).toBe(201);
      } finally {
        errors.mockRestore();
      }
    },
  );

  it.each(NON_CANONICAL_KEYS)(
    "rejects $label with a 400 before auth or code lookup",
    async ({ label, pubkey }) => {
      const errors = vi.spyOn(console, "error");
      try {
        const accountId = testAccount(`acct-non-canonical-unauth-${label}`);
        await startPairing(accountId);

        const resp = await exports.default.fetch(url(accountId, "/pairing/complete"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code: "NO-SUCH-CODE", pubkey }),
        });
        expect({ status: resp.status, body: await resp.json() }).toEqual({
          status: 400,
          body: SHAPE_ERROR,
        });
        expect(errors).not.toHaveBeenCalled();
      } finally {
        errors.mockRestore();
      }
    },
  );
});

/** The same helper guards actor keys, which were stored verbatim with a 201 before. */
describe("POST /actors — non-canonical base64url keys", () => {
  it.each(NON_CANONICAL_KEYS)("rejects $label with a 400", async ({ label, pubkey }) => {
    const accountId = testAccount(`acct-actor-non-canonical-${label}`);
    const start = await startPairing(accountId);
    const paired = await completePairing(accountId, start, DEVICE_X25519_PUBKEY);
    expect(paired.status).toBe(201);
    const deviceToken = paired.body.device_auth_token;
    if (typeof deviceToken !== "string")
      throw new Error("pairing/complete returned no device token");

    const resp = await exports.default.fetch(url(accountId, "/actors"), {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${deviceToken}` },
      body: JSON.stringify({ actor_id: "actor-1", pubkey }),
    });
    expect({ status: resp.status, body: await resp.json() }).toEqual({
      status: 400,
      body: SHAPE_ERROR,
    });

    const listed = await exports.default.fetch(url(accountId, "/actors"));
    expect((await listed.json<{ actors: unknown[] }>()).actors).toEqual([]);
  });
});
