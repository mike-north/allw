/**
 * How `POST /pairing/complete` classifies a throw from the core's small-order check (#248).
 *
 * Only a core that failed to initialize (`CoreUnavailableError`) is the relay's fault: a 500 plus an
 * operator log line. Any other throw is the core rejecting the caller's key, which is a 400 with the
 * shape error and no log. The relay's canonical-encoding check normally stops such keys first, so
 * the core binding is mocked here to reach this branch directly.
 *
 * @see ../src/index.ts (`deviceEncryptionKeyFailure`)
 * @see ../../../docs/relay-api.md §3 Pairing (`POST /{acct}/pairing/complete`)
 */

import { exports } from "cloudflare:workers";
import { describe, it, expect, vi, afterEach } from "vitest";
import { pairingStartBody, testAccount } from "./support/accounts.js";
import { DEVICE_X25519_PUBKEY } from "./support/keys.js";

const smallOrderCheck = vi.hoisted(() => ({ throws: null as Error | null }));

vi.mock("../src/core.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/core.js")>();
  return {
    ...actual,
    isSmallOrderX25519PublicKey: (pubkey: string): boolean => {
      if (smallOrderCheck.throws) throw smallOrderCheck.throws;
      return actual.isSmallOrderX25519PublicKey(pubkey);
    },
  };
});

afterEach(() => {
  smallOrderCheck.throws = null;
  vi.restoreAllMocks();
});

async function completeWithFreshCode(name: string): Promise<{ status: number; body: unknown }> {
  const accountId = testAccount(name);
  const startResp = await exports.default.fetch(
    `https://relay.allw.test/${accountId}/pairing/start`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(pairingStartBody(accountId)),
    },
  );
  expect(startResp.status).toBe(201);
  const start = await startResp.json<{ code: string; pairing_auth_token: string }>();

  const resp = await exports.default.fetch(
    `https://relay.allw.test/${accountId}/pairing/complete`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${start.pairing_auth_token}`,
      },
      body: JSON.stringify({ code: start.code, pubkey: DEVICE_X25519_PUBKEY }),
    },
  );
  return { status: resp.status, body: await resp.json() };
}

describe("pairing/complete — core errors from the small-order check", () => {
  it("answers a core rejection of the key with the 400 shape error and no error log", async () => {
    const { CoreUnavailableError } = await import("../src/core.js");
    smallOrderCheck.throws = new Error("Invalid last symbol 66, offset 42.");
    expect(smallOrderCheck.throws).not.toBeInstanceOf(CoreUnavailableError);
    const errors = vi.spyOn(console, "error");

    expect(await completeWithFreshCode("acct-core-rejects-key")).toEqual({
      status: 400,
      body: { error: "'pubkey' must be a base64url-unpadded 32-byte public key" },
    });
    expect(errors).not.toHaveBeenCalled();
  });

  it("answers a core that failed to initialize with a 500 and an error log", async () => {
    const { CoreUnavailableError } = await import("../src/core.js");
    smallOrderCheck.throws = new CoreUnavailableError(new Error("simulated init failure"));
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const result = await completeWithFreshCode("acct-core-unavailable-on-key");
    expect(result.status).toBe(500);
    expect(result.body).toEqual({ error: "relay verification core unavailable" });
    expect(errors).toHaveBeenCalled();
  });
});
