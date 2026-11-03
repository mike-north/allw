/**
 * Tests for the SDK's relay-URL transport rule (issue #249): `createClient` accepts a relay URL
 * only if it is `https:`, or `http:` on a loopback host (`localhost`, `127.0.0.1`, `[::1]`).
 * Anything else is rejected at configuration time — before any request is built — so bearer
 * tokens and approval ciphertext never travel over plaintext HTTP to a remote host, where an
 * on-path attacker could do anything a malicious relay can.
 *
 * Construction never touches the network or WASM, so these tests run without the vendored WASM.
 *
 * @see https://github.com/mike-north/allw/issues/249
 * @see ../../../docs/threat-model.md (§Relay and Transport)
 * @see ../src/relay.ts (assertRelayUrlTransport)
 */

import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { createClient } from "../dist/index.js";

/** A fetch that fails the test if called: construction must never reach the network. */
function forbiddenFetch() {
  throw new Error("createClient must not issue a request at configuration time");
}

/** Build a client for `relayUrl` with no network or WebSocket access. */
function clientFor(relayUrl) {
  return createClient({
    relayUrl,
    accountId: "acct_transport_249",
    fetchImpl: forbiddenFetch,
    webSocketFactory: undefined,
  });
}

describe("createClient relay-URL transport rule (#249)", () => {
  test("rejects plaintext http:// to a remote relay host with an actionable error", () => {
    assert.throws(() => clientFor("http://relay.example.com"), {
      message: /must use https:\/\/.*localhost, 127\.0\.0\.1, or \[::1\]/,
    });
  });

  test("rejects a non-http(s) scheme", () => {
    assert.throws(() => clientFor("ftp://relay.example.com"), { message: /must use https:\/\// });
  });

  test("rejects a ws:// relay URL (the WebSocket form is derived, never configured)", () => {
    assert.throws(() => clientFor("ws://relay.example.com"), { message: /must use https:\/\// });
  });

  test("rejects plaintext http:// to a host that merely contains 'localhost'", () => {
    assert.throws(() => clientFor("http://localhost.evil.example"), {
      message: /must use https:\/\//,
    });
  });

  test("rejects a relative / unparseable relay URL", () => {
    assert.throws(() => clientFor("relay.example.com"), { message: /not an absolute URL/ });
  });

  test("accepts an https:// relay", () => {
    assert.doesNotThrow(() => clientFor("https://relay.example.com"));
  });

  for (const loopback of ["http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787"]) {
    test(`accepts plaintext http:// on loopback (${loopback}) for local development`, () => {
      assert.doesNotThrow(() => clientFor(loopback));
    });
  }
});
