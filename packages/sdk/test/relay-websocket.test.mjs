/** Browser-safe protocol builder. @see ../../../docs/relay-api.md §1 (exact offers and privacy). */
import assert from "node:assert/strict";
import test from "node:test";
import { relayWebSocketProtocols } from "@allw/sdk/relay-websocket";

test("offers only an application marker and a base64url bearer, with no token in validation errors", () => {
  assert.deepEqual(relayWebSocketProtocols("Abc_12-3"), ["allw.v1", "allw.auth.Abc_12-3"]);
  for (const token of [
    "",
    "secret private token",
    "private=token",
    "private,token",
    "private/token",
    "private\ntoken",
  ]) {
    assert.throws(() => relayWebSocketProtocols(token), {
      message: "allw: missing or malformed WebSocket credential",
    });
  }
});
