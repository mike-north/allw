/**
 * Consumer test: `RelayTimeoutError` is part of `@allw/sdk`'s public API, because
 * `relayAccountStateSource().load()` rejects with it when the account-state fetch hangs. Imports the
 * bare package specifier (resolved through `package.json#exports`, as an installed consumer would)
 * and narrows the rejection with `instanceof`, which only works if the class a consumer imports is
 * the one the SDK throws.
 *
 * @see ../README.md §Who can read a request: account state
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { fileSequenceFloorStore, RelayTimeoutError, relayAccountStateSource } from "@allw/sdk";

const ACCOUNT_ID = "A".repeat(43);

test("a hung account-state fetch: load() rejects with an instanceof-narrowable RelayTimeoutError", async () => {
  assert.equal(typeof RelayTimeoutError, "function", "exported from the package entry point");
  const dir = mkdtempSync(join(tmpdir(), "allw-relay-timeout-"));
  const source = relayAccountStateSource({
    relayUrl: "https://relay.example.com",
    accountId: ACCOUNT_ID,
    floorStore: fileSequenceFloorStore({ accountId: ACCOUNT_ID, dir }),
    // A relay that accepts the connection and never answers; it only honours the abort.
    fetchImpl: (_url, init = {}) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      }),
    fetchTimeoutMs: 20,
  });

  await assert.rejects(
    () => source.load(),
    (err) => {
      assert.ok(err instanceof RelayTimeoutError, `expected RelayTimeoutError, got ${String(err)}`);
      assert.ok(err instanceof Error);
      assert.equal(err.name, "RelayTimeoutError");
      return true;
    },
  );
});
