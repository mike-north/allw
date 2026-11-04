/**
 * If the audited core wasm cannot be instantiated, every core-backed route (`pairing/start`,
 * `POST account-states`) fails closed with a 500 and an operator log line — never a 4xx that blames
 * the caller's key, authorization or documents.
 *
 * The glue's `initSync` is mocked to throw, standing in for a bad build or runtime change.
 *
 * @see ../src/core.ts (`CoreUnavailableError`, `ensureCore`)
 */

import { exports } from "cloudflare:workers";
import { describe, it, expect, vi } from "vitest";

vi.mock("@allw/sdk/vendor/allw-wasm/allw_wasm.js", () => ({
  initSync: () => {
    throw new Error("simulated wasm instantiation failure");
  },
}));

describe("core unavailable", () => {
  it("pairing/start returns 500 and logs, without judging the request", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const resp = await exports.default.fetch("http://relay.test/some-account/pairing/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ root_pubkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }),
    });
    expect(resp.status).toBe(500);
    const body = await resp.json<{ error: string }>();
    expect(body.error).toMatch(/core unavailable/);
    expect(body.error).not.toMatch(/root_pubkey|Ed25519|derive/);
    expect(errors).toHaveBeenCalled();
    errors.mockRestore();
  });

  it("POST account-states returns 500 and logs, without judging the documents", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const resp = await exports.default.fetch("http://relay.test/some-account/account-states", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ account_states: ["eyJhbGciOiJFZERTQSJ9.eyJzIjoxfQ.sig"] }),
    });
    expect(resp.status).toBe(500);
    const body = await resp.json<{ error: string }>();
    expect(body.error).toMatch(/core unavailable/);
    expect(body.error).not.toMatch(/verify|account root/);
    expect(errors).toHaveBeenCalled();
    errors.mockRestore();
  });
});
