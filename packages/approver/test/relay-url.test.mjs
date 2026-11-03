/**
 * The approver CLI's relay-URL transport rule (#267), at every place a relay URL enters the CLI:
 * `pair --relay`, `watch --relay`, and the keyfile's `relay_url` (used by `watch` when no override
 * is given).
 *
 * A relay URL is accepted only if it is `https:`, or `http:` on `localhost` / `127.0.0.1` (not
 * `[::1]`, #277), with no username, password, query or fragment. Anything else is rejected before
 * any request is built: no fetch, no WebSocket, and for `pair`, no keyfile written either.
 *
 * Expected verdicts come from the shared vectors (`runtime` field), whose values are written from
 * the rule in `docs/web-approver-deploy.md` §2 and §3.1 and pinned for the SDK and web approver too,
 * so the CLI's copy of the rule cannot drift from theirs. Accepted vectors are proven to get as far
 * as the first network call, which a stub then refuses.
 *
 * @see https://github.com/mike-north/allw/issues/267
 * @see ../../../docs/threat-model.md (§Relay and Transport)
 * @see ../../sdk/test/fixtures/relay-url-vectors.json (shared with the SDK and the web approver)
 * @see ../src/lib/relay-url.ts (assertCliRelayUrl)
 */

import { afterEach, beforeEach, describe, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadWasm, runPair, runWatch } from "../dist/index.js";
import { generateKeyfile, writeKeyfile } from "../dist/lib/keyfile.js";
import { assertCliRelayUrl } from "../dist/lib/relay-url.js";

const { vectors } = JSON.parse(
  readFileSync(new URL("../../sdk/test/fixtures/relay-url-vectors.json", import.meta.url), "utf8"),
);

const wasm = await loadWasm();

/** Thrown by the network stubs: reaching one means the URL passed the check. */
class ReachedNetwork extends Error {}

/** Message prefix every rejection carries, naming its source (#267: "an actionable error"). */
const REJECTION = {
  "--relay": /^--relay '/,
  "keyfile relay_url": /^keyfile relay_url '/,
};

let dir;
let realFetch;
let fetchCalls;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "allw-relay-url-"));
  realFetch = globalThis.fetch;
  fetchCalls = [];
  globalThis.fetch = (input) => {
    fetchCalls.push(String(input));
    return Promise.reject(new ReachedNetwork(`fetch ${String(input)}`));
  };
});

afterEach(() => {
  globalThis.fetch = realFetch;
  rmSync(dir, { recursive: true, force: true });
});

/** A paired keyfile on disk whose stored relay is `relayUrl`. */
function writePairedKeyfile(relayUrl) {
  const fresh = generateKeyfile(wasm);
  const path = join(dir, "keyfile.json");
  writeKeyfile(path, {
    ...fresh,
    relay_url: relayUrl,
    account_id: wasm.account_id_for_root(fresh.account_root_pubkey),
    device_id: "dev-relay-url-267",
    device_auth_token: "device-token-267",
    device_cert: "cert.placeholder.267",
  });
  return path;
}

/**
 * Run `watch` with network access stubbed: `connect` records the URL and throws, so an accepted
 * URL ends at the socket and a rejected one never gets there.
 */
async function watchWith(keyfilePath, relayOverride) {
  const connected = [];
  const run = runWatch(
    wasm,
    { keyfilePath, ...(relayOverride !== undefined ? { relayUrl: relayOverride } : {}) },
    {
      connect: (url) => {
        connected.push(url);
        throw new ReachedNetwork(`connect ${url}`);
      },
      prompter: { decide: () => Promise.resolve(null) },
      log: { info() {}, warn() {} },
    },
  );
  return { run, connected };
}

describe("assertCliRelayUrl — shared vectors (#267)", () => {
  for (const { input, runtime, why } of vectors) {
    test(`${runtime}s ${JSON.stringify(input)} (${why})`, () => {
      if (runtime === "accept") {
        assert.doesNotThrow(() => assertCliRelayUrl(input, "--relay"));
      } else {
        assert.throws(() => assertCliRelayUrl(input, "--relay"), { message: REJECTION["--relay"] });
      }
    });
  }
});

describe("assertCliRelayUrl — actionable messages (#267)", () => {
  test("plaintext http to a remote host names the flag, the loopback exception and a fix", () => {
    assert.throws(() => assertCliRelayUrl("http://relay.example.com", "--relay"), {
      message:
        /^--relay 'http:\/\/relay\.example\.com' must use https:\/\/.*localhost or 127\.0\.0\.1.*--relay https:\/\//,
    });
  });

  test("a keyfile relay_url rejection says to re-pair or override", () => {
    assert.throws(() => assertCliRelayUrl("http://relay.example.com", "keyfile relay_url"), {
      message:
        /^keyfile relay_url 'http:\/\/relay\.example\.com' must use https:\/\/.*re-pair.*--relay/,
    });
  });

  test("http://[::1] points to 127.0.0.1", () => {
    assert.throws(() => assertCliRelayUrl("http://[::1]:8787", "--relay"), {
      message: /use 127\.0\.0\.1 rather than \[::1\]/,
    });
  });

  test("userinfo, query and fragment are each named", () => {
    for (const input of [
      "https://relay.example.com@evil.example",
      "https://relay.example.com?x=1",
      "https://relay.example.com#frag",
    ]) {
      assert.throws(() => assertCliRelayUrl(input, "--relay"), {
        message: /must not include a username, password, query \(\?\) or fragment \(#\)/,
      });
    }
  });

  test("a relative URL is called out as not absolute", () => {
    assert.throws(() => assertCliRelayUrl("relay.example.com", "--relay"), {
      message: /^--relay 'relay\.example\.com' is not an absolute URL/,
    });
  });
});

describe("pair --relay (#267)", () => {
  test("http://relay.example.com is refused before any request and before a keyfile is written", async () => {
    const keyfilePath = join(dir, "keyfile.json");
    await assert.rejects(
      runPair(wasm, { relayUrl: "http://relay.example.com", keyfilePath }, () => {}),
      { message: /^--relay 'http:\/\/relay\.example\.com' must use https:\/\// },
    );
    assert.deepEqual(fetchCalls, [], "no relay request is built");
    assert.equal(existsSync(keyfilePath), false, "a refused pair leaves no keyfile behind");
  });

  for (const { input, runtime, why } of vectors) {
    test(`${runtime}s ${JSON.stringify(input)} (${why})`, async () => {
      const keyfilePath = join(dir, "keyfile.json");
      const pairing = runPair(wasm, { relayUrl: input, keyfilePath }, () => {});
      if (runtime === "accept") {
        await assert.rejects(pairing, ReachedNetwork);
        assert.equal(fetchCalls.length, 1, "an accepted URL reaches pairing/start");
      } else {
        await assert.rejects(pairing, { message: REJECTION["--relay"] });
        assert.deepEqual(fetchCalls, []);
        assert.equal(existsSync(keyfilePath), false);
      }
    });
  }
});

describe("watch --relay override (#267)", () => {
  test("http://relay.example.com is refused before the socket or any fetch, even over a good keyfile URL", async () => {
    const keyfilePath = writePairedKeyfile("https://relay.example.com");
    const { run, connected } = await watchWith(keyfilePath, "http://relay.example.com");
    await assert.rejects(run, {
      message: /^--relay 'http:\/\/relay\.example\.com' must use https:\/\//,
    });
    assert.deepEqual(connected, [], "no presence socket is opened");
    assert.deepEqual(fetchCalls, [], "no account-state request is built");
  });

  for (const { input, runtime, why } of vectors) {
    test(`${runtime}s ${JSON.stringify(input)} (${why})`, async () => {
      const keyfilePath = writePairedKeyfile("https://relay.example.com");
      const { run, connected } = await watchWith(keyfilePath, input);
      if (runtime === "accept") {
        await assert.rejects(run, ReachedNetwork);
        assert.equal(connected.length, 1, "an accepted URL reaches the presence socket");
      } else {
        await assert.rejects(run, { message: REJECTION["--relay"] });
        assert.deepEqual(connected, []);
        assert.deepEqual(fetchCalls, []);
      }
    });
  }

  test("a valid --relay override is used even when the stored relay_url is plaintext", async () => {
    const keyfilePath = writePairedKeyfile("http://relay.example.com");
    const { run, connected } = await watchWith(keyfilePath, "https://relay.example.com");
    await assert.rejects(run, ReachedNetwork);
    assert.match(connected[0], /^wss:\/\/relay\.example\.com\//);
  });
});

describe("keyfile relay_url, used by watch (#267)", () => {
  test("a stored http://relay.example.com is refused before the socket or any fetch", async () => {
    const keyfilePath = writePairedKeyfile("http://relay.example.com");
    const { run, connected } = await watchWith(keyfilePath, undefined);
    await assert.rejects(run, {
      message: /^keyfile relay_url 'http:\/\/relay\.example\.com' must use https:\/\/.*re-pair/,
    });
    assert.deepEqual(connected, []);
    assert.deepEqual(fetchCalls, []);
  });

  for (const { input, runtime, why } of vectors) {
    test(`${runtime}s ${JSON.stringify(input)} (${why})`, async () => {
      const keyfilePath = writePairedKeyfile(input);
      const { run, connected } = await watchWith(keyfilePath, undefined);
      if (runtime === "accept") {
        await assert.rejects(run, ReachedNetwork);
        assert.equal(connected.length, 1);
      } else {
        await assert.rejects(run, { message: REJECTION["keyfile relay_url"] });
        assert.deepEqual(connected, []);
        assert.deepEqual(fetchCalls, []);
      }
    });
  }
});
