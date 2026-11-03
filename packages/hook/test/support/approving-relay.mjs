/**
 * A loopback relay double that answers every request with a **real, signed verdict**, for UATs that
 * drive the hook bin as a subprocess (stdin in, stdout out) end to end.
 *
 * It serves the integrator-facing relay routes over real HTTP on `127.0.0.1` (`docs/contract.md`
 * §Transport → Relay routing API): `GET /:acct/devices`, `POST /:acct/requests` and
 * `GET /:acct/requests/:id`. It has no WebSocket endpoint, so the SDK falls back to polling. On the
 * first poll it plays the approver with software-held keys (as `@allw/approver` does): it decrypts
 * the human-shown context, recomputes the WYSIWYS `request_hash`, and signs a verdict with the given
 * `decision` that the hook's SDK then verifies against the account-root key. Nothing is stubbed on
 * the hook side.
 *
 * The verdict's `decided_at` is the envelope's own `created_at`, which always lies inside the
 * request's validity window, so the double never reads a clock.
 *
 * @see ../integration.test.mjs (the same signing, as an in-process `fetchImpl` double)
 * @see ../../../../docs/contract.md §Transport, §Lifecycle
 */

import { createServer } from "node:http";

const DEVICE_ID = "dev_approving_relay";
/** A fixed issue time for the device cert (no expiry, so it is never the thing under test). */
const CERT_ISSUED_AT_MS = 1_700_000_000_000;

/**
 * Start the double. Resolves `{ url, accountId, accountRootPub, seen, close }`: point the hook at
 * `url` with `ALLW_ACCOUNT_ID = accountId` and `ALLW_APPROVER_ROOT_KEY = accountRootPub`. `seen`
 * counts the request submits and verdict fetches the double has served, so a test can prove the
 * hook actually went through the relay, and keeps each decrypted approval context (what the human
 * was shown) in `seen.contexts`.
 */
export async function startApprovingRelay({ wasm, decision }) {
  const accountSeed = Buffer.alloc(32, 11).toString("base64url");
  const deviceSigningSeed = Buffer.alloc(32, 22).toString("base64url");
  const deviceEncryptionSeed = Buffer.alloc(32, 33).toString("base64url");
  const accountRootPub = wasm.ed25519_public_key(accountSeed);
  // Accounts are self-certifying: the id is the core's derivation from the root key.
  const ACCOUNT_ID = wasm.account_id_for_root(accountRootPub);
  const cert = wasm.issue_device_cert(
    accountSeed,
    ACCOUNT_ID,
    DEVICE_ID,
    wasm.ed25519_public_key(deviceSigningSeed),
    CERT_ISSUED_AT_MS,
  );

  let envelope = null;
  const seen = { submits: 0, verdictFetches: 0, contexts: [] };
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const send = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const path = new URL(req.url, "http://127.0.0.1").pathname;

    if (req.method === "GET" && path.endsWith("/devices")) {
      return send(200, {
        devices: [
          {
            device_id: DEVICE_ID,
            pubkey: wasm.x25519_public_key(deviceEncryptionSeed),
            label: null,
            created_at: CERT_ISSUED_AT_MS,
          },
        ],
      });
    }
    if (req.method === "POST" && path.endsWith("/requests")) {
      envelope = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      seen.submits += 1;
      return send(202, {
        request_id: envelope.id,
        status: "pending",
        delivered_to: 1,
        request_auth_token: `token-${envelope.id}`,
      });
    }
    if (req.method === "GET" && /\/requests\/[^/]+$/.test(path) && envelope !== null) {
      seen.verdictFetches += 1;
      const contextJson = wasm.decrypt_context(
        envelope.context_ciphertext,
        DEVICE_ID,
        deviceEncryptionSeed,
      );
      seen.contexts.push(JSON.parse(contextJson));
      const unsigned = {
        v: envelope.v,
        request_id: envelope.id,
        request_hash: wasm.compute_request_hash(contextJson, envelope.expires_at),
        decision,
        decided_at: envelope.created_at,
        approver: { account_id: ACCOUNT_ID, device_id: DEVICE_ID },
      };
      const verdict = JSON.parse(
        wasm.sign_verdict(
          JSON.stringify(unsigned),
          deviceSigningSeed,
          Buffer.alloc(16, 7).toString("base64url"),
          cert,
        ),
      );
      return send(200, { status: "resolved", verdict });
    }
    return send(404, { error: "not found" });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    accountId: ACCOUNT_ID,
    accountRootPub,
    seen,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
