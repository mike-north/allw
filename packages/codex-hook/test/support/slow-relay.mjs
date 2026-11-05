/**
 * A loopback relay double for process-level hook tests that need the **poll** path to span more
 * than one poll interval.
 *
 * It serves the integrator-facing relay routes over real HTTP on `127.0.0.1` (`docs/contract.md`
 * §Transport → Relay routing API): `GET /:acct/account-states`, `POST /:acct/requests`, and
 * `GET /:acct/requests/:id`. It has no WebSocket endpoint, so the SDK's `…/wait` upgrade fails and
 * the SDK falls back to polling. A submitted request stays `pending` until `answerAfterMs` has
 * passed, then reads as the relay's terminal `expired`, which the hook maps to a deny. It serves
 * the root-signed account states it is given and never signs or decrypts anything itself.
 *
 * Kept in sync with the copy in `packages/hook/test/support/slow-relay.mjs`.
 *
 * @see ../../../../docs/contract.md §Transport (relay routing API)
 */

import { createServer } from "node:http";

/**
 * Start the double. `accountStates` are root-signed account-state documents naming the device the
 * SDK encrypts to. Resolves `{ url, polls, close }`; `polls()` counts status polls received.
 */
export async function startSlowRelay({ accountStates, answerAfterMs }) {
  let submittedAt = null;
  let polls = 0;
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const send = (status, body) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const path = new URL(req.url, "http://127.0.0.1").pathname;
    if (req.method === "GET" && path.endsWith("/account-states")) {
      return send(200, { account_states: accountStates, max_sequence: accountStates.length });
    }
    if (req.method === "POST" && path.endsWith("/requests")) {
      const { id } = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      submittedAt = Date.now();
      return send(202, {
        request_id: id,
        status: "pending",
        delivered_to: 1,
        request_auth_token: "token-slow",
      });
    }
    const poll = /\/requests\/([^/]+)$/.exec(path);
    if (req.method === "GET" && poll) {
      polls += 1;
      const answered = submittedAt !== null && Date.now() - submittedAt >= answerAfterMs;
      return send(200, { request_id: poll[1], status: answered ? "expired" : "pending" });
    }
    return send(404, { error: "not found" });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    polls: () => polls,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
