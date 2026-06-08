/**
 * `@allw/relay` — zero-knowledge approval relay.
 *
 * Routes ciphertext + signed verdicts between integrators and a user's devices; never
 * decrypts. One Durable Object per account coordinates device presence, push fan-out, and
 * cross-device retraction/dedupe. See `../../docs/architecture.md`. **Status: skeleton.**
 */

export interface Env {
  readonly ACCOUNT: DurableObjectNamespace;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    // Route by account id → its Durable Object.
    const accountId = url.pathname.split("/")[1] ?? "";
    if (!accountId) return new Response("missing account", { status: 400 });
    const stub = env.ACCOUNT.get(env.ACCOUNT.idFromName(accountId));
    return stub.fetch(request);
  },
} satisfies ExportedHandler<Env>;

/** Per-account relay: device registry, pending-approval routing, fan-out + retract + dedupe. */
export class AccountRelay {
  // TODO: capture (DurableObjectState, Env) in the constructor once they're used.
  fetch(_request: Request): Response {
    // TODO: device pairing, WebSocket presence, ciphertext routing, push fan-out,
    // verdict relay, cross-device retraction/dedupe.
    return new Response("not implemented", { status: 501 });
  }
}
