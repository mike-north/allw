/** Browser-safe credential transport for relay sockets; no crypto, storage or Node dependencies. */

/**
 * Offer the application marker and a separate bearer capability (base64url). Only `allw.v1` may
 * be selected by the relay: reflecting the credential would expose it in handshake diagnostics.
 * HTTP uses Authorization instead. Never log this list or an exception supplied by a connector.
 * @public
 * @see ../../../docs/relay-api.md §1
 */
export function relayWebSocketProtocols(token: string): string[] {
  if (!/^[A-Za-z0-9_-]+$/.test(token)) {
    throw new Error("allw: missing or malformed WebSocket credential");
  }
  return ["allw.v1", `allw.auth.${token}`];
}
