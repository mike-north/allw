/**
 * The OpenClaw gateway operator client (`docs/openclaw-integration.md` §4).
 *
 * allw connects as its **own** gateway operator client — a separate `node` process holding exactly
 * `operator.approvals` — not as an in-gateway plugin, so the approval credentials never live in the
 * address space of the runtime they gate (§2).
 *
 * The rules this module exists to enforce, all of them fail-closed:
 *
 * - **`operator.approvals` and nothing else** (§4.1). Never `operator.admin` (it satisfies every
 *   `operator.*` scope and would let a compromised bridge rewrite the exec policy it enforces);
 *   never `operator.read` (that scope gates chat/agent/tool-result frames the bridge has no business
 *   seeing — the four approval broadcasts are registered under `operator.approvals` directly).
 * - **Pinned wire version** (§4.3). `minProtocol = maxProtocol = 4`. A mismatch is a startup
 *   failure, not a degraded mode: a bridge that cannot parse approval frames must not *appear* to be
 *   gating.
 * - **Advertise only what is implemented** (§4.3) — `approvals`, `exec-approvals`,
 *   `plugin-approvals`. Never `tool-events`; it opts the connection into live tool-execution
 *   streaming the bridge has no use for.
 * - **Listener before backfill** (§4.3). Handlers are registered on `hello-ok` *before*
 *   `*.approval.list` is called, and the backfill reconciles against live events **by approval id**,
 *   so a transition racing the backfill is neither lost nor resurrected.
 * - **Every reconnect is a fresh projection** (§4.3), not a delta.
 *
 * The transport is `@openclaw/gateway-client`, whose Node entry is pure JS (`ws` + `ipaddr.js`) and
 * adds no native addon — required by the WASM-under-`node` constraint (§10, `docs/architecture.md`).
 *
 * @see ../../../../docs/openclaw-integration.md §4, §10
 * @see https://docs.openclaw.ai/gateway/clients
 */

import { createPublicKey, createPrivateKey, sign as cryptoSign } from "node:crypto";

import { GatewayClient } from "@openclaw/gateway-client";
import { readPairingConnectErrorDetails } from "@openclaw/gateway-protocol/connect-error-details";

import type { BridgeConfig } from "./config.js";
import type { CredentialStore } from "./credential-store.js";
import type { Logger } from "./logging.js";
import {
  BRIDGE_CAPABILITIES,
  BRIDGE_SCOPES,
  PINNED_PROTOCOL_VERSION,
  APPROVAL_EVENTS,
} from "./protocol.js";

/** The role the bridge connects as. Paired device tokens are keyed by this. */
export const BRIDGE_ROLE = "operator";

/** One broadcast frame, narrowed to the two fields the bridge reads. */
export interface GatewayEvent {
  readonly event: string;
  readonly payload: unknown;
}

/**
 * The gateway surface the bridge depends on. Narrow by design: the bridge issues kind-agnostic
 * durable RPCs and listens for approval broadcasts — nothing else. Tests substitute a double for
 * this interface; `test/gateway.test.mjs` exercises the real implementation against a WebSocket
 * server speaking the real frame shapes.
 */
export interface ApprovalGateway {
  /** Issue one RPC. Rejects on a gateway error, a client timeout, or a closed connection. */
  request<T>(method: string, params?: unknown): Promise<T>;
  /** Register a broadcast listener. Returns an unsubscribe function. */
  addEventListener(listener: (event: GatewayEvent) => void): () => void;
  /** True while a `hello-ok` connection is live. */
  readonly connected: boolean;
}

/** Lifecycle hooks the bridge implements to run the listener-before-backfill projection. */
export interface GatewayLifecycle {
  /**
   * Called on every successful `hello-ok`, **after** the event listener is already installed.
   * Implementations re-backfill and re-reconcile from scratch (§4.3 "fresh projection").
   */
  onConnected(): void | Promise<void>;
  /** Called whenever the connection drops. */
  onDisconnected(code: number, reason: string): void;
}

/** A connectable gateway client bound to one gateway. */
export interface GatewayConnection extends ApprovalGateway {
  start(): void;
  stop(): Promise<void>;
}

/** Sign a device-auth payload with the stored Ed25519 key (base64url-unpadded, per the protocol). */
function signDevicePayload(privateKeyPem: string, payload: string): string {
  const key = createPrivateKey(privateKeyPem);
  return cryptoSign(null, Buffer.from(payload, "utf8"), key).toString("base64url");
}

/** Extract the raw 32-byte Ed25519 public key from an SPKI PEM as base64url-unpadded. */
function publicKeyRawBase64UrlFromPem(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  // An Ed25519 SPKI is a fixed 12-byte header followed by the 32-byte raw key.
  return Buffer.from(der.subarray(der.length - 32)).toString("base64url");
}

/**
 * Build the bridge's gateway connection.
 *
 * Pairing (§4.2) is surfaced, not automated: a structured `PAIRING_REQUIRED` connect failure is
 * logged with the request id the operator approves on the gateway host
 * (`openclaw devices approve <requestId>`). The device token that follows a successful pair is
 * persisted by {@link CredentialStore}, never by an env var or config file.
 */
export function createGatewayConnection(
  config: BridgeConfig,
  store: CredentialStore,
  logger: Logger,
  lifecycle: GatewayLifecycle,
): GatewayConnection {
  const identity = store.loadOrCreateDeviceIdentity();
  const listeners = new Set<(event: GatewayEvent) => void>();
  let connected = false;

  const client = new GatewayClient({
    url: config.gatewayUrl,
    role: BRIDGE_ROLE,
    // §4.1 — exactly one scope. `resolveGatewayConnectScopes` honours an explicit list verbatim, so
    // this never widens to the client library's `operator.admin` default.
    scopes: [...BRIDGE_SCOPES],
    caps: [...BRIDGE_CAPABILITIES],
    // §4.3 — operator clients negotiate the exact current version; no N-1 acceptance window.
    minProtocol: PINNED_PROTOCOL_VERSION,
    maxProtocol: PINNED_PROTOCOL_VERSION,
    deviceIdentity: identity,
    // The shared bootstrap credential is a bootstrap step only (§4.2): it is dropped as soon as a
    // device token exists, so the long-lived credential is always the paired device token.
    ...(config.bootstrapToken !== undefined
      ? { bootstrapToken: config.bootstrapToken, preferBootstrapToken: true }
      : {}),
    hostDeps: {
      loadOrCreateDeviceIdentity: () => identity,
      signDevicePayload,
      publicKeyRawBase64UrlFromPem,
      loadDeviceAuthToken: ({ role }) => {
        const record = store.loadDeviceToken(role);
        return record === null ? null : { token: record.token, scopes: [...record.scopes] };
      },
      storeDeviceAuthToken: ({ role, token, scopes }) => {
        store.storeDeviceToken(role, { token, scopes });
        logger.info("gateway.device-token-stored", { role, scopes: scopes.join(",") });
      },
      clearDeviceAuthToken: ({ role }) => {
        store.clearDeviceToken(role);
      },
      // The client library's debug/error strings can embed connect params; keep them off the
      // operator log entirely rather than trying to redact them field by field.
      logDebug: () => undefined,
      logError: () => undefined,
    },
    onEvent: (frame) => {
      const event: GatewayEvent = { event: frame.event, payload: frame.payload };
      for (const listener of listeners) listener(event);
    },
    onHelloOk: (hello) => {
      connected = true;
      const missing = APPROVAL_EVENTS.filter((name) => !hello.features.events.includes(name));
      if (missing.length > 0) {
        // Not fatal on its own — the gateway may name events differently across builds — but an
        // operator must see it, because a bridge subscribed to nothing looks identical to a bridge
        // with nothing to approve.
        logger.warn("gateway.missing-approval-events", { events: missing.join(",") });
      }
      logger.info("gateway.connected", { protocol: hello.protocol });
      void Promise.resolve(lifecycle.onConnected()).catch((err: unknown) => {
        logger.error("gateway.projection-failed", {
          message: err instanceof Error ? err.message : String(err),
        });
      });
    },
    onConnectError: (err) => {
      const pairing = readPairingConnectErrorDetails(
        (err as { details?: unknown }).details ?? undefined,
      );
      if (pairing !== null) {
        logger.error("gateway.pairing-required", {
          requestId: pairing.requestId ?? null,
          deviceId: identity.deviceId,
          hint: "approve on the gateway host: openclaw devices approve <requestId>",
        });
        return;
      }
      logger.error("gateway.connect-error", { message: err.message });
    },
    onClose: (code, reason) => {
      connected = false;
      lifecycle.onDisconnected(code, reason);
    },
  });

  return {
    get connected(): boolean {
      return connected;
    },
    request<T>(method: string, params?: unknown): Promise<T> {
      return client.request<T>(method, params);
    },
    addEventListener(listener: (event: GatewayEvent) => void): () => void {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    start(): void {
      client.start();
    },
    async stop(): Promise<void> {
      await client.stopAndWait({ timeoutMs: 2_000 });
    },
  };
}
