/**
 * `allw-approver watch` (alias `serve`) — open the device presence WebSocket and approve/deny
 * requests as they arrive (`docs/contract.md` §Transport → Device socket).
 *
 * Per inbound `{ type: "request" }`:
 *   decrypt → recompute `request_hash` (WYSIWYS) → render → prompt Approve/Deny → sign → send
 *   `{ type: "verdict", request_id, verdict }`.
 * On `{ type: "retract" }`: clear the pending prompt (another surface resolved it).
 *
 * # Fail-closed
 * A request that fails to decrypt/parse is reported and **skipped** — no verdict is emitted, so the
 * integrator's gate stays closed (deny-by-default). The approver only ever sends a verdict the WASM
 * core signed over the real human decision; it never fabricates an approval.
 */

import { createInterface, type Interface } from "node:readline/promises";

import { prepareRequest, signDecision, type RenderableRequest } from "../lib/approver-core.js";
import { readKeyfile, type Keyfile } from "../lib/keyfile.js";
import { deviceConnectWsUrl } from "../lib/relay-client.js";
import { renderRequest } from "../lib/render.js";
import type { AllwWasm } from "../lib/wasm.js";
import type { Decision, DeviceInboundMessage } from "../lib/types.js";

/** Options for `watch`. */
export interface WatchOptions {
  readonly keyfilePath: string;
  /** Override the paired relay URL (defaults to the keyfile's `relay_url`). */
  readonly relayUrl?: string;
}

/**
 * A minimal prompt abstraction so the decision loop is testable without a TTY. `decide` returns the
 * human's choice for a rendered request; `null` means "no decision" (e.g. retracted/aborted).
 */
export interface Prompter {
  /** Show the rendered block and return the decision (or null if none was made). */
  decide(rendered: string, prepared: RenderableRequest): Promise<Decision | null>;
  /** Optional cleanup (close the readline interface). */
  close?(): void;
}

/** A WebSocket-like surface (Node 24's global `WebSocket`, or a stub in tests). */
export interface WebSocketLike {
  send(data: string): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: "open" | "close", listener: () => void): void;
  addEventListener(type: "message", listener: (ev: { data: unknown }) => void): void;
  addEventListener(type: "error", listener: (ev: unknown) => void): void;
}

/** A logger sink (stdout/stderr by default; captured in tests). */
export interface WatchLogger {
  info(line: string): void;
  warn(line: string): void;
}

const defaultLogger: WatchLogger = {
  info: (line) => {
    console.log(line);
  },
  warn: (line) => {
    console.error(line);
  },
};

/** Parse a raw WS message payload into our typed inbound union; returns null if unrecognized. */
function parseInbound(data: unknown): DeviceInboundMessage | null {
  const text = typeof data === "string" ? data : new TextDecoder().decode(data as ArrayBuffer);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.type !== "string") return null;
  return obj as unknown as DeviceInboundMessage;
}

/**
 * Handle a single decrypted request: render, prompt, sign, and send the verdict. Isolated and
 * exported so tests can drive it directly with a stub socket/prompter. Returns the decision made
 * (or null when none was — fail-closed: no verdict sent).
 *
 * @throws never for a per-request decrypt/sign failure — those are caught, logged, and skipped so
 *   one bad request cannot take down the watch loop. (Programmer errors still surface.)
 */
export async function handleRequest(
  wasm: AllwWasm,
  keyfile: Keyfile,
  ws: WebSocketLike,
  prompter: Prompter,
  rawEnvelope: unknown,
  log: WatchLogger,
  now: () => number = Date.now,
): Promise<Decision | null> {
  let prepared: RenderableRequest;
  try {
    // Pass the current clock so prepareRequest can fail-closed on an already-expired request
    // (refused before the human is ever prompted).
    prepared = prepareRequest(wasm, keyfile, rawEnvelope, now());
  } catch (err) {
    // Fail-closed: a request we cannot decrypt/verify (or that is already expired) yields NO
    // verdict (the integrator's gate stays closed). The human is not prompted.
    log.warn(`Skipping request — could not decrypt/verify: ${(err as Error).message}`);
    return null;
  }

  const rendered = renderRequest(prepared);
  const decision = await prompter.decide(rendered, prepared);
  if (decision === null) {
    log.info(`No decision recorded for ${prepared.requestId} — leaving it pending.`);
    return null;
  }

  // Fail-closed re-check (long-idle prompt): a prompt may have sat open past the deadline while the
  // human deliberated. Re-read the clock AFTER the decision and BEFORE signing — a request that
  // expired during the prompt must emit nothing, never a stale-but-signed approval.
  if (prepared.expiresAt <= now()) {
    log.warn(
      `Request ${prepared.requestId} expired while awaiting a decision — discarding (fail-closed).`,
    );
    return null;
  }

  let verdict: unknown;
  try {
    verdict = signDecision(wasm, keyfile, prepared, decision, now());
  } catch (err) {
    // A signing failure must NOT emit a partial/forged verdict — abort this request.
    log.warn(`Failed to sign verdict for ${prepared.requestId}: ${(err as Error).message}`);
    return null;
  }

  ws.send(JSON.stringify({ type: "verdict", request_id: prepared.requestId, verdict }));
  log.info(`Sent ${decision} verdict for ${prepared.requestId}.`);
  return decision;
}

/** A readline-backed prompter for the interactive CLI. */
export function createReadlinePrompter(): Prompter {
  const rl: Interface = createInterface({ input: process.stdin, output: process.stdout });
  return {
    async decide(rendered: string): Promise<Decision | null> {
      console.log(rendered);
      const answer = (await rl.question("Approve / Deny / Skip? [a/d/s] ")).trim().toLowerCase();
      if (answer === "a" || answer === "approve") return "approved";
      if (answer === "d" || answer === "deny") return "denied";
      return null; // skip / anything else → no decision (fail-closed)
    },
    close(): void {
      rl.close();
    },
  };
}

/**
 * Run the watch loop: connect the presence socket and service requests until the socket closes.
 * Resolves when the connection ends. Pairing must have completed first (the keyfile carries the
 * relay/account/device + cert).
 */
export async function runWatch(
  wasm: AllwWasm,
  options: WatchOptions,
  deps: {
    connect: (url: string) => WebSocketLike;
    prompter: Prompter;
    log?: WatchLogger;
    now?: () => number;
  },
): Promise<void> {
  const log = deps.log ?? defaultLogger;
  const keyfile = readKeyfile(options.keyfilePath);

  const relayUrl = options.relayUrl ?? keyfile.relay_url;
  const accountId = keyfile.account_id;
  const deviceId = keyfile.device_id;
  if (relayUrl === undefined || accountId === undefined || deviceId === undefined) {
    throw new Error("keyfile is not paired — run 'allw-approver pair' first");
  }
  if (keyfile.device_cert === undefined || keyfile.device_cert.length === 0) {
    throw new Error("keyfile has no device_cert — re-pair to mint one before watching");
  }

  const url = deviceConnectWsUrl(relayUrl, accountId, deviceId);
  log.info(`Connecting to ${url} …`);
  // TODO(#41 v0): no reconnect/backoff — on close the loop simply exits (re-run `watch` to
  // reconnect). A resilient reconnect-with-backoff loop is out of scope for the v0 skeleton.
  const ws = deps.connect(url);

  // Serialize request handling: prompts are interactive, so process one at a time.
  let chain: Promise<unknown> = Promise.resolve();

  await new Promise<void>((resolve) => {
    ws.addEventListener("open", () => {
      log.info("Connected. Waiting for approval requests (Ctrl-C to exit).");
    });
    ws.addEventListener("message", (ev) => {
      const msg = parseInbound(ev.data);
      if (msg === null) {
        log.warn("Ignoring an unrecognized relay message.");
        return;
      }
      if (msg.type === "request") {
        chain = chain.then(() =>
          handleRequest(wasm, keyfile, ws, deps.prompter, msg.envelope, log, deps.now).catch(
            (err: unknown) => {
              log.warn(`Unexpected error handling a request: ${(err as Error).message}`);
            },
          ),
        );
      } else if (msg.type === "retract") {
        // TODO(#41 v0): a retract that arrives mid-prompt only logs — the human can still answer the
        // now-dead prompt, but the relay acks the late verdict `already_resolved` (first-verdict-
        // wins), so it is harmless. Aborting the active prompter on retract is a v0+ refinement.
        log.info(`Request ${msg.request_id} was retracted (resolved elsewhere).`);
      } else if (msg.type === "ack") {
        log.info(`Relay ack for ${msg.request_id}: ${msg.status}`);
      } else {
        // The only remaining inbound variant is `{ type: "error" }`.
        log.warn(`Relay error: ${msg.error}`);
      }
    });
    ws.addEventListener("error", (ev) => {
      log.warn(`WebSocket error: ${String((ev as { message?: unknown }).message ?? ev)}`);
    });
    ws.addEventListener("close", () => {
      log.info("Connection closed.");
      deps.prompter.close?.();
      resolve();
    });
  });
}
