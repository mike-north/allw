/**
 * `@allw/approver` — the v0 stand-in approver (the "second device") for the allw walking skeleton.
 *
 * A minimal Node CLI that pairs with the relay, receives encrypted approval requests over the
 * device presence WebSocket, renders them WYSIWYS, and returns a correctly-signed verdict — all
 * cryptography delegated to the audited Rust core via WASM (`docs/contract.md`, `docs/architecture.md`).
 *
 * # ⚠ v0 stand-in
 * Device keys are held **in software** (a local keyfile). This is a deliberate stand-in to unblock
 * the first end-to-end proof; production custody is hardware-backed (Secure Enclave / StrongBox)
 * and is tracked by **#23**. The wire protocol does not depend on key custody, so #23 swaps in with
 * no protocol change.
 *
 * This module re-exports the programmatic surface (used by the CLI and the tests).
 */

export type { AllwWasm } from "./lib/wasm.js";
export { loadWasm } from "./lib/wasm.js";

export type {
  ActionRecord,
  Actor,
  ApprovalContext,
  ApprovalRequest,
  Approver,
  Constraints,
  Decision,
  DeviceInboundMessage,
  Risk,
  Surface,
  SyntacticSubstrate,
  UnsignedVerdict,
  VerdictOutboundMessage,
} from "./lib/types.js";

export type { Keyfile, FreshKeyfile } from "./lib/keyfile.js";
export {
  KEYFILE_VERSION,
  generateKeyfile,
  readKeyfile,
  validateKeyfile,
  writeKeyfile,
} from "./lib/keyfile.js";

export { defaultKeyfilePath } from "./lib/paths.js";

export type { RenderableRequest } from "./lib/approver-core.js";
export { generateNonce, prepareRequest, signDecision } from "./lib/approver-core.js";
export { renderRequest } from "./lib/render.js";

export {
  deviceConnectWsUrl,
  pairingComplete,
  pairingStart,
  type PairingStartResult,
} from "./lib/relay-client.js";

export { runPair, type PairOptions, type Logger } from "./commands/pair.js";
export { runKeygen, type KeygenOptions } from "./commands/keygen.js";
export {
  createReadlinePrompter,
  handleRequest,
  runWatch,
  type Prompter,
  type WatchOptions,
  type WatchLogger,
  type WebSocketLike,
} from "./commands/watch.js";
