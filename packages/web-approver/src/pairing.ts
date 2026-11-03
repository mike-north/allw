/**
 * Login / pairing-ceremony entry gate for the web approver (issue #148, #93).
 *
 * This module provides the `PairingStore` — a thin persistence seam over `localStorage` — and
 * `mountPairingGate`, which renders the appropriate pre-inbox screen and hands control to the inbox
 * only after a valid, persisted {@link ApproverIdentity} is confirmed.
 *
 * # Three pre-inbox routes (design/web-approver/onboarding/flow-notes.md)
 *
 * 1. **Returning device** — `localStorage` already has a stored identity; a lightweight re-auth
 *    confirmation unlocks the inbox (the local key was already established at pairing). If the
 *    stored identity cannot be parsed it is discarded and the user is routed to pairing.
 *
 * 2. **Device pairing** — no stored identity; user enters the CLI-issued pairing code plus the
 *    relay-returned device credentials. The gate validates the submitted fields (non-empty, required
 *    structure) and, on success, persists the identity and routes to the inbox.
 *
 * 3. **Pairing error** — validation or relay rejection; the form stays up with a visible error
 *    message. The inbox is never rendered.
 *
 * # Fail-closed invariant (`docs/contract.md` §Invariants #6)
 *
 * An unpaired or failed-pairing state MUST NEVER reach the approve-capable inbox. This is
 * structural: `mountPairingGate` invokes `onPaired` only after a valid `ApproverIdentity` is
 * confirmed; the inbox `mountWebApprover` must not be called before that callback fires.
 *
 * # Storage-security tradeoff (docs/enrollment.md §Device Enrollment)
 *
 * The device seeds are stored in `localStorage` as base64url strings. This is the same tradeoff
 * the v0 walking-skeleton device keyfile makes: **software-held seeds in browser storage**. Hardware
 * custody (#23) and secure-enclave key management are tracked as future work; that swap changes
 * only the storage layer (the wire protocol and relay model remain unchanged). Callers that provide
 * a custom `PairingStore` can implement hardened storage immediately.
 *
 * @see design/web-approver/onboarding/flow-notes.md (flow design)
 * @see design/web-approver/onboarding/app.jsx (visual source of truth)
 * @see design/web-approver/inbox/tokens.css (verbatim token source)
 * @see docs/enrollment.md §Pairing Flow, §Device Enrollment
 * @see docs/contract.md §Invariants #6 (fail-closed)
 */

import { checkRelayUrl } from "./relay-config.js";
import type { ApproverIdentity } from "./runtime.js";

/**
 * The identity the pairing store persists: the runtime's {@link ApproverIdentity} plus the relay
 * it was paired against (#249).
 *
 * The relay is **pinned at pairing**: every relay call a paired browser makes goes to
 * `relayUrl`, and a later `?relay=` link cannot move it (`./relay-config.ts`,
 * `docs/web-approver-deploy.md` §Relay pinning). Without the pin a phishing link could re-point a
 * paired device and collect its bearer `deviceAuthToken`.
 */
export interface PairedIdentity extends ApproverIdentity {
  /**
   * The canonical relay URL this identity was paired against (https, or http on loopback —
   * `checkRelayUrl`). Absent only for an identity stored before pinning existed or paired through a
   * relay-less harness (`mountWebApprover` without `relay`); the production boot (`./app.ts`)
   * binds such an identity to the already-persisted relay — never to a `?relay=` link — before any
   * relay call.
   */
  readonly relayUrl?: string;
}

// ── PairingStore ─────────────────────────────────────────────────────────────────────────────────

/** The localStorage key under which the serialized identity is persisted. */
const STORAGE_KEY = "allw:pairing:v1";

/**
 * The subset of the `ApproverIdentity` the gate persists. All fields are required; the store
 * rejects any stored value missing a required string — fail-closed.
 */
const REQUIRED_IDENTITY_FIELDS: readonly (keyof ApproverIdentity)[] = [
  "accountId",
  "deviceId",
  "deviceEncryptionSeed",
  "deviceSigningSeed",
  "deviceCert",
  "accountRootPubkey",
  "deviceAuthToken",
];

/**
 * Narrow a parsed JSON value to a {@link PairedIdentity}. Returns `null` on any structural failure,
 * including a present-but-invalid pinned `relayUrl` (a tampered or insecure pin is treated as a
 * corrupt identity — fail-closed — never silently dropped, which would un-pin the device).
 */
function parseIdentity(value: unknown): PairedIdentity | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  for (const field of REQUIRED_IDENTITY_FIELDS) {
    const fieldValue = record[field];
    if (typeof fieldValue !== "string" || fieldValue.length === 0) return null;
  }
  const relayUrl = record.relayUrl;
  if (relayUrl !== undefined) {
    if (typeof relayUrl !== "string") return null;
    const checked = checkRelayUrl(relayUrl);
    if (!checked.ok || checked.relayUrl !== relayUrl) return null;
  }
  return record as unknown as PairedIdentity;
}

/**
 * Injectable storage seam for the paired-device identity.
 *
 * The default implementation persists to `localStorage` under the key `allw:pairing:v1`. A custom
 * implementation may use `sessionStorage`, IndexedDB, or an in-memory store (test / SSR scenarios
 * where `localStorage` is unavailable).
 *
 * # ⚠ Security tradeoff
 * Seeds stored in `localStorage` are accessible to any JavaScript on the origin. This mirrors the
 * v0 device keyfile's posture (software-held seeds) and is the deliberate v1 stand-in pending
 * hardware key custody (#23). Callers that need stronger isolation should provide a custom
 * implementation backed by IndexedDB + the WebCrypto non-extractable key API.
 */
export interface PairingStore {
  /** Load the persisted identity. Returns `null` when not yet paired or the stored value is corrupt. */
  load(): PairedIdentity | null;
  /** Persist a new identity (replaces any existing stored value). */
  save(identity: PairedIdentity): void;
  /** Remove the stored identity (used for "sign out" / reset flows). */
  clear(): void;
}

/**
 * Build a `PairingStore` backed by `localStorage`. Pass `storage` to inject a custom
 * `Storage`-compatible object (useful in tests via a plain `Map`-backed fake).
 */
export function createLocalPairingStore(storage?: Storage): PairingStore {
  const store: Storage = storage ?? localStorage;
  return {
    load() {
      try {
        const raw = store.getItem(STORAGE_KEY);
        if (raw === null) return null;
        return parseIdentity(JSON.parse(raw));
      } catch {
        return null;
      }
    },
    save(identity: PairedIdentity) {
      store.setItem(STORAGE_KEY, JSON.stringify(identity));
    },
    clear() {
      store.removeItem(STORAGE_KEY);
    },
  };
}

// ── Form field validation ─────────────────────────────────────────────────────────────────────────

/** Validate a submitted pairing form's fields. Returns an error message or null on success. */
function validatePairingFields(fields: Record<string, string>): string | null {
  for (const field of REQUIRED_IDENTITY_FIELDS) {
    if (!fields[field] || fields[field].trim().length === 0) {
      return `Missing required field: ${field}`;
    }
  }
  const identity = parseIdentity(fields);
  if (identity === null) {
    return "All fields must be non-empty strings";
  }
  return null;
}

// ── DOM helpers ──────────────────────────────────────────────────────────────────────────────────

function el<Tag extends keyof HTMLElementTagNameMap>(
  tag: Tag,
  className?: string,
): HTMLElementTagNameMap[Tag] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  return element;
}

function text<Tag extends keyof HTMLElementTagNameMap>(
  tag: Tag,
  content: string,
  className?: string,
): HTMLElementTagNameMap[Tag] {
  const element = el(tag, className);
  element.textContent = content;
  return element;
}

/** A labeled input row used in the pairing form. Returns `{ row, input }`. */
function labeledInput(
  labelText: string,
  inputName: string,
  placeholder: string,
  inputType = "text",
): { row: HTMLElement; input: HTMLInputElement } {
  const row = el("div", "pairing-field");
  const labelEl = text("label", labelText, "pairing-label");
  labelEl.htmlFor = inputName;
  const input = el("input", "pairing-input");
  input.type = inputType;
  input.name = inputName;
  input.id = inputName;
  input.placeholder = placeholder;
  input.autocomplete = "off";
  input.spellcheck = false;
  row.append(labelEl, input);
  return { row, input };
}

// ── Screen renderers ──────────────────────────────────────────────────────────────────────────────

/**
 * Render the returning-device login screen (identity already stored; human re-auth confirmation).
 * The screen shows the stored device id so the user can confirm it is theirs, then offers "Unlock
 * inbox" (proceed) or "Use another device" (clear stored identity and go to pairing).
 */
function renderReturningScreen(
  root: HTMLElement,
  identity: PairedIdentity,
  onUnlock: () => void,
  onReset: () => void,
): void {
  root.replaceChildren();

  const shell = el("div", "pairing-shell");

  const header = el("header", "pairing-header");
  header.append(text("h1", "allw approvals", "pairing-wordmark"));
  shell.append(header);

  const screen = el("section", "pairing-screen");
  screen.setAttribute("aria-labelledby", "pairing-title");

  const kicker = el("div", "pairing-kicker");
  kicker.textContent = "Already paired";
  screen.append(kicker);

  screen.append(text("h2", "Already paired.", "pairing-headline"));
  screen.append(
    text(
      "p",
      "The browser recognizes its local device key. Confirm you are present to unlock the inbox.",
      "pairing-subcopy",
    ),
  );

  // Device ticket (mirrors design/web-approver/onboarding/app.jsx ReturningDevice)
  const ticket = el("div", "pairing-device-ticket");
  const ticketInfo = el("div");
  ticketInfo.append(text("div", "Paired browser", "pairing-device-title"));
  ticketInfo.append(
    text("div", `${identity.deviceId} · ${identity.accountId}`, "pairing-device-meta"),
  );
  const pill = text("span", "verified", "pairing-status-pill");
  ticket.append(ticketInfo, pill);
  screen.append(ticket);

  // Evidence checklist
  const evidence = el("ul", "pairing-evidence");
  for (const item of [
    "Local key found — no password reset loop.",
    "Account root anchored. Origin checks use root-signed state.",
    "Human presence confirmation required before signing.",
  ]) {
    const li = el("li", "pairing-evidence-item");
    li.append(text("span", "✓", "pairing-check"), text("span", item));
    evidence.append(li);
  }
  screen.append(evidence);

  // Actions
  const actions = el("div", "pairing-actions");

  const unlockBtn = el("button", "pairing-btn pairing-btn--primary");
  unlockBtn.type = "button";
  unlockBtn.textContent = "Unlock inbox";
  unlockBtn.addEventListener("click", onUnlock);

  const resetBtn = el("button", "pairing-btn pairing-btn--secondary");
  resetBtn.type = "button";
  resetBtn.textContent = "Use another device";
  resetBtn.addEventListener("click", onReset);

  actions.append(unlockBtn, resetBtn);
  screen.append(actions);
  shell.append(screen);
  root.append(shell);
}

/**
 * Render the pairing-ceremony screen (no stored identity; user enters the relay-issued credentials
 * from the CLI `allw pair` output). On successful validation the identity is persisted and
 * `onPaired` is called.
 *
 * The form collects all seven fields required by `ApproverIdentity`; this mirrors the dev-mode
 * credential-stub path described in the issue scope. In production the fields would be
 * pre-populated by a QR/deep-link containing the CLI pairing ceremony output.
 *
 * @param errorMessage - If non-null, renders as a visible error banner above the form.
 */
function renderPairingScreen(
  root: HTMLElement,
  relayUrl: string | undefined,
  onPaired: (identity: ApproverIdentity) => void,
  errorMessage: string | null = null,
): void {
  root.replaceChildren();

  const shell = el("div", "pairing-shell");

  const header = el("header", "pairing-header");
  header.append(text("h1", "allw approvals", "pairing-wordmark"));
  shell.append(header);

  const screen = el("section", "pairing-screen");
  screen.setAttribute("aria-labelledby", "pairing-title");

  const kicker = el("div", "pairing-kicker");
  kicker.textContent = "Device pairing ceremony";
  screen.append(kicker);

  screen.append(text("h2", "Trust this browser.", "pairing-headline"));
  screen.append(
    text(
      "p",
      "Enter the device credentials from the CLI pairing output. This grants the browser permission to decrypt pending requests and sign verdicts for this account.",
      "pairing-subcopy",
    ),
  );

  // Trust checklist (mirrors design/web-approver/onboarding/app.jsx PairDevice)
  const trustList = el("ul", "pairing-trust-list");
  for (const item of [
    "Device key is created locally before pairing.",
    "Relay receives public key material and routing metadata only.",
    "Approval context remains end-to-end encrypted.",
  ]) {
    const li = el("li", "pairing-trust-item");
    li.append(text("span", "✓", "pairing-check"), text("span", item));
    trustList.append(li);
  }
  screen.append(trustList);

  // The relay this pairing will pin (#249) — shown before the human commits, because a `?relay=`
  // link may have pre-filled it and, once paired, it cannot be changed by a link.
  if (relayUrl !== undefined) {
    const relayRow = el("div", "pairing-relay");
    relayRow.append(text("span", "Relay", "pairing-relay-label"));
    relayRow.append(text("code", relayUrl, "pairing-relay-url"));
    relayRow.append(
      text(
        "p",
        "This browser will only ever talk to this relay. Pair only if your operator gave you this address.",
        "pairing-relay-note",
      ),
    );
    screen.append(relayRow);
  }

  // Error banner (fail-closed: shown when previous submission failed validation)
  if (errorMessage !== null) {
    const banner = el("div", "pairing-error-banner");
    banner.setAttribute("role", "alert");
    banner.textContent = errorMessage;
    screen.append(banner);
  }

  // Pairing form
  const form = el("form", "pairing-form");
  form.setAttribute("aria-label", "Device pairing credentials");
  form.noValidate = true;

  const fields: Record<keyof ApproverIdentity, { label: string; placeholder: string }> = {
    accountId: { label: "Account ID", placeholder: "acct_…" },
    deviceId: { label: "Device ID", placeholder: "dev_…" },
    deviceEncryptionSeed: {
      label: "Device encryption seed (base64url)",
      placeholder: "X25519 seed",
    },
    deviceSigningSeed: { label: "Device signing seed (base64url)", placeholder: "Ed25519 seed" },
    deviceCert: { label: "Device certificate (compact JWS)", placeholder: "eyJ…" },
    accountRootPubkey: {
      label: "Account root public key (base64url)",
      placeholder: "Ed25519 pubkey",
    },
    deviceAuthToken: {
      label: "Device auth token (relay bearer)",
      placeholder: "relay-issued bearer token",
    },
  };

  for (const [name, { label, placeholder }] of Object.entries(fields)) {
    const { row } = labeledInput(label, name, placeholder);
    form.append(row);
  }

  const submitBtn = el("button", "pairing-btn pairing-btn--primary");
  submitBtn.type = "submit";
  submitBtn.textContent = "Pair browser";

  const submitRow = el("div", "pairing-submit-row");
  submitRow.append(submitBtn);
  form.append(submitRow);

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const fields: Record<string, string> = {};
    for (const [key, value] of data.entries()) {
      if (typeof value === "string") {
        fields[key] = value.trim();
      }
    }

    const validationError = validatePairingFields(fields);
    if (validationError !== null) {
      // Re-render the screen with the validation error visible (fail-closed: no inbox on error).
      renderPairingScreen(root, relayUrl, onPaired, validationError);
      return;
    }

    const identity = parseIdentity(fields);
    if (identity === null) {
      // Should be unreachable after validation but guarded for defensive fail-closed.
      renderPairingScreen(root, relayUrl, onPaired, "Invalid credential format — please re-enter.");
      return;
    }

    onPaired(identity);
  });

  screen.append(form);
  shell.append(screen);
  root.append(shell);
}

// ── Gate entry point ──────────────────────────────────────────────────────────────────────────────

/**
 * Options for {@link mountPairingGate}.
 */
export interface PairingGateOptions {
  /** The DOM element to render the login/pairing screen into. */
  readonly root: HTMLElement;
  /**
   * The persistence layer for the device identity. Defaults to `createLocalPairingStore()`.
   * Inject a custom store in tests or SSR contexts where `localStorage` is unavailable.
   */
  readonly pairingStore?: PairingStore;
  /**
   * The relay a **new** pairing pins into the stored identity (#249). It is shown on the pairing
   * screen before the human commits. A returning device keeps the relay already pinned in its
   * stored identity; this value never overrides it. Omit only in a relay-less harness.
   */
  readonly relayUrl?: string;
  /**
   * Called once when the user has a confirmed, valid `PairedIdentity`. The caller should
   * immediately mount the inbox (`mountWebApprover`) with the returned identity, sending every
   * relay call to its pinned `relayUrl`.
   *
   * This callback MUST be the only path to the inbox — the gate never calls it on a failed
   * or missing identity, enforcing the fail-closed invariant structurally.
   */
  readonly onPaired: (identity: PairedIdentity) => void;
}

/**
 * Mount the login / pairing-ceremony gate into `options.root`.
 *
 * Determines the initial route from the `PairingStore`:
 *
 * - **Returning device** (stored identity found and parseable): renders the re-auth screen.
 *   The human clicks "Unlock inbox" → `onPaired` fires with the stored identity.
 * - **New / reset device** (no stored identity or corrupt stored value): renders the pairing form.
 *   The human submits valid credentials → the identity is persisted and `onPaired` fires.
 *
 * The `onPaired` callback is the exclusive path to the inbox. The gate NEVER calls `onPaired` on
 * a failed, invalid, or missing identity — fail-closed is structural, not conditional.
 *
 * @see design/web-approver/onboarding/flow-notes.md
 * @see docs/contract.md §Invariants #6 (fail-closed)
 */
export function mountPairingGate(options: PairingGateOptions): void {
  const { root, onPaired, relayUrl } = options;
  const store: PairingStore = options.pairingStore ?? createLocalPairingStore();

  function goToPairing(): void {
    store.clear();
    renderPairingScreen(root, relayUrl, (identity: ApproverIdentity) => {
      const paired: PairedIdentity = relayUrl === undefined ? identity : { ...identity, relayUrl };
      store.save(paired);
      onPaired(paired);
    });
  }

  const stored = store.load();
  if (stored !== null) {
    renderReturningScreen(
      root,
      stored,
      () => {
        // Re-confirm the stored identity is still valid before routing to inbox.
        const current = store.load();
        if (current === null) {
          goToPairing();
          return;
        }
        onPaired(current);
      },
      goToPairing,
    );
  } else {
    goToPairing();
  }
}
