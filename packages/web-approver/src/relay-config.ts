/**
 * Runtime relay-URL configuration for the bundled web approver (issue #180).
 *
 * The static bundle produced by `scripts/build-site.mjs` is deployed once and then pointed at
 * whichever relay the operator runs (self-hosted, staging, the hosted `allw-relay` Worker) —
 * the relay origin must therefore be resolved **at runtime**, never embedded in the bundled JS as
 * a build-time literal. {@link resolveRelayUrl} resolves it, in priority order, from:
 *
 *   1. a `?relay=` query-string parameter — present, it is validated and persisted to storage so
 *      a follow-up visit (or a home-screen bookmark without the query string) keeps working;
 *   2. a previously-persisted value in storage (`localStorage` in production; an injectable
 *      `Storage` in tests);
 *   3. neither present → `null`, signalling the caller to render {@link mountRelayConfigGate}
 *      (the "small config UI" the issue allows as a third option) before the pairing/inbox flow
 *      can proceed.
 *
 * Fail-closed on malformed input: a query value or stored value that is not an absolute `http(s)`
 * URL is treated as absent rather than passed through to `fetch` calls downstream (`relay-poll.ts`,
 * `account-state.ts`) — never construct a network request against untrusted, unparsed input.
 *
 * @see ./app.ts (the production bootstrap that calls this before mounting the pairing gate)
 * @see ../../../docs/web-approver-deploy.md §Runtime relay configuration
 */

/** The query-string parameter name used to seed the relay URL, e.g. `?relay=https%3A%2F%2F...`. */
export const RELAY_URL_QUERY_PARAM = "relay";

/** The `localStorage` key the resolved relay URL is persisted under. */
export const RELAY_URL_STORAGE_KEY = "allw:relay-url:v1";

/** Where {@link resolveRelayUrl} reads the query string and persisted value from. */
export interface RelayUrlSource {
  /** A `location.search`-shaped string, e.g. `"?relay=https%3A%2F%2Frelay.example.com"` or `""`. */
  readonly search: string;
  /** Injectable storage seam. Production callers pass `window.localStorage`. */
  readonly storage: Storage;
}

/**
 * Validate and canonicalize a candidate relay URL. Returns `null` for anything that is not an
 * absolute `http:`/`https:` URL (fail-closed — malformed input is never treated as configured).
 * Trailing slashes are stripped so the stored value matches the canonical form `relay-poll.ts` /
 * `account-state.ts` already normalize internally.
 */
function normalizeRelayUrl(candidate: string): string | null {
  const trimmed = candidate.trim();
  if (trimmed.length === 0) return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  return trimmed.replace(/\/+$/, "");
}

/**
 * Resolve the relay URL from the query string, falling back to storage. When the query string
 * carries a valid `?relay=` value it is persisted so the origin is remembered without the query
 * string on a future visit (e.g. a home-screen bookmark). Returns `null` when no valid relay URL
 * is available from either source — the caller should render {@link mountRelayConfigGate}.
 */
export function resolveRelayUrl(source: RelayUrlSource): string | null {
  const params = new URLSearchParams(source.search);
  const fromQuery = params.get(RELAY_URL_QUERY_PARAM);
  if (fromQuery !== null) {
    const normalized = normalizeRelayUrl(fromQuery);
    if (normalized !== null) {
      source.storage.setItem(RELAY_URL_STORAGE_KEY, normalized);
      return normalized;
    }
    // A malformed query value falls through to any previously-stored value rather than wiping it.
  }
  const stored = source.storage.getItem(RELAY_URL_STORAGE_KEY);
  return stored !== null ? normalizeRelayUrl(stored) : null;
}

// ── Small config UI (issue #180's third allowed option) ─────────────────────────────────────────

/** Options for {@link mountRelayConfigGate}. */
export interface RelayConfigGateOptions {
  /** The DOM element to render the config prompt into. */
  readonly root: HTMLElement;
  /** Injectable storage seam. Production callers pass `window.localStorage`. */
  readonly storage: Storage;
  /** Called once with the validated, persisted relay URL. */
  readonly onConfigured: (relayUrl: string) => void;
}

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

/**
 * Render a minimal one-field prompt for the relay URL when neither a `?relay=` query param nor a
 * previously-persisted value is available. On valid submission the URL is persisted (so a
 * subsequent visit resolves it via {@link resolveRelayUrl} without this prompt) and
 * `onConfigured` fires; on invalid input (empty, non-`http(s)`) an inline error is shown and
 * `onConfigured` never fires — structurally mirrors {@link mountPairingGate}'s fail-closed shape.
 */
export function mountRelayConfigGate(options: RelayConfigGateOptions): void {
  const { root, storage, onConfigured } = options;
  render(null);

  function render(errorMessage: string | null): void {
    root.replaceChildren();

    const shell = el("div", "relay-config-shell");
    shell.append(text("h1", "allw approvals", "relay-config-wordmark"));
    shell.append(text("h2", "Connect a relay.", "relay-config-headline"));
    shell.append(
      text(
        "p",
        "Enter the relay URL your operator gave you (or open this page with a link that includes ?relay=…).",
        "relay-config-subcopy",
      ),
    );

    if (errorMessage !== null) {
      const banner = el("div", "relay-config-error-banner");
      banner.setAttribute("role", "alert");
      banner.textContent = errorMessage;
      shell.append(banner);
    }

    const form = el("form", "relay-config-form");
    form.setAttribute("aria-label", "Relay URL configuration");
    form.noValidate = true;

    const row = el("div", "relay-config-field");
    const label = text("label", "Relay URL", "relay-config-label");
    label.htmlFor = "relayUrl";
    const input = el("input", "relay-config-input");
    input.type = "url";
    input.name = "relayUrl";
    input.id = "relayUrl";
    input.placeholder = "https://relay.example.com";
    input.autocomplete = "off";
    row.append(label, input);
    form.append(row);

    const submit = el("button", "relay-config-btn relay-config-btn--primary");
    submit.type = "submit";
    submit.textContent = "Continue";
    form.append(submit);

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const normalized = normalizeRelayUrl(input.value);
      if (normalized === null) {
        render("Enter a valid relay URL, e.g. https://relay.example.com");
        return;
      }
      storage.setItem(RELAY_URL_STORAGE_KEY, normalized);
      onConfigured(normalized);
    });

    shell.append(form);
    root.append(shell);
  }
}
