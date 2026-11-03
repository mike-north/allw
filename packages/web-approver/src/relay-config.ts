/**
 * Runtime relay-URL configuration for the bundled web approver (issues #180, #249).
 *
 * The static bundle produced by `scripts/build-site.mjs` is deployed once and then pointed at
 * whichever relay the operator runs (self-hosted, staging, the hosted `allw-relay` Worker) —
 * the relay origin must therefore be resolved **at runtime**, never embedded in the bundled JS as
 * a build-time literal. This module owns the two phases of that resolution:
 *
 * - **Before pairing** ({@link resolveRelayUrl}) the relay is a *candidate*: a `?relay=` link may
 *   pre-fill it (and is persisted, so a bookmark without the query keeps working), otherwise a
 *   previously-persisted value is used, otherwise the caller renders {@link mountRelayConfigGate}.
 *   The candidate is shown to the human on the pairing screen before they commit (#249).
 * - **After pairing** the relay is *pinned* inside the stored identity (`./pairing.ts`
 *   `PairedIdentity.relayUrl`) and is the only relay any request goes to. A `?relay=` that differs
 *   is ignored — never persisted, never contacted — and {@link describeIgnoredRelayOverride} +
 *   {@link mountIgnoredRelayNotice} tell the human that a link was ignored, naming it only through
 *   the core's display escape (#307). Without the pin, a
 *   phishing link (`…/?relay=https://evil.example`) would re-point a paired device and hand its
 *   bearer `deviceAuthToken` to the attacker's relay (`docs/threat-model.md` §Trust Boundaries).
 *
 * Fail-closed on malformed or insecure input ({@link checkRelayUrl}): only `https:` relay URLs are
 * accepted, plus `http:` on a loopback host for local development. Anything else is rejected
 * with an actionable reason rather than passed through to the `fetch`/WebSocket calls downstream
 * (`relay-poll.ts`, `account-state.ts`, `retract-listener.ts`). The SDK's `createClient` applies
 * the same rule (`packages/sdk/src/relay.ts` `assertRelayUrlTransport`).
 *
 * @see ./app.ts (the production bootstrap that sequences these)
 * @see ../../../docs/web-approver-deploy.md §Runtime relay configuration, §Relay pinning
 */

import { displayUntrusted, type DisplayEscape } from "./display-escape.js";

/** The query-string parameter name used to seed the relay URL, e.g. `?relay=https%3A%2F%2F...`. */
export const RELAY_URL_QUERY_PARAM = "relay";

/** The `localStorage` key the pre-pairing candidate relay URL is persisted under. */
export const RELAY_URL_STORAGE_KEY = "allw:relay-url:v1";

/**
 * Hostnames on which a plaintext `http:` relay is tolerated: the local-development relay
 * (`wrangler dev`) never leaves the machine, so there is no network path to protect.
 *
 * The IPv6 loopback `[::1]` is deliberately absent: a CSP host-source cannot express an IPv6
 * literal, so the site build can never put it in `connect-src`, and a browser pinned to it would be
 * blocked on every build. `127.0.0.1` is the loopback to use. The SDK and the build share this set
 * (`packages/sdk/src/relay.ts`, `scripts/build-site.mjs`).
 */
const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set(["localhost", "127.0.0.1"]);

/** The actionable reason shown when a relay URL fails the transport rule. */
export const INSECURE_RELAY_URL_REASON =
  "Relay URLs must use https://. Plain http:// is allowed only for a relay on this machine, " +
  "at localhost or 127.0.0.1 (use 127.0.0.1 rather than [::1]).";

/**
 * The actionable reason shown when a relay URL carries userinfo (`user:pw@`), a query (`?`) or a
 * fragment (`#`). Userinfo lets a link *look* like one host while pointing at another
 * (`https://relay.example.com@evil.example` is `evil.example`); a query or fragment would corrupt
 * the request paths appended to the relay URL.
 */
export const RELAY_URL_EXTRAS_REASON =
  "Relay URLs must not include a username, password, query (?) or fragment (#), " +
  "e.g. https://relay.example.com";

/** Outcome of {@link checkRelayUrl}: the canonical URL, or why the candidate was rejected. */
export type RelayUrlCheck =
  | { readonly ok: true; readonly relayUrl: string }
  | { readonly ok: false; readonly reason: string };

/**
 * Whether the raw text carries userinfo, a query, or a fragment — including the *empty* forms
 * (`https://@host`, `https://host?`, `https://host#`) that `URL` normalizes away. Checked on the
 * raw text as well as the parsed URL so this rule agrees with the SDK's `assertRelayUrlTransport`,
 * which appends request paths to the caller's raw string.
 */
function hasUrlExtras(raw: string, parsed: URL): boolean {
  return (
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    raw.includes("?") ||
    raw.includes("#") ||
    /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*@/i.test(raw)
  );
}

/**
 * Validate and canonicalize a candidate relay URL. Accepts an absolute `https:` URL, or an
 * `http:` URL whose host is loopback, with no userinfo, query, or fragment; rejects everything
 * else with a human-readable reason. A path is allowed (a relay may be served under a subpath).
 *
 * The canonical form is `URL.origin` (lowercased, punycode host, default port dropped) plus the
 * parsed pathname with trailing slashes stripped — never the caller's raw text — so the value
 * stored in a pin, compared against a `?relay=` link, and shown to the human is one unambiguous
 * string. `./pairing.ts` requires a stored pin to equal this form, so **changing the canonical form
 * or narrowing what this function accepts** puts every affected browser into the re-pair-required
 * state (#286): its identity is unusable and the human must confirm re-pairing. A change that does
 * so should ship a migration for stored pins, or say in its release notes that those devices must
 * re-pair.
 */
export function checkRelayUrl(candidate: string): RelayUrlCheck {
  const trimmed = candidate.trim();
  if (trimmed.length === 0) {
    return { ok: false, reason: "Enter a relay URL, e.g. https://relay.example.com" };
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      ok: false,
      reason: "Enter a valid relay URL, e.g. https://relay.example.com",
    };
  }
  const secure =
    parsed.protocol === "https:" ||
    (parsed.protocol === "http:" && LOOPBACK_HOSTNAMES.has(parsed.hostname));
  if (!secure) return { ok: false, reason: INSECURE_RELAY_URL_REASON };
  if (hasUrlExtras(trimmed, parsed)) return { ok: false, reason: RELAY_URL_EXTRAS_REASON };
  return { ok: true, relayUrl: parsed.origin + parsed.pathname.replace(/\/+$/, "") };
}

/** Where {@link resolveRelayUrl} reads the query string and persisted value from. */
export interface RelayUrlSource {
  /** A `location.search`-shaped string, e.g. `"?relay=https%3A%2F%2Frelay.example.com"` or `""`. */
  readonly search: string;
  /** Injectable storage seam. Production callers pass `window.localStorage`. */
  readonly storage: Storage;
}

/** Outcome of {@link resolveRelayUrl}. */
export interface RelayUrlResolution {
  /** The candidate relay URL, or `null` when none is configured (render the config gate). */
  readonly relayUrl: string | null;
  /**
   * Why a `?relay=` value was rejected, when one was present and failed {@link checkRelayUrl} —
   * surfaced in {@link mountRelayConfigGate} so the human sees an actionable error rather than a
   * silently-ignored link. `null` when no query value was present or it was accepted.
   */
  readonly rejectedQueryReason: string | null;
}

/**
 * Resolve the **pre-pairing** candidate relay URL from the query string, falling back to storage.
 * A valid `?relay=` value is persisted so the origin is remembered without the query string on a
 * future visit (e.g. a home-screen bookmark). Never call this for a paired device — its relay is
 * pinned in the stored identity; use {@link describeIgnoredRelayOverride} instead.
 */
export function resolveRelayUrl(source: RelayUrlSource): RelayUrlResolution {
  const fromQuery = readRelayQueryValue(source.search);
  let rejectedQueryReason: string | null = null;
  if (fromQuery !== null) {
    const checked = checkRelayUrl(fromQuery);
    if (checked.ok) {
      source.storage.setItem(RELAY_URL_STORAGE_KEY, checked.relayUrl);
      return { relayUrl: checked.relayUrl, rejectedQueryReason: null };
    }
    // A rejected query value falls through to any previously-stored value rather than wiping it.
    rejectedQueryReason = checked.reason;
  }
  return { relayUrl: readStoredRelayUrl(source.storage), rejectedQueryReason };
}

/**
 * The persisted pre-pairing relay URL, re-validated on read (a value written by an older build
 * before the https-only rule is rejected here, fail-closed). `null` when absent or invalid.
 */
export function readStoredRelayUrl(storage: Storage): string | null {
  const stored = storage.getItem(RELAY_URL_STORAGE_KEY);
  if (stored === null) return null;
  const checked = checkRelayUrl(stored);
  return checked.ok ? checked.relayUrl : null;
}

/** The raw `?relay=` value, or `null` when the parameter is absent. */
function readRelayQueryValue(search: string): string | null {
  return new URLSearchParams(search).get(RELAY_URL_QUERY_PARAM);
}

/** Longest text, in code points, the notice echoes back for an ignored `?relay=` value. */
const MAX_ECHOED_RELAY_TEXT = 120;

/**
 * What the notice names for a `?relay=` value that parses as a URL without a network origin
 * (`javascript:`, `data:`, `file:`, or prose such as `word: …`, whose origin is `"null"`).
 */
export const NOT_A_RELAY_URL_TEXT = "(not a relay URL)";

/**
 * `text` cut to {@link MAX_ECHOED_RELAY_TEXT} code points, with `…` when cut. It reads only up to
 * the limit, so an attacker-sized value costs no more than a short one, and never splits a
 * surrogate pair.
 */
function clipEchoedText(text: string): string {
  let clipped = "";
  let count = 0;
  for (const codePoint of text) {
    if (count === MAX_ECHOED_RELAY_TEXT) return `${clipped}…`;
    clipped += codePoint;
    count += 1;
  }
  return clipped;
}

/**
 * For a **paired** device: if the page was opened with a `?relay=` that differs from the pinned
 * relay, return the text naming what was ignored; otherwise `null`. The text is the requested URL's
 * origin, {@link NOT_A_RELAY_URL_TEXT} for a URL with no network origin, or the raw value when it
 * does not parse, each cut to {@link MAX_ECHOED_RELAY_TEXT} code points. Pure:
 * it never persists or contacts anything, so the override has no effect beyond the notice.
 *
 * The result is **untrusted** (anyone can send the human a link) and may hold bidi overrides,
 * zero-width or control characters. Print it only through the core escape
 * ({@link mountIgnoredRelayNotice} does), never as is.
 */
export function describeIgnoredRelayOverride(
  search: string,
  pinnedRelayUrl: string,
): string | null {
  const requested = readRelayQueryValue(search);
  if (requested === null) return null;
  const checked = checkRelayUrl(requested);
  if (checked.ok && checked.relayUrl === pinnedRelayUrl) return null;
  let origin: string;
  try {
    origin = new URL(requested.trim()).origin;
  } catch {
    return clipEchoedText(requested.trim());
  }
  // The URL parser enforces no host length, so an origin is clipped like any other echo.
  return origin === "null" ? NOT_A_RELAY_URL_TEXT : clipEchoedText(origin);
}

/** The display origin of a canonical relay URL (falls back to the URL itself if unparseable). */
export function relayOrigin(relayUrl: string): string {
  try {
    return new URL(relayUrl).origin;
  } catch {
    return relayUrl;
  }
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

// ── Ignored-override notice (#249) ───────────────────────────────────────────────────────────────

/** Options for {@link mountIgnoredRelayNotice}. */
export interface IgnoredRelayNoticeOptions {
  /** The element the notice renders into (`#notices` in `public/index.html`, outside `#app`). */
  readonly host: HTMLElement;
  /**
   * What {@link describeIgnoredRelayOverride} returned for the ignored `?relay=` value. Untrusted:
   * it is shown only as `escapeForDisplay`'s output, or withheld.
   */
  readonly ignored: string;
  /** The relay URL pinned in the stored identity, or the relay a re-pair visit pairs against. */
  readonly pinnedRelayUrl: string;
  /**
   * The core's display escape, once the core has loaded; `null` when it can't. The notice renders
   * at once, with the ignored link's name pending, and fills the name in when this settles: the
   * core's escape of it, or the withheld text (`./display-escape.ts`) if there is no core. A core that never
   * loads leaves the name pending; the notice still says a link was ignored.
   */
  readonly escapeForDisplay: Promise<DisplayEscape | null>;
  /**
   * Whether this browser is re-pairing (#286): it has no usable identity yet, but is treated as
   * previously paired, so the notice says it is re-pairing with the relay rather than paired.
   */
  readonly repairing?: boolean;
}

/** Shown in place of the ignored link's name until the core escape is available. */
export const PENDING_IGNORED_RELAY_TEXT = "(checking…)";

/**
 * Whether the notice may print the pinned relay's origin as is. A relay URL that {@link checkRelayUrl} accepts in this
 * exact form has a WHATWG-parsed origin: ASCII only (an internationalized host is punycode), with no
 * controls, bidi or zero-width characters, so it is printed as is, like the pairing screen does. Any
 * other value is untrusted and goes through the core escape like the ignored link.
 */
function isCanonicalRelayUrl(relayUrl: string): boolean {
  const checked = checkRelayUrl(relayUrl);
  return checked.ok && checked.relayUrl === relayUrl;
}

/**
 * Render a persistent notice that a `?relay=` link was ignored because this browser is paired
 * with a pinned relay. It renders into a host outside `#app` so it stays visible as the pairing
 * gate hands off to the inbox.
 *
 * The ignored link is attacker-chosen, so it is never put into the DOM: the notice shows the
 * core's escape of it, or withholds it (`docs/threat-model.md`, display model). The notice itself
 * renders immediately and never waits for the core. Resolves once the name has been filled in.
 */
export async function mountIgnoredRelayNotice(options: IgnoredRelayNoticeOptions): Promise<void> {
  const { host, ignored, pinnedRelayUrl, repairing = false } = options;
  const relation = repairing ? "is re-pairing with" : "is paired with";
  const pinnedIsCanonical = isCanonicalRelayUrl(pinnedRelayUrl);
  const notice = el("div", "relay-pin-notice");
  notice.setAttribute("role", "status");
  notice.append(text("strong", "Relay link ignored. ", "relay-pin-notice-title"));
  notice.append(document.createTextNode(`This browser ${relation} `));
  const pinned = text(
    "span",
    pinnedIsCanonical ? relayOrigin(pinnedRelayUrl) : PENDING_IGNORED_RELAY_TEXT,
    "relay-pin-notice-pinned",
  );
  notice.append(pinned);
  notice.append(document.createTextNode(" and only talks to that relay. The link asked to use "));
  const name = text("code", PENDING_IGNORED_RELAY_TEXT, "relay-pin-notice-origin");
  notice.append(name);
  notice.append(
    document.createTextNode(
      "; nothing was sent there. To use another relay, clear this site's data, then open the new link.",
    ),
  );
  host.replaceChildren(notice);

  let escapeForDisplay: DisplayEscape | null;
  try {
    escapeForDisplay = await options.escapeForDisplay;
  } catch {
    escapeForDisplay = null;
  }
  name.textContent = displayUntrusted(ignored, escapeForDisplay);
  if (!pinnedIsCanonical) pinned.textContent = displayUntrusted(pinnedRelayUrl, escapeForDisplay);
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
  /**
   * An error to show on first render — e.g. why a `?relay=` link was rejected
   * ({@link RelayUrlResolution.rejectedQueryReason}).
   */
  readonly initialError?: string | null;
}

/**
 * Render a minimal one-field prompt for the relay URL when neither a `?relay=` query param nor a
 * previously-persisted value is available. On valid submission the URL is persisted (so a
 * subsequent visit resolves it via {@link resolveRelayUrl} without this prompt) and
 * `onConfigured` fires; on invalid input (empty, malformed, or insecure per
 * {@link checkRelayUrl}) an inline error is shown and `onConfigured` never fires — structurally
 * mirrors `mountPairingGate`'s fail-closed shape.
 */
export function mountRelayConfigGate(options: RelayConfigGateOptions): void {
  const { root, storage, onConfigured } = options;
  render(options.initialError ?? null);

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
      const checked = checkRelayUrl(input.value);
      if (!checked.ok) {
        render(checked.reason);
        return;
      }
      storage.setItem(RELAY_URL_STORAGE_KEY, checked.relayUrl);
      onConfigured(checked.relayUrl);
    });

    shell.append(form);
    root.append(shell);
  }
}
