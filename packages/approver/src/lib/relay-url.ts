/**
 * The approver CLI's relay-URL transport rule (#267).
 *
 * Every relay request the CLI makes carries pairing material or the device bearer token: the
 * pairing-start authorization and pairing code, the `deviceAuthToken` on `account-states`, and the
 * same token in the presence WebSocket's protocol offers. Over plaintext HTTP to a remote host an on-path
 * attacker reads all of it and can then do anything a malicious relay can. So a relay URL is
 * accepted only if it is `https:`, or `http:` on a local-development loopback host, and carries no
 * userinfo, query or fragment (`docs/threat-model.md` §Relay and Transport).
 *
 * The check runs where a relay URL **enters** the CLI (`pair --relay`, `watch --relay`, and the
 * keyfile's `relay_url` when `watch` uses it), before any request is built. The request builders in
 * `./relay-client.ts` are deliberately left unchanged: they trust their callers, so a library
 * caller that uses them directly applies {@link assertCliRelayUrl} first (it is exported for that).
 *
 * An accepted URL comes back in **canonical form** (origin plus path, no trailing `/`), and callers
 * use only that: it is what they connect to, derive the `ws(s)://` socket URL from, and persist.
 * The raw text is never used after the check, so input the URL parser tolerates (surrounding
 * whitespace, an upper-case scheme or host) cannot reach `fetch` or `WebSocket` un-normalized.
 *
 * The rule is the one the SDK's `assertRelayUrlTransport` (`packages/sdk/src/relay.ts`) and the web
 * approver's `checkRelayUrl` (`packages/web-approver/src/relay-config.ts`) apply, and the canonical
 * form is `checkRelayUrl`'s. The three copies are held together by the shared vectors in
 * `packages/sdk/test/fixtures/relay-url-vectors.json` (`runtime` verdicts and `canonical` forms),
 * which every surface's tests load. This copy differs only in how the error names its source, so
 * the human knows which flag or file to fix.
 */

/**
 * Hosts on which a plaintext `http:` relay is tolerated: a local-development relay (`wrangler dev`)
 * never leaves the machine. The IPv6 loopback `[::1]` is deliberately absent so one loopback set
 * holds across the web approver (whose CSP cannot express an IPv6 literal), the SDK and this CLI
 * (#277); `127.0.0.1` is the loopback to use.
 */
const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set(["localhost", "127.0.0.1"]);

/**
 * Where a relay URL came from, named in the error so the human knows what to change. The keyfile
 * case also says how to fix it: `pair` rewrites the stored `relay_url`.
 */
export type RelayUrlSource = "--relay" | "keyfile relay_url";

/**
 * The most code points of a rejected URL an error echoes. The URL is untrusted and unbounded (a
 * `--relay` value or a keyfile field), so the echo is clipped, like the web approver's notice.
 * The CLI's fatal path then escapes the whole message for the terminal (`../cli.ts`).
 */
export const MAX_ECHOED_RELAY_URL_CODE_POINTS = 120;

/** `text` cut to {@link MAX_ECHOED_RELAY_URL_CODE_POINTS} code points, with `…` when cut. */
function clipEcho(text: string): string {
  const codePoints = Array.from(text);
  return codePoints.length > MAX_ECHOED_RELAY_URL_CODE_POINTS
    ? `${codePoints.slice(0, MAX_ECHOED_RELAY_URL_CODE_POINTS).join("")}…`
    : text;
}

/** How to fix a rejected URL, per source. */
const REMEDY: Readonly<Record<RelayUrlSource, string>> = {
  "--relay": "pass e.g. --relay https://relay.example.com",
  "keyfile relay_url":
    "re-pair with an https relay (allw-approver pair --relay https://relay.example.com), " +
    "or pass --relay to override it",
};

/**
 * Check `relayUrl` against the relay transport rule and return its canonical form; throw an
 * actionable `Error` if it fails. The rule: `https:`, or `http:` on `localhost` / `127.0.0.1`; no
 * username, password, query or fragment (including the empty forms `https://host?`, `https://host#`
 * and `https://@host`, which are rejected on the raw text). A path is allowed. An unparseable or
 * relative URL is rejected too.
 *
 * The canonical form is the parsed origin (lower-case scheme and host, punycode, default port
 * dropped) plus the path without trailing slashes, e.g. `https://relay.example.com/base`.
 *
 * Call this before building any relay request, and use only its return value from then on. A
 * rejected URL never sees a byte. The request builders in `./relay-client.ts` don't check; library
 * callers that use them directly must apply this first.
 */
export function assertCliRelayUrl(relayUrl: string, source: RelayUrlSource): string {
  const named = `${source} '${clipEcho(relayUrl)}'`;
  const remedy = REMEDY[source];
  let parsed: URL;
  try {
    parsed = new URL(relayUrl);
  } catch {
    throw new Error(`${named} is not an absolute URL; ${remedy}`);
  }
  const secure =
    parsed.protocol === "https:" ||
    (parsed.protocol === "http:" && LOOPBACK_HOSTNAMES.has(parsed.hostname));
  if (!secure) {
    throw new Error(
      `${named} must use https:// (plain http:// is allowed only for a local relay on localhost ` +
        `or 127.0.0.1; use 127.0.0.1 rather than [::1]); ${remedy}`,
    );
  }
  const hasExtras =
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    relayUrl.includes("?") ||
    relayUrl.includes("#") ||
    /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*@/i.test(relayUrl.trim());
  if (hasExtras) {
    throw new Error(
      `${named} must not include a username, password, query (?) or fragment (#); ${remedy}`,
    );
  }
  return parsed.origin + parsed.pathname.replace(/\/+$/, "");
}
