/**
 * Bundle the web approver into a deployable static site (issue #180).
 *
 * Bundles `src/app.ts` (the production bootstrap — `../src/app.ts`) into `dist-site/app.js` with
 * esbuild, copies the vendored `allw-wasm` browser artifact next to it (so `app.ts`'s
 * `import.meta.url`-relative asset URLs resolve on any static host, at any subpath), and copies
 * the static `public/` shell (`index.html`, `theme.js`, `tokens.css`, `styles.css`, `_headers`) alongside. `tokens.css` is
 * the vendored `design/web-approver/inbox/tokens.css` (issue #162) that `styles.css`'s `var(--…)`
 * declarations and `index.html`'s `theme-light`/`theme-dark` class resolve against — it must ship
 * next to `styles.css` or those custom properties are undefined on the deployed site. The result
 * is a flat directory of plain static files — no server-side runtime, no Cloudflare-specific API —
 * hostable on Cloudflare Pages or any static host (`docs/web-approver-deploy.md`).
 *
 * # Response headers (`_headers`, issue #249)
 * `public/_headers` is a Cloudflare Pages headers file carrying the site's Content-Security-Policy
 * and related headers. Its `connect-src` names the relays the page may talk to, which is a
 * deployment choice, so the template holds a placeholder that {@link buildSite} fills from the
 * build's relay origins: `relayOrigins` when passed, else the `ALLW_RELAY_ORIGINS` environment
 * variable (whitespace- or comma-separated), else {@link DEFAULT_RELAY_ORIGINS}. Each origin is
 * emitted in its `https:` and `wss:` forms (or `http:`/`ws:` for a loopback dev relay). A relay
 * origin that fails the web approver's transport rule fails the build rather than widening the
 * policy, and so does a header line past Cloudflare's 2,000-character limit.
 *
 * # Why esbuild (not Vite)
 * The repo's existing tooling taste is plain `tsc` plus small `scripts/*.mjs` (e.g.
 * `scripts/postbuild-wasm.mjs`); esbuild's JS API composes with that directly (one function call,
 * no dev-server/plugin ecosystem, no new config file format to introduce), and esbuild's
 * postinstall lifecycle script is already allow-listed at the workspace root
 * (`pnpm.onlyBuiltDependencies` in the root `package.json`), so this introduces no new tooling
 * category to the workspace.
 *
 * # Why this is not wired into `tsc`/typecheck/lint
 * The vendored WASM (`pnpm run build:wasm`, gitignored — see `../../../.gitignore`) is a
 * build-time prerequisite for the site bundle *only*: `tsc`/typecheck/lint must keep working
 * before wasm is built, because CI's `typescript` job runs `pnpm -r build` before any wasm step
 * (`.github/workflows/ci.yml`). This script is invoked as a chained step of `package.json`'s
 * `build` script (after `tsc`), and when the vendor artifact is absent it skips the bundle with a
 * clear message and exits 0 rather than failing the whole `pnpm -r build`. The `wasm` CI job
 * (which does build wasm first) explicitly re-runs `pnpm --filter @allw/web-approver build`
 * afterward so the real bundle is exercised in CI, not just this best-effort local skip.
 *
 * @see ../src/app.ts (the bundled entry point)
 * @see ../../../scripts/postbuild-wasm.mjs (the sibling small-script convention this follows)
 */

import { build } from "esbuild";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const packageDir = dirname(dirname(fileURLToPath(import.meta.url)));
const vendorDir = join(packageDir, "..", "sdk", "vendor", "allw-wasm");
const defaultOutDir = join(packageDir, "dist-site");

/** The relay the hosted web approver talks to unless the build is told otherwise. */
export const DEFAULT_RELAY_ORIGINS = ["https://allw-relay.mnorth.workers.dev"];

/** The token in `public/_headers` replaced with the relay `connect-src` sources. */
const RELAY_CONNECT_SRC_PLACEHOLDER = "__ALLW_RELAY_CONNECT_SRC__";

/**
 * Hosts on which a plaintext `http:` relay is tolerated — the same set as `src/relay-config.ts`.
 * The IPv6 loopback `[::1]` is excluded everywhere because an IPv6 literal cannot be written as a
 * CSP host-source (see {@link relayConnectSources}).
 */
const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1"]);

/**
 * A plain DNS name or dotted IPv4 address, as `URL.hostname` reports it (lowercased, punycode).
 * Nothing else may reach the header: this is what keeps CSP metacharacters — `*`, `;`, `'`,
 * whitespace — out of `connect-src`, where `https://*` would allow every host and
 * `https://a.com;sandbox` would start a new directive.
 */
const PLAIN_HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/**
 * Turn the configured relay origins into `connect-src` sources: each origin plus its WebSocket
 * form. Throws — failing the build rather than emitting a wider or broken policy — on anything
 * that is not an `https:` origin (or `http:` on `localhost`/`127.0.0.1`) with a plain hostname and
 * no path, query, fragment, or credentials. IPv6 literals are rejected because the CSP3
 * host-source grammar has no form for them (a browser would drop the source and block the relay).
 *
 * @see https://www.w3.org/TR/CSP3/#grammardef-host-source
 */
export function relayConnectSources(relayOrigins) {
  if (relayOrigins.length === 0) {
    throw new Error("[web-approver] at least one relay origin is required for connect-src");
  }
  const sources = [];
  for (const candidate of relayOrigins) {
    let url;
    try {
      url = new URL(candidate);
    } catch {
      throw new Error(`[web-approver] relay origin '${candidate}' is not an absolute URL`);
    }
    if (url.hostname.startsWith("[")) {
      throw new Error(
        `[web-approver] relay origin '${candidate}' uses an IPv6 address, which a CSP ` +
          "connect-src cannot express; use a DNS name, or http://127.0.0.1 for a local relay",
      );
    }
    if (!PLAIN_HOSTNAME.test(url.hostname)) {
      throw new Error(
        `[web-approver] relay origin '${candidate}' must have a plain DNS hostname ` +
          "(no wildcards or other CSP syntax)",
      );
    }
    const secure =
      url.protocol === "https:" ||
      (url.protocol === "http:" && LOOPBACK_HOSTNAMES.has(url.hostname));
    if (!secure) {
      throw new Error(
        `[web-approver] relay origin '${candidate}' must use https:// ` +
          "(http:// is allowed only for localhost or 127.0.0.1)",
      );
    }
    if (
      (url.pathname !== "/" && url.pathname !== "") ||
      url.search !== "" ||
      url.hash !== "" ||
      url.username !== "" ||
      url.password !== "" ||
      /[?#@]/.test(candidate)
    ) {
      throw new Error(
        `[web-approver] relay origin '${candidate}' must be a bare origin like https://relay.example.com`,
      );
    }
    const wsOrigin = url.origin.replace(/^http/, "ws");
    sources.push(url.origin, wsOrigin);
  }
  return [...new Set(sources)];
}

/** The relay origins from `ALLW_RELAY_ORIGINS`, or `null` when it is unset/blank. */
function relayOriginsFromEnv() {
  const raw = process.env.ALLW_RELAY_ORIGINS;
  if (raw === undefined) return null;
  const origins = raw.split(/[\s,]+/).filter((origin) => origin.length > 0);
  return origins.length > 0 ? origins : null;
}

/** Cloudflare Pages ignores `_headers` lines longer than this (its documented per-line limit). */
const MAX_HEADERS_LINE_LENGTH = 2000;

/**
 * Render `public/_headers` with the relay `connect-src` sources substituted. Throws if a line
 * would exceed Cloudflare's per-line limit — a long relay list must fail the build, not ship a
 * policy the host silently drops.
 */
export function renderHeaders(template, relayOrigins) {
  if (!template.includes(RELAY_CONNECT_SRC_PLACEHOLDER)) {
    throw new Error(`[web-approver] public/_headers is missing ${RELAY_CONNECT_SRC_PLACEHOLDER}`);
  }
  const rendered = template.replaceAll(
    RELAY_CONNECT_SRC_PLACEHOLDER,
    relayConnectSources(relayOrigins).join(" "),
  );
  for (const line of rendered.split("\n")) {
    if (line.length > MAX_HEADERS_LINE_LENGTH) {
      throw new Error(
        `[web-approver] a _headers line is ${String(line.length)} characters; Cloudflare Pages ` +
          `allows ${String(MAX_HEADERS_LINE_LENGTH)} — shorten the relay list`,
      );
    }
  }
  return rendered;
}

/**
 * Build the static site into `outDir` (defaults to `dist-site/` next to this package). Returns
 * `{ built: false, outDir }` (a no-op) when the vendored WASM has not been built yet, or
 * `{ built: true, outDir }` once the bundle + copied assets are written. `relayOrigins` sets the
 * CSP `connect-src` relays (see the module doc); it defaults to `ALLW_RELAY_ORIGINS`, then
 * {@link DEFAULT_RELAY_ORIGINS}.
 */
export async function buildSite({
  outDir = defaultOutDir,
  relayOrigins = relayOriginsFromEnv() ?? DEFAULT_RELAY_ORIGINS,
} = {}) {
  // Validate the relay list before touching the output directory, so a bad value fails fast.
  const headers = renderHeaders(
    readFileSync(join(packageDir, "public", "_headers"), "utf8"),
    relayOrigins,
  );

  const wasmBinary = join(vendorDir, "allw_wasm_bg.wasm");
  const wasmGlue = join(vendorDir, "allw_wasm.js");

  if (!existsSync(wasmBinary) || !existsSync(wasmGlue)) {
    console.warn(
      `[web-approver] skipping site bundle — vendored WASM not found at ${vendorDir}. ` +
        "Run 'pnpm run build:wasm' from the repo root, then re-run this build.",
    );
    return { built: false, outDir };
  }

  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  await build({
    entryPoints: [join(packageDir, "src", "app.ts")],
    outfile: join(outDir, "app.js"),
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "browser",
    sourcemap: true,
    minify: true,
    logLevel: "warning",
  });

  const vendorOutDir = join(outDir, "vendor", "allw-wasm");
  mkdirSync(vendorOutDir, { recursive: true });
  cpSync(wasmBinary, join(vendorOutDir, "allw_wasm_bg.wasm"));
  cpSync(wasmGlue, join(vendorOutDir, "allw_wasm.js"));

  cpSync(join(packageDir, "public", "index.html"), join(outDir, "index.html"));
  cpSync(join(packageDir, "public", "tokens.css"), join(outDir, "tokens.css"));
  cpSync(join(packageDir, "public", "styles.css"), join(outDir, "styles.css"));
  cpSync(join(packageDir, "public", "theme.js"), join(outDir, "theme.js"));
  writeFileSync(join(outDir, "_headers"), headers);

  console.log(`[web-approver] site bundle written to ${outDir}`);
  return { built: true, outDir };
}

// Run when invoked directly (`node scripts/build-site.mjs`) — not when imported by tests
// (`test/site-build.test.mjs` imports `buildSite` to build into a throwaway temp directory).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await buildSite();
}
