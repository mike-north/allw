/**
 * Production bootstrap for the bundled web approver (issue #180).
 *
 * `scripts/build-site.mjs` bundles this module into the deployable static site
 * (`dist-site/app.js`, referenced by `public/index.html`'s `<script type="module">`). It composes
 * the existing building blocks — runtime relay-URL config, the pairing gate, the WASM-backed
 * runtime, and the inbox mount — into one boot sequence. It contains no crypto or policy logic of
 * its own (thin shell, `docs/architecture.md`): every cryptographic step still runs through the
 * audited core via {@link createBrowserRuntime}.
 *
 * # Why a *new* entry instead of `browser.ts`'s `window.allwWebApprover` convention
 * `browser.ts`'s auto-mount hook expects a caller to have already constructed a full
 * `WebApproverRuntime` before the module loads — but a real runtime needs the paired device
 * identity, which is only known *after* the pairing gate resolves, and the WASM core must be
 * fetched from a same-origin asset URL rather than read from a Node path. This module sequences
 * those steps explicitly: resolve the relay URL → run the pairing gate → load WASM → build the
 * runtime from the paired identity → mount the live inbox.
 *
 * # WASM asset loading (never a bare package specifier at runtime)
 * The vendored `--target web` glue and `.wasm` binary are copied by `scripts/build-site.mjs` to
 * `./vendor/allw-wasm/` next to this bundled module. Both URLs below are computed relative to
 * *this module's own URL* (`import.meta.url`) as non-literal runtime string values — never a
 * string-literal `import()` specifier — so `tsc` never attempts to resolve the gitignored vendor
 * path at typecheck time (mirrors `packages/approver/src/lib/wasm.ts`'s
 * `pathToFileURL(gluePath).href` pattern) and so the bundle keeps working when relocated to any
 * subpath or host (Cloudflare Pages, any static host — `docs/web-approver-deploy.md`).
 *
 * @see ./relay-config.ts (runtime relay-URL resolution + the fallback config prompt)
 * @see ./pairing.ts (the login / pairing-ceremony gate)
 * @see ./runtime.ts (the WASM-backed `WebApproverRuntime`)
 * @see ./browser.ts (the inbox mount + relay poll loop)
 * @see ./sequence-floor.ts (the persisted account-state rollback floor, #171)
 * @see ../../../docs/web-approver-deploy.md
 */

import { createRelayAccountStateResolver } from "./account-state.js";
import { mountWebApprover } from "./browser.js";
import { createLocalPairingStore, mountPairingGate } from "./pairing.js";
import { mountRelayConfigGate, resolveRelayUrl } from "./relay-config.js";
import { createBrowserRuntime, type ApproverIdentity } from "./runtime.js";
import { createLocalAccountStateFloorStore } from "./sequence-floor.js";

/** The default poll interval for the live inbox once mounted (matches `relay-poll.ts`'s default). */
const POLL_INTERVAL_MS = 2_000;

/**
 * URLs for the vendored WASM glue + binary, resolved relative to this bundled module's own URL
 * (see the module doc above for why these must stay non-literal `import()` inputs).
 */
const WASM_GLUE_URL = new URL("./vendor/allw-wasm/allw_wasm.js", import.meta.url);
const WASM_BINARY_URL = new URL("./vendor/allw-wasm/allw_wasm_bg.wasm", import.meta.url);

/** Resolve the relay URL, prompting with {@link mountRelayConfigGate} if none is configured yet. */
function ensureRelayUrl(root: HTMLElement): Promise<string> {
  const resolved = resolveRelayUrl({
    search: window.location.search,
    storage: window.localStorage,
  });
  if (resolved !== null) {
    return Promise.resolve(resolved);
  }
  return new Promise((resolve) => {
    mountRelayConfigGate({ root, storage: window.localStorage, onConfigured: resolve });
  });
}

/**
 * Load the vendored WASM core and mount the live inbox for a confirmed `identity`. Any failure
 * here (a stale/missing vendored artifact, a WASM instantiation error) is allowed to reject —
 * there is no safe UI to fall back to once pairing has already confirmed a human is present, so
 * a startup failure surfaces as an unhandled rejection an operator can see in devtools rather than
 * a silently blank inbox.
 */
async function bootInbox(
  root: HTMLElement,
  identity: ApproverIdentity,
  relayUrl: string,
): Promise<void> {
  const glueModule: unknown = await import(WASM_GLUE_URL.href);
  const runtime = await createBrowserRuntime({
    glueModule,
    moduleSource: WASM_BINARY_URL,
    identity,
    resolveAccountStates: createRelayAccountStateResolver({
      relayUrl,
      accountId: identity.accountId,
      deviceAuthToken: identity.deviceAuthToken,
    }),
    // Persists the account-state rollback floor (#171) in localStorage so it survives reloads —
    // the in-memory default `createWasmRuntime` falls back to would reset on every page load.
    sequenceFloorStore: createLocalAccountStateFloorStore(),
  });

  await mountWebApprover({
    root,
    runtime,
    relay: {
      relayUrl,
      accountId: identity.accountId,
      deviceId: identity.deviceId,
      deviceAuthToken: identity.deviceAuthToken,
      pollIntervalMs: POLL_INTERVAL_MS,
    },
  });
}

/** The full boot sequence: relay URL → pairing gate → (on success) WASM + live inbox. */
async function boot(): Promise<void> {
  const root = document.getElementById("app");
  if (!root) {
    throw new Error("allw web approver: missing '#app' mount element in the static HTML shell");
  }

  const relayUrl = await ensureRelayUrl(root);

  const pairingStore = createLocalPairingStore();
  mountPairingGate({
    root,
    pairingStore,
    onPaired: (identity) => {
      void bootInbox(root, identity, relayUrl);
    },
  });
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  void boot();
}

// Exported for the site-build integration test (`test/site-build.test.mjs`) to assert the bundle
// resolves the WASM asset URLs relative to its own module URL rather than an absolute build-time
// path — never imported by the production HTML shell, which only ever runs `boot()` above.
export { WASM_BINARY_URL, WASM_GLUE_URL };
