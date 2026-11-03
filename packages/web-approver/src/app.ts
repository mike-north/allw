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
 * those steps explicitly: resolve the relay URL → run the first-run onboarding walkthrough
 * (pre-enrollment only, #151) → run the pairing gate → load WASM → build the runtime from the
 * paired identity → mount the live inbox, and beside it the notification controls (#237).
 *
 * # Relay pinning (#249)
 * The relay URL is resolved differently depending on whether this browser is already paired:
 *
 * - **Paired** — the relay pinned inside the stored identity is the only relay used. A `?relay=`
 *   link that differs is ignored (never persisted, never contacted) and a notice names the
 *   ignored origin. An identity stored before pinning existed is bound to the relay this browser
 *   had already persisted — never to the link — or, if none, to one the human types.
 * - **Unpaired** — a `?relay=` link may pre-fill the candidate relay; the pairing screen shows it
 *   before the human commits, and pairing pins it.
 *
 * Every relay call after pairing ({@link bootInbox}) reads the identity's pinned `relayUrl`.
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
 * @see ./onboarding.ts (the first-run walkthrough gate, pre-enrollment only, #151)
 * @see ./pairing.ts (the login / pairing-ceremony gate)
 * @see ./runtime.ts (the WASM-backed `WebApproverRuntime`)
 * @see ./browser.ts (the inbox mount + relay poll loop)
 * @see ./sequence-floor.ts (the persisted account-state rollback floor, #171)
 * @see ../../../docs/web-approver-deploy.md
 */

import { createRelayAccountStateResolver } from "./account-state.js";
import { mountWebApprover, type WebApproverMount } from "./browser.js";
import { mountOnboardingGate } from "./onboarding.js";
import { createLocalPairingStore, mountPairingGate, type PairedIdentity } from "./pairing.js";
import {
  describeIgnoredRelayOverride,
  mountIgnoredRelayNotice,
  mountRelayConfigGate,
  readStoredRelayUrl,
  resolveRelayUrl,
} from "./relay-config.js";
import { createIndexedDbPushCredentialStore } from "./push-credentials.js";
import { browserPushEnvironment, mountNotificationControls } from "./push-subscribe.js";
import { createBrowserRuntime } from "./runtime.js";
import { createLocalAccountStateFloorStore } from "./sequence-floor.js";
import { createLocalSurfaceIdStore, resolveSurfaceId } from "./surface-id.js";
import type { WasmModuleSource } from "./wasm.js";

/** The default poll interval for the live inbox once mounted (matches `relay-poll.ts`'s default). */
const POLL_INTERVAL_MS = 2_000;

/**
 * URLs for the vendored WASM glue + binary, resolved relative to this bundled module's own URL
 * (see the module doc above for why these must stay non-literal `import()` inputs).
 */
const WASM_GLUE_URL = new URL("./vendor/allw-wasm/allw_wasm.js", import.meta.url);
const WASM_BINARY_URL = new URL("./vendor/allw-wasm/allw_wasm_bg.wasm", import.meta.url);

/**
 * Where {@link bootInbox} gets the WASM core: the glue module and the binary it instantiates.
 * Production uses {@link VENDORED_WASM}; tests inject the same vendored artifact from disk.
 */
export interface InboxWasmSource {
  readonly loadGlue: () => Promise<unknown>;
  readonly moduleSource: WasmModuleSource;
}

/** The vendored WASM copied next to the bundled module by `scripts/build-site.mjs`. */
const VENDORED_WASM: InboxWasmSource = {
  loadGlue: () => import(WASM_GLUE_URL.href),
  moduleSource: WASM_BINARY_URL,
};

/** A paired identity whose relay is pinned — the only shape {@link bootInbox} accepts. */
export type PinnedIdentity = PairedIdentity & { readonly relayUrl: string };

/**
 * Everything {@link boot} reads from the page, injectable so the boot decisions (which relay,
 * which notice, which gate) are testable without a real browser or WASM.
 */
export interface BootEnvironment {
  /** The `#app` element every gate and the inbox render into. */
  readonly root: HTMLElement;
  /** The `#notices` element, outside `#app`, that keeps the ignored-relay notice visible. */
  readonly noticeHost: HTMLElement;
  /** Injectable storage seam. Production passes `window.localStorage`. */
  readonly storage: Storage;
  /** A `location.search`-shaped string. */
  readonly search: string;
  /** Load WASM and mount the live inbox for a paired identity, against its pinned relay. */
  readonly startInbox: (root: HTMLElement, identity: PinnedIdentity) => Promise<unknown>;
  /**
   * Mount the notification controls (#237) for a paired identity, outside the inbox. Called after
   * `startInbox`, and never awaited: notifications can't delay or block the inbox. Omit to skip.
   */
  readonly startNotifications?: (identity: PinnedIdentity) => void;
}

/**
 * Resolve an element the static HTML shell must provide, or throw. Returning a non-nullable
 * `HTMLElement` (rather than narrowing `HTMLElement | null` inline) keeps the type non-null when
 * the element is later captured by {@link boot}'s nested closures.
 */
function requireElement(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`allw web approver: missing '#${id}' element in the static HTML shell`);
  }
  return element;
}

/** Prompt for a relay URL with {@link mountRelayConfigGate}; resolves once a valid one is entered. */
function promptForRelayUrl(
  root: HTMLElement,
  storage: Storage,
  initialError: string | null,
): Promise<string> {
  return new Promise((resolve) => {
    mountRelayConfigGate({ root, storage, initialError, onConfigured: resolve });
  });
}

/**
 * The relay for a browser with **no** stored identity: a `?relay=` candidate (persisted), the
 * persisted candidate, or one the human enters. A rejected `?relay=` (e.g. plain `http:` to a
 * remote host) is surfaced in the config prompt as an actionable error.
 */
function resolveCandidateRelayUrl(env: BootEnvironment): Promise<string> {
  const resolution = resolveRelayUrl({ search: env.search, storage: env.storage });
  if (resolution.relayUrl !== null && resolution.rejectedQueryReason === null) {
    return Promise.resolve(resolution.relayUrl);
  }
  return promptForRelayUrl(env.root, env.storage, resolution.rejectedQueryReason);
}

/**
 * The pinned relay for a browser **with** a stored identity. An identity stored before pinning
 * existed is bound once — to the relay this browser had already persisted, or to one the human
 * types — and re-saved. The `?relay=` query is never consulted here.
 */
async function resolvePinnedRelayUrl(
  env: BootEnvironment,
  stored: PairedIdentity,
  save: (identity: PairedIdentity) => void,
): Promise<string> {
  if (stored.relayUrl !== undefined) return stored.relayUrl;
  const legacyRelayUrl =
    readStoredRelayUrl(env.storage) ?? (await promptForRelayUrl(env.root, env.storage, null));
  save({ ...stored, relayUrl: legacyRelayUrl });
  return legacyRelayUrl;
}

/**
 * Load the vendored WASM core and mount the live inbox for a confirmed `identity`, sending every
 * relay call — inbox poll, `connect` WebSocket, account-state resolution — to its pinned
 * `relayUrl` and to nothing else. Resolves to the mount, whose `stop()` ends the poll loop. Any failure here (a stale/missing vendored artifact, a WASM
 * instantiation error) is allowed to reject — there is no safe UI to fall back to once pairing has
 * already confirmed a human is present, so a startup failure surfaces as an unhandled rejection
 * an operator can see in devtools rather than a silently blank inbox.
 */
export async function bootInbox(
  root: HTMLElement,
  identity: PinnedIdentity,
  wasm: InboxWasmSource = VENDORED_WASM,
): Promise<WebApproverMount> {
  const { relayUrl } = identity;
  const glueModule: unknown = await wasm.loadGlue();
  const runtime = await createBrowserRuntime({
    glueModule,
    moduleSource: wasm.moduleSource,
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

  return mountWebApprover({
    root,
    runtime,
    relay: {
      relayUrl,
      accountId: identity.accountId,
      deviceId: identity.deviceId,
      deviceAuthToken: identity.deviceAuthToken,
      pollIntervalMs: POLL_INTERVAL_MS,
      // Cross-device retraction (#150): a stable per-install surface id opens the live
      // `connect` WebSocket that removes a request as soon as another device resolves it.
      surfaceId: resolveSurfaceId(createLocalSurfaceIdStore()),
    },
  });
}

/**
 * The full boot sequence: relay URL (pinned if paired, candidate otherwise) → first-run
 * onboarding walkthrough (pre-enrollment only, #151) → pairing gate → (on success) WASM + live
 * inbox against the pinned relay.
 */
export async function boot(env: BootEnvironment): Promise<void> {
  const { root, storage } = env;
  const pairingStore = createLocalPairingStore(storage);
  const stored = pairingStore.load();

  let relayUrl: string;
  if (stored !== null) {
    relayUrl = await resolvePinnedRelayUrl(env, stored, (identity) => {
      pairingStore.save(identity);
    });
    const ignored = describeIgnoredRelayOverride(env.search, relayUrl);
    if (ignored !== null) {
      mountIgnoredRelayNotice({ host: env.noticeHost, ignored, pinnedRelayUrl: relayUrl });
    }
  } else {
    relayUrl = await resolveCandidateRelayUrl(env);
  }

  function startPairing(): void {
    mountPairingGate({
      root,
      pairingStore,
      // A new pairing (including "Use another device") pins this relay; a returning device keeps
      // the relay already pinned in its stored identity.
      relayUrl,
      onPaired: (identity) => {
        // Fail-closed: the gate always pins `relayUrl` above and a stored identity was bound
        // before the gate mounted, so an unpinned identity here is a programming error — never
        // fall back to an unpinned relay.
        if (identity.relayUrl === undefined) {
          throw new Error("allw web approver: paired identity has no pinned relay");
        }
        const pinned: PinnedIdentity = { ...identity, relayUrl: identity.relayUrl };
        void env.startInbox(root, pinned);
        env.startNotifications?.(pinned);
      },
    });
  }

  // The walkthrough is scoped to pre-enrollment (#151): an already-paired device (a stored
  // identity exists) skips straight to the pairing gate's returning-device screen, and a device
  // that has already completed/skipped the walkthrough is never shown it again.
  mountOnboardingGate({
    root,
    storage,
    hasStoredIdentity: stored !== null,
    onComplete: startPairing,
  });
}

/**
 * Mount the notification controls (#237) into `#notifications`, against the browser's real
 * service worker, Push API, Notifications API and IndexedDB.
 */
function startBrowserNotifications(identity: PinnedIdentity): void {
  mountNotificationControls({
    host: requireElement("notifications"),
    identity,
    env: browserPushEnvironment(window, createIndexedDbPushCredentialStore(window.indexedDB)),
  });
}

if (typeof window !== "undefined" && typeof document !== "undefined") {
  void boot({
    root: requireElement("app"),
    noticeHost: requireElement("notices"),
    storage: window.localStorage,
    search: window.location.search,
    startInbox: bootInbox,
    startNotifications: startBrowserNotifications,
  });
}

// Exported for the site-build integration test (`test/site-build.test.mjs`) to assert the bundle
// resolves the WASM asset URLs relative to its own module URL rather than an absolute build-time
// path — never imported by the production HTML shell, which only ever runs `boot()` above.
export { WASM_BINARY_URL, WASM_GLUE_URL };
