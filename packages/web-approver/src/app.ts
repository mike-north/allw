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
 * - **Re-pair required** (#286) — the stored identity is pinned to a relay this build rejects. Before
 *   any relay is resolved or asked for, a screen names that relay and why; the identity is cleared
 *   only when the human confirms (and only if it is still the stored one). The browser then pairs
 *   again, but as a **previously paired** browser, like the legacy binding above: a `?relay=` link
 *   is ignored (with the notice) and never persisted, and the relay comes from the candidate this
 *   browser had already persisted, or from the human.
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
import { deviceDetailsModel, mountDeviceDetails } from "./device-details.js";
import { mountOnboardingGate } from "./onboarding.js";
import {
  createLocalPairingStore,
  mountPairingGate,
  mountRelayRepairGate,
  type DisplayEscape,
  type PairedIdentity,
  type PairingStore,
  type RejectedRelayPin,
} from "./pairing.js";
import {
  describeIgnoredRelayOverride,
  mountIgnoredRelayNotice,
  mountRelayConfigGate,
  readStoredRelayUrl,
  resolveRelayUrl,
} from "./relay-config.js";
import {
  createIndexedDbPushCredentialStore,
  pushCredentialsFrom,
  type PushCredentials,
} from "./push-credentials.js";
import {
  browserForgetNotificationsDeps,
  browserPushEnvironment,
  forgetNotifications,
  mountNotificationControls,
} from "./push-subscribe.js";
import { createBrowserRuntime } from "./runtime.js";
import { createLocalAccountStateFloorStore } from "./sequence-floor.js";
import { createLocalSurfaceIdStore, resolveSurfaceId } from "./surface-id.js";
import { initWasm, type WasmModuleSource } from "./wasm.js";

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
   * Load the core's display escape (#246) for the re-pair screen (#286), which shows a stored relay
   * string before the inbox (and so before the runtime) loads. Production initializes the vendored
   * WASM core, which is memoized and reused by the inbox. The ignored-relay notice (#307) gets its
   * escape from the same seam. When omitted, when it rejects, or when it does not resolve within
   * {@link DISPLAY_ESCAPE_LOAD_TIMEOUT_MS} (#308), the re-pair screen withholds the pin text and
   * the notice withholds the ignored link's name rather than print either unescaped.
   */
  readonly loadDisplayEscape?: () => Promise<DisplayEscape>;
  /**
   * Mount the notification controls (#237) for a paired identity, outside the inbox. Called after
   * `startInbox`, and never awaited: notifications can't delay or block the inbox. Omit to skip.
   * `isStillPaired` reports whether that identity is still this browser's pairing (another tab may
   * forget or replace it), so the controls never re-mirror or re-register a forgotten identity.
   */
  readonly startNotifications?: (identity: PinnedIdentity, isStillPaired: () => boolean) => void;
  /**
   * Mount the "This device" panel (#381) for a paired identity, outside the inbox: the device id,
   * public keys and fingerprints the root holder needs for `allw-approver vouch`. Never awaited.
   */
  readonly startDeviceDetails?: (identity: PinnedIdentity) => void;
  /**
   * Undo notifications for a forgotten pairing (#237): clear the service worker's credential
   * mirror, then best-effort clear the browser's subscription and the relay's push tokens. Called
   * whenever the pairing store clears an identity, and at boot when no identity is stored (absent or
   * corrupt), so the mirrored bearer token never outlives the identity it came from. Never awaited.
   * `forgotten` holds the relay credentials of the identity being cleared, when it was a pinned
   * pairing: the token source for withdrawing its registration if the mirror is already empty.
   */
  readonly forgetNotifications?: (forgotten: PushCredentials | null) => Promise<void>;
}

/**
 * `store`, except that clearing an identity also runs `forget` (not awaited). Every path that
 * forgets the pairing ("Use another device", a corrupt identity, confirming a re-pair) goes through
 * `clear` or a successful `clearIfUnchanged`, so none of them can leave a notification credential
 * behind. A `clearIfUnchanged` that keeps a newer identity (another tab re-paired) forgets nothing.
 */
function clearingNotifications(
  store: PairingStore,
  forget: ((forgotten: PushCredentials | null) => Promise<void>) | undefined,
): PairingStore {
  if (forget === undefined) return store;
  /** The relay credentials of the identity stored right now, if it is a pinned pairing. */
  function storedCredentials(): PushCredentials | null {
    const stored = store.load();
    if (stored.status !== "paired") return null;
    const { relayUrl } = stored.identity;
    return relayUrl === undefined ? null : pushCredentialsFrom({ ...stored.identity, relayUrl });
  }
  return {
    load: () => store.load(),
    save: (identity) => {
      store.save(identity);
    },
    clear: () => {
      const forgotten = storedCredentials();
      store.clear();
      void forget(forgotten);
    },
    clearIfUnchanged: (snapshot) => {
      const forgotten = storedCredentials();
      const cleared = store.clearIfUnchanged(snapshot);
      if (cleared) void forget(forgotten);
      return cleared;
    },
  };
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
 * The relay for a browser re-pairing after a rejected pin (#286, decision D1). It was paired
 * before, so, like the legacy binding in {@link resolvePinnedRelayUrl}, a `?relay=` link is never
 * used or persisted: the relay is the candidate this browser already persisted, or one the human
 * types.
 */
async function resolveRepairRelayUrl(env: BootEnvironment): Promise<string> {
  return readStoredRelayUrl(env.storage) ?? (await promptForRelayUrl(env.root, env.storage, null));
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
 * Show the re-pair-required state (#286) and resolve once the human has confirmed. The rejected
 * identity has then been cleared if it was still the stored one; the caller re-loads the store.
 * Never resolves if the human leaves instead, so nothing is cleared.
 */
function confirmRelayRepair(
  root: HTMLElement,
  pairingStore: PairingStore,
  rejected: RejectedRelayPin,
  escapeForDisplay: DisplayEscape | null,
): Promise<void> {
  return new Promise((resolve) => {
    mountRelayRepairGate({ root, pairingStore, rejected, escapeForDisplay, onResolved: resolve });
  });
}

/**
 * How long boot waits for the core's display escape before it shows untrusted text withheld
 * (#308): the re-pair screen's stored pin (#286) and the ignored-relay notice's link (#307).
 *
 * The core is a ~1 MB WASM fetch. Without a bound, a stalled fetch (a slow or captive network)
 * left the re-pair screen blank with no explanation. Five seconds is long enough for a normal
 * connection and short enough that a human isn't left looking at an empty page. Missing it only
 * withholds that text: the re-pair confirm and the notice are shown either way, and a core that
 * arrives later still serves the inbox (`initWasm` is memoized) without changing what was shown.
 */
export const DISPLAY_ESCAPE_LOAD_TIMEOUT_MS = 5_000;

/**
 * The core display escape from `env`, or `null` when it is not provided, fails to load, or does
 * not load within {@link DISPLAY_ESCAPE_LOAD_TIMEOUT_MS}. Never rejects.
 */
async function loadDisplayEscape(env: BootEnvironment): Promise<DisplayEscape | null> {
  const load = env.loadDisplayEscape;
  if (load === undefined) return null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<null>((resolve) => {
    timer = setTimeout(() => {
      resolve(null);
    }, DISPLAY_ESCAPE_LOAD_TIMEOUT_MS);
  });
  const loaded = (async () => {
    try {
      return await load();
    } catch {
      return null;
    }
  })();
  try {
    // A core that settles in the same macrotask as the deadline loses the race: `loaded` is two
    // microtask hops behind the deadline's direct `resolve(null)`. That is fail-safe and intended:
    // the text is withheld, not printed raw, and the screen is rendered once either way. Don't
    // "fix" the tie in the core's favour.
    return await Promise.race([loaded, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/** The core's `escape_for_display`, from the vendored WASM (memoized; the inbox reuses it). */
async function loadVendoredDisplayEscape(): Promise<DisplayEscape> {
  const wasm = await initWasm(await VENDORED_WASM.loadGlue(), VENDORED_WASM.moduleSource);
  return (text) => wasm.escape_for_display(text);
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
 * The full boot sequence: re-pair confirmation if the stored pin is rejected (#286) → relay URL
 * (pinned if paired, candidate otherwise) → first-run
 * onboarding walkthrough (pre-enrollment only, #151) → pairing gate → (on success) WASM + live
 * inbox against the pinned relay.
 */
export async function boot(env: BootEnvironment): Promise<void> {
  const { root, storage } = env;
  const pairingStore = clearingNotifications(
    createLocalPairingStore(storage),
    env.forgetNotifications,
  );
  let loaded = pairingStore.load();
  // No identity stored (absent or corrupt): whatever a previous pairing mirrored for notifications
  // is stale. A rejected pin is forgotten only if the human confirms (via `clearIfUnchanged`).
  if (loaded.status === "absent" || loaded.status === "corrupt")
    void env.forgetNotifications?.(null);
  let repairing = false;
  let escapeForDisplay: DisplayEscape | null = null;
  if (loaded.status === "relay-pin-rejected") {
    escapeForDisplay = await loadDisplayEscape(env);
    await confirmRelayRepair(root, pairingStore, loaded, escapeForDisplay);
    repairing = true;
    loaded = pairingStore.load();
  }
  const stored = loaded.status === "paired" ? loaded.identity : null;

  let relayUrl: string;
  if (stored !== null || repairing) {
    relayUrl =
      stored !== null
        ? await resolvePinnedRelayUrl(env, stored, (identity) => {
            pairingStore.save(identity);
          })
        : await resolveRepairRelayUrl(env);
    const ignored = describeIgnoredRelayOverride(env.search, relayUrl);
    if (ignored !== null) {
      // Rendered now, never awaited: the ignored link's name is filled in once the core escape is
      // available (#307). A re-pair visit already tried to load it; otherwise start the load here
      // (`initWasm` shares it with the inbox's).
      void mountIgnoredRelayNotice({
        host: env.noticeHost,
        ignored,
        pinnedRelayUrl: relayUrl,
        repairing: stored === null,
        escapeForDisplay: repairing ? Promise.resolve(escapeForDisplay) : loadDisplayEscape(env),
      });
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
      ...(escapeForDisplay === null ? {} : { escapeForDisplay }),
      onPaired: (identity) => {
        // Fail-closed: the gate always pins `relayUrl` above and a stored identity was bound
        // before the gate mounted, so an unpinned identity here is a programming error — never
        // fall back to an unpinned relay.
        if (identity.relayUrl === undefined) {
          throw new Error("allw web approver: paired identity has no pinned relay");
        }
        const pinned: PinnedIdentity = { ...identity, relayUrl: identity.relayUrl };
        void env.startInbox(root, pinned);
        env.startDeviceDetails?.(pinned);
        env.startNotifications?.(pinned, () => {
          // Another tab may forget or replace the pairing while this one stays open.
          const now = pairingStore.load();
          return (
            now.status === "paired" &&
            now.identity.deviceId === pinned.deviceId &&
            now.identity.deviceAuthToken === pinned.deviceAuthToken
          );
        });
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
function startBrowserNotifications(identity: PinnedIdentity, isStillPaired: () => boolean): void {
  mountNotificationControls({
    host: requireElement("notifications"),
    identity,
    isStillPaired,
    env: browserPushEnvironment(window, createIndexedDbPushCredentialStore(window.indexedDB)),
  });
}

/** Mount the "This device" panel (#381) into `#device`, with fingerprints from the vendored core. */
async function startBrowserDeviceDetails(identity: PinnedIdentity): Promise<void> {
  const wasm = await initWasm(await VENDORED_WASM.loadGlue(), VENDORED_WASM.moduleSource);
  mountDeviceDetails({
    host: requireElement("device"),
    model: deviceDetailsModel(wasm, identity),
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
    startDeviceDetails: (identity) => {
      void startBrowserDeviceDetails(identity);
    },
    forgetNotifications: (forgotten) =>
      forgetNotifications(
        browserForgetNotificationsDeps(
          window,
          createIndexedDbPushCredentialStore(window.indexedDB),
        ),
        forgotten,
      ),
    loadDisplayEscape: loadVendoredDisplayEscape,
  });
}

// Exported for the site-build integration test (`test/site-build.test.mjs`) to assert the bundle
// resolves the WASM asset URLs relative to its own module URL rather than an absolute build-time
// path — never imported by the production HTML shell, which only ever runs `boot()` above.
export { WASM_BINARY_URL, WASM_GLUE_URL };
