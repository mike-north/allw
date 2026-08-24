import {
  WebApproverController,
  type ApprovalDecision,
  type ApprovalEnvelope,
  type ApprovalStatus,
  type WebApproverRuntime,
} from "./index.js";
import { mountPairingGate, type PairingStore } from "./pairing.js";
import { createRelayPoller, type RelayPollerOptions } from "./relay-poll.js";
import {
  createRetractListener,
  type ConnectImpl,
  type ReconnectCanceller,
  type ReconnectScheduler,
} from "./retract-listener.js";

/** Configuration for automatic relay polling. When supplied, `fetchInbox` is ignored. */
export type RelayPollConfig = Pick<
  RelayPollerOptions,
  "relayUrl" | "accountId" | "deviceId" | "deviceAuthToken" | "pollIntervalMs" | "fetchImpl"
> & {
  /**
   * This install's persisted `surface_id` (`./surface-id.ts`, `docs/relay-api.md` §7.4). When
   * present, {@link mountWebApprover} also opens a live cross-device retraction listener (#150)
   * alongside the poll loop, so a request resolved on another device disappears from the inbox as
   * soon as the relay's `{type:"retract"}` message arrives — not just on the next poll tick.
   * Omit to keep the poll-only behavior from #147 (e.g. test harnesses that don't exercise the
   * WebSocket path).
   */
  readonly surfaceId?: string;
  /** Injectable WebSocket connector for the retraction listener; test-only. */
  readonly connectImpl?: ConnectImpl;
  /** Injectable reconnect scheduler for the retraction listener; test-only. */
  readonly scheduleReconnect?: ReconnectScheduler;
  /** Injectable reconnect canceller for the retraction listener; test-only. */
  readonly cancelReconnect?: ReconnectCanceller;
  /** Injectable jitter source for the retraction listener's reconnect backoff; test-only. */
  readonly randomImpl?: () => number;
};

interface BrowserConfig {
  readonly root: HTMLElement;
  readonly runtime: WebApproverRuntime;
  /**
   * Called on each successful poll tick to supply envelopes. Mutually exclusive with
   * {@link relay} — when `relay` is set, `fetchInbox` is ignored and the built-in poller drives
   * all syncs. Kept for test harnesses that drive the inbox through a fake fetch.
   */
  readonly fetchInbox?: () => Promise<readonly ApprovalEnvelope[]>;
  /**
   * When set, the browser mounts a live relay poller (issue #147). The poller fetches
   * `GET /{accountId}/devices/{deviceId}/inbox` on each tick, calls `controller.sync`, and
   * re-renders the inbox automatically. Overrides `fetchInbox` when both are present.
   */
  readonly relay?: RelayPollConfig;
  readonly nowMs?: () => number;
  /**
   * When set, {@link mountWebApprover} first renders the login/pairing-ceremony gate (issue #148).
   * The inbox is only rendered after the human has confirmed a valid stored identity or completed
   * the pairing ceremony. The gate renders into the same `root` element and replaces itself with
   * the inbox once pairing is confirmed.
   *
   * Omit to skip the gate (e.g. in tests that supply a pre-authenticated runtime directly).
   */
  readonly pairingStore?: PairingStore;
}

declare global {
  interface Window {
    allwWebApprover?: BrowserConfig;
  }
}

/**
 * The result of mounting the web approver.
 *
 * `controller` is always present. `stop` is a cleanup disposer: in the relay-polling path it
 * cancels the poll interval; in the manual/test path it is a harmless no-op (there is no interval
 * to cancel). Callers that unmount (e.g. SPA route changes) should always call `stop()` — it is
 * safe to call regardless of which path mounted, and safe to call more than once.
 */
export interface WebApproverMount {
  /** The mounted controller. */
  readonly controller: WebApproverController;
  /** Cancel the poll loop (relay path) or no-op (manual path). Idempotent. */
  readonly stop: () => void;
}

/**
 * Mount the web approver into `config.root`.
 *
 * When `config.pairingStore` is provided (issue #148), the login/pairing-ceremony gate renders
 * first. The inbox is only mounted after the human confirms a valid stored identity or completes
 * the pairing ceremony. An unpaired or failed-pairing state **never** reaches the approve-capable
 * inbox — fail-closed is structural.
 *
 * When `config.relay` is provided the inbox is kept live via a relay poll loop (issue #147):
 * the poller fires an initial tick immediately, then polls every `pollIntervalMs` (default 2s).
 * On outage the last-known inbox is preserved with an error banner — never fail-open. The refresh
 * (↻) button forces an immediate poll tick.
 *
 * When only `config.fetchInbox` is provided (test harness / manual mode) a single fetch is done
 * on mount and the returned controller can be re-synced manually.
 *
 * Returns a Promise that resolves to `{ controller, stop }`. `stop()` cancels the poll interval
 * in the relay path so callers can dispose the loop on unmount; in the manual path it is a no-op.
 *
 * When `pairingStore` is set the Promise resolves only after the gate hands off to the inbox —
 * i.e. after the human completes the pairing ceremony or confirms the returning-device screen.
 */
export async function mountWebApprover(config: BrowserConfig): Promise<WebApproverMount> {
  // Pairing gate (issue #148): render login/pairing before the inbox when a store is provided.
  // The Promise is resolved inside the `onPaired` callback, guaranteeing that the inbox is
  // mounted only after a valid identity is confirmed — fail-closed is structural.
  if (config.pairingStore) {
    const pairingStore = config.pairingStore;
    return new Promise<WebApproverMount>((resolve) => {
      mountPairingGate({
        root: config.root,
        pairingStore,
        onPaired: (_identity) => {
          // Identity confirmed — now mount the inbox (without the gate).
          void mountWebApproverInbox(config).then(resolve);
        },
      });
    });
  }

  return mountWebApproverInbox(config);
}

/**
 * The inner inbox-mount logic, separated so the pairing gate can call it after confirming an
 * identity without triggering the gate again.
 */
async function mountWebApproverInbox(config: BrowserConfig): Promise<WebApproverMount> {
  const controllerOptions = {
    runtime: config.runtime,
    ...(config.nowMs ? { nowMs: config.nowMs } : {}),
  };
  const controller = new WebApproverController(controllerOptions);

  if (config.relay) {
    // Live polling path (issue #147). The poller fires the first tick immediately and re-renders
    // on every outcome (success or failure). We render once eagerly so the shell is present before
    // the first poll settles. The refresh (↻) button forces an immediate poll tick.
    let lastError: string | null = null;

    function rerender(): void {
      if (lastError !== null) {
        renderWithOutage(config.root, controller, lastError, onRefresh);
      } else {
        render(config.root, controller, onRefresh);
      }
    }

    // The refresh (↻) button forces an immediate poll against the relay (not just a local repaint):
    // it triggers a real fetch, the controller syncs on success, and `onPollResult` repaints. We
    // also repaint defensively in case the poll rejects before `onPollResult` runs.
    function onRefresh(): void {
      void poller.poll().then(rerender, rerender);
    }

    // Render an empty-inbox shell immediately so the page is usable before the first poll.
    render(config.root, controller, onRefresh);

    const poller = createRelayPoller({
      ...config.relay,
      controller,
      onPollResult: (result) => {
        if (!result.ok) {
          // Preserve last-known inbox but show an outage banner — never fail-open.
          lastError = result.error;
        } else {
          // Successful poll — clear any outage banner.
          lastError = null;
        }
        rerender();
      },
    });

    // Live cross-device retraction listener (#150), opt-in via `surfaceId` (see `RelayPollConfig`
    // doc). `controller.retract` structurally removes the record (unreachable, not just hidden);
    // a successful removal repaints immediately rather than waiting for the next poll tick.
    const { relay } = config;
    const retractListener = relay.surfaceId
      ? createRetractListener({
          relayUrl: relay.relayUrl,
          accountId: relay.accountId,
          deviceId: relay.deviceId,
          deviceAuthToken: relay.deviceAuthToken,
          surfaceId: relay.surfaceId,
          ...(relay.connectImpl ? { connectImpl: relay.connectImpl } : {}),
          ...(relay.scheduleReconnect ? { scheduleReconnect: relay.scheduleReconnect } : {}),
          ...(relay.cancelReconnect ? { cancelReconnect: relay.cancelReconnect } : {}),
          ...(relay.randomImpl ? { randomImpl: relay.randomImpl } : {}),
          onRetract: (requestId) => {
            if (controller.retract(requestId)) {
              rerender();
            }
          },
        })
      : null;

    return {
      controller,
      stop: () => {
        poller.stop();
        retractListener?.stop();
      },
    };
  }

  // Manual / test path: a single fetch on mount; caller re-drives via returned controller.
  async function fetchAndSync(): Promise<void> {
    const fetchInbox = config.fetchInbox;
    if (!fetchInbox) {
      render(config.root, controller, () => {
        void fetchAndSync();
      });
      return;
    }
    const envelopes = await fetchInbox();
    await controller.sync(envelopes);
    render(config.root, controller, () => {
      void fetchAndSync();
    });
  }

  await fetchAndSync();
  // No poll loop in the manual path — `stop` is a no-op so callers can dispose uniformly.
  return { controller, stop: () => undefined };
}

function render(root: HTMLElement, controller: WebApproverController, refresh: () => void): void {
  root.replaceChildren();
  const shell = document.createElement("main");
  shell.className = "approver-shell";

  const header = document.createElement("header");
  header.className = "approver-header";
  header.append(textElement("h1", "allw approvals"));

  const refreshButton = document.createElement("button");
  refreshButton.type = "button";
  refreshButton.className = "icon-button";
  refreshButton.title = "Refresh approvals";
  refreshButton.textContent = "↻";
  refreshButton.addEventListener("click", refresh);
  header.append(refreshButton);
  shell.append(header);

  const inbox = section("Pending", controller.inbox(), controller, true, refresh);
  const history = section("History", controller.history(), controller, false, refresh);
  shell.append(inbox, history);
  root.append(shell);
}

/**
 * Render the current (stale) inbox with a visible outage banner. Called when a poll tick fails —
 * the inbox is not re-synced (last-known state is preserved) and the banner tells the user the
 * relay is unreachable. Fail-closed: this path never renders anything approved-looking.
 */
function renderWithOutage(
  root: HTMLElement,
  controller: WebApproverController,
  errorMessage: string,
  refresh: () => void,
): void {
  root.replaceChildren();
  const shell = document.createElement("main");
  shell.className = "approver-shell approver-shell--degraded";

  const header = document.createElement("header");
  header.className = "approver-header";
  header.append(textElement("h1", "allw approvals"));

  const refreshButton = document.createElement("button");
  refreshButton.type = "button";
  refreshButton.className = "icon-button";
  refreshButton.title = "Refresh approvals";
  refreshButton.textContent = "↻";
  refreshButton.addEventListener("click", refresh);
  header.append(refreshButton);
  shell.append(header);

  // Outage banner — visible but does not block the stale inbox below.
  const banner = document.createElement("div");
  banner.className = "relay-outage-banner";
  banner.setAttribute("role", "alert");
  banner.append(textElement("p", `Relay unavailable — showing last known inbox. ${errorMessage}`));
  shell.append(banner);

  const inbox = section("Pending", controller.inbox(), controller, true, refresh);
  const history = section("History", controller.history(), controller, false, refresh);
  shell.append(inbox, history);
  root.append(shell);
}

function section(
  title: string,
  items: readonly ReturnType<WebApproverController["inbox"]>[number][],
  controller: WebApproverController,
  interactive: boolean,
  refresh: () => void,
): HTMLElement {
  const sectionEl = document.createElement("section");
  sectionEl.className = "approver-section";
  sectionEl.append(textElement("h2", title));

  if (items.length === 0) {
    const empty = textElement(
      "p",
      title === "Pending" ? "No pending approvals." : "No resolved approvals.",
    );
    empty.className = "empty-state";
    sectionEl.append(empty);
    return sectionEl;
  }

  const list = document.createElement("div");
  list.className = "approval-list";
  for (const item of items) {
    list.append(card(item.id, controller, interactive, refresh));
  }
  sectionEl.append(list);
  return sectionEl;
}

function card(
  id: string,
  controller: WebApproverController,
  interactive: boolean,
  refresh: () => void,
): HTMLElement {
  const detail = controller.detail(id);
  if (!detail) {
    return document.createElement("article");
  }

  const article = document.createElement("article");
  article.className = `approval-card approval-card--${statusClass(detail.status)}`;
  article.append(textElement("h3", detail.summary));
  article.append(metaLine("Actor", detail.actor));
  article.append(
    metaLine("Risk", `${detail.riskLevel}${detail.reversible === false ? " · irreversible" : ""}`),
  );
  article.append(metaLine("Expires", `${String(Math.ceil(detail.countdownMs / 1000))}s`));
  article.append(metaLine("Request hash", detail.requestHash ?? "unverified"));

  const plaintext = document.createElement("pre");
  plaintext.className = "approval-plaintext";
  plaintext.textContent = detail.exactPlaintext;
  article.append(plaintext);

  if (detail.verificationError) {
    const warning = textElement("p", `Verification failed: ${detail.verificationError}`);
    warning.className = "verification-warning";
    article.append(warning);
  }

  if (interactive) {
    article.append(decisionControls(id, controller, refresh));
  }
  return article;
}

function decisionControls(
  id: string,
  controller: WebApproverController,
  refresh: () => void,
): HTMLElement {
  const form = document.createElement("form");
  form.className = "decision-controls";
  const detail = controller.detail(id);
  const challenge = detail?.challenge;

  const challengeInput = document.createElement("input");
  challengeInput.name = "challenge";
  challengeInput.inputMode = "numeric";
  challengeInput.autocomplete = "one-time-code";
  challengeInput.placeholder = challenge?.prompt ?? "Number match";
  challengeInput.hidden = !challenge;

  const deny = button("Deny", "denied");
  const approve = button("Approve", "approved");
  approve.disabled = !controller.canApprove(id);

  challengeInput.addEventListener("input", () => {
    approve.disabled = !controller.canApprove(id, { challengeResponse: challengeInput.value });
  });

  form.append(challengeInput, deny, approve);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const submitter = event.submitter;
    const decision =
      submitter instanceof HTMLButtonElement && isDecision(submitter.value)
        ? submitter.value
        : "denied";
    const challengeResponse = challengeInput.value || undefined;
    deny.disabled = true;
    approve.disabled = true;
    challengeInput.disabled = true;
    void controller
      .decide(id, decision, {
        ...(challengeResponse ? { challengeResponse } : {}),
      })
      .then(refresh, refresh);
  });
  return form;
}

function button(label: string, value: ApprovalDecision): HTMLButtonElement {
  const buttonEl = document.createElement("button");
  buttonEl.type = "submit";
  buttonEl.name = "decision";
  buttonEl.value = value;
  buttonEl.textContent = label;
  return buttonEl;
}

function isDecision(value: string): value is ApprovalDecision {
  return value === "approved" || value === "denied";
}

function metaLine(label: string, value: string): HTMLElement {
  const line = document.createElement("p");
  line.className = "approval-meta";
  line.append(textElement("strong", `${label}: `), document.createTextNode(value));
  return line;
}

function textElement<Tag extends keyof HTMLElementTagNameMap>(
  tag: Tag,
  text: string,
): HTMLElementTagNameMap[Tag] {
  const element = document.createElement(tag);
  element.textContent = text;
  return element;
}

function statusClass(status: ApprovalStatus): string {
  return status.replaceAll(" ", "-");
}

if (typeof window !== "undefined" && window.allwWebApprover) {
  void mountWebApprover(window.allwWebApprover);
}
