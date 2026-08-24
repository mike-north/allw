/**
 * First-run onboarding walkthrough (issue #151, slice of #93).
 *
 * Explains three concepts before a new user ever sees the pairing form: the human-in-the-loop
 * approval model, WYSIWYS ("what you see is what you sign"), and the number-match challenge used
 * for destructive/high-risk actions. This is a **purely explanatory** flow — it renders no
 * approve/deny controls and holds no `WebApproverController`/`WebApproverRuntime` reference, so
 * there is no path from this module into the approve-capable inbox. The only way forward is
 * {@link mountOnboardingGate}'s `onComplete` callback, which `src/app.ts` wires to the existing
 * pairing gate (`./pairing.ts`) — the inbox remains reachable only through that gate's
 * already-fail-closed `onPaired` callback.
 *
 * # "Show only pre-enrollment" (issue #151's scope line)
 *
 * {@link mountOnboardingGate} renders the walkthrough only when **both**:
 *   1. no device identity is already stored (`hasStoredIdentity: false` — an enrolled/returning
 *      device skips straight to the pairing gate's returning-device screen), and
 *   2. the walkthrough has not already been completed or skipped on this browser
 *      (`allw:onboarding:v1` in `localStorage`, mirroring `./pairing.ts`'s `allw:pairing:v1` and
 *      `./relay-config.ts`'s `allw:relay-url:v1` storage-seam convention).
 *
 * Once either is true, `onComplete` fires immediately and nothing is rendered — a returning or
 * previously-onboarded user is never re-shown the walkthrough.
 *
 * @see design/web-approver/onboarding/flow-notes.md (flow design — pairing ceremony + trust framing)
 * @see design/web-approver/onboarding/app.jsx (visual source of truth for kicker/headline/subcopy shape)
 * @see design/web-approver/inbox/tokens.css (verbatim token source, via public/tokens.css)
 * @see docs/contract.md §Invariants, §WYSIWYS, §number-match challenge derivation
 * @see ./pairing.ts (the gate this walkthrough hands off to)
 */

// ── Persistence seam ─────────────────────────────────────────────────────────────────────────────

/** The `localStorage` key recording that this browser has completed (or skipped) the walkthrough. */
const ONBOARDING_STORAGE_KEY = "allw:onboarding:v1";

/** Returns `true` if this browser has already completed or skipped the walkthrough. */
export function isOnboardingComplete(storage: Storage): boolean {
  try {
    return storage.getItem(ONBOARDING_STORAGE_KEY) !== null;
  } catch {
    // A storage read failure (e.g. disabled localStorage) is treated as "not yet onboarded" —
    // the walkthrough is explanatory only, so re-showing it is a UX cost, never a safety issue.
    return false;
  }
}

/** Record that this browser has completed (or skipped) the walkthrough. */
function markOnboardingComplete(storage: Storage): void {
  try {
    storage.setItem(ONBOARDING_STORAGE_KEY, "1");
  } catch {
    // Best-effort; a storage write failure just means the walkthrough may show again next visit.
  }
}

// ── Walkthrough content ──────────────────────────────────────────────────────────────────────────

interface OnboardingStep {
  readonly kicker: string;
  readonly headline: string;
  readonly subcopy: string;
  readonly bullets: readonly string[];
}

/**
 * The three explanatory steps required by issue #151: the approval model, WYSIWYS, and
 * number-match. Copy is derived from `docs/contract.md`'s invariants and wire-format sections
 * (never from implementation internals) so it stays accurate as the authoritative source evolves.
 */
const STEPS: readonly OnboardingStep[] = [
  {
    kicker: "Human-in-the-loop approvals",
    headline: "Every sensitive action waits for you.",
    subcopy:
      "allw pauses an agent's high-risk actions and asks you — a human — to approve or deny. It is not a password and not a standing rule that silently grants access; a verdict only ever tightens what the agent can do.",
    bullets: [
      "Approvals never happen automatically — a human decides.",
      "No response, timeout, or unverifiable signature ⇒ the action is denied.",
      "A verdict can only make access stricter, never grant it on its own.",
    ],
  },
  {
    kicker: "What you see is what you sign",
    headline: "You approve exactly what you saw.",
    subcopy:
      "Before you decide, allw decrypts and shows you the exact command or tool call an agent wants to run — on this device only. Your decision is cryptographically bound to that precise content.",
    bullets: [
      "The approval context is decrypted and rendered on this device only.",
      "Your signed verdict binds to a hash of exactly what you were shown.",
      "Any tampering with the request after you decide invalidates the signature.",
    ],
  },
  {
    kicker: "Number-match for high-risk actions",
    headline: "A short code confirms it's really you.",
    subcopy:
      "For destructive or irreversible actions, allw shows a short code you must re-enter to approve. Re-typing it proves a human deliberately confirmed this specific request.",
    bullets: [
      "Only shown for actions flagged as destructive or high-risk.",
      "The code is derived from the exact request you're approving.",
      "Denials never need the code — only approvals do.",
    ],
  },
];

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

// ── Walkthrough renderer ─────────────────────────────────────────────────────────────────────────

/** Options for {@link mountOnboardingWalkthrough}. */
export interface OnboardingWalkthroughOptions {
  /** The DOM element to render the walkthrough into. */
  readonly root: HTMLElement;
  /**
   * Injectable storage seam for the "already onboarded" flag persisted on completion/skip.
   * Defaults to `window.localStorage`.
   */
  readonly storage?: Storage;
  /**
   * Called exactly once, either after the final step's "Continue to pairing" click or after
   * "Skip walkthrough". The caller (see {@link mountOnboardingGate}) is responsible for mounting
   * whatever comes next (the pairing gate) — this module never does so itself.
   */
  readonly onComplete: () => void;
}

/**
 * Render the onboarding walkthrough into `options.root`, starting at the first step. Renders one
 * step at a time with "Back"/"Continue" navigation, a step-progress indicator, and a "Skip
 * walkthrough" control available from any step. `onComplete` is invoked exactly once — never
 * called more than once, and never bypassed silently.
 */
export function mountOnboardingWalkthrough(options: OnboardingWalkthroughOptions): void {
  const { root, onComplete } = options;
  const storage = options.storage ?? window.localStorage;
  let index = 0;
  let completed = false;

  function complete(): void {
    if (completed) return;
    completed = true;
    onComplete();
  }

  function render(): void {
    root.replaceChildren();
    const step = STEPS[index];
    if (!step) {
      throw new Error(`onboarding walkthrough: step index ${String(index)} is out of range`);
    }
    const isLast = index === STEPS.length - 1;

    const shell = el("div", "onboarding-shell");

    const header = el("header", "onboarding-header");
    header.append(text("h1", "allw approvals", "onboarding-wordmark"));
    const skipBtn = el("button", "onboarding-skip");
    skipBtn.type = "button";
    skipBtn.textContent = "Skip walkthrough";
    skipBtn.addEventListener("click", () => {
      markOnboardingComplete(storage);
      complete();
    });
    header.append(skipBtn);
    shell.append(header);

    const screen = el("section", "onboarding-screen");
    screen.setAttribute("aria-labelledby", "onboarding-title");

    const progress = el("div", "onboarding-progress");
    progress.setAttribute("role", "progressbar");
    progress.setAttribute("aria-valuemin", "1");
    progress.setAttribute("aria-valuemax", String(STEPS.length));
    progress.setAttribute("aria-valuenow", String(index + 1));
    progress.setAttribute("aria-label", `Step ${String(index + 1)} of ${String(STEPS.length)}`);
    for (let dotIndex = 0; dotIndex < STEPS.length; dotIndex++) {
      const dot = el("span", "onboarding-dot");
      if (dotIndex === index) dot.classList.add("onboarding-dot--active");
      progress.append(dot);
    }
    screen.append(progress);

    screen.append(text("div", step.kicker, "onboarding-kicker"));

    const headline = text("h2", step.headline, "onboarding-headline");
    headline.id = "onboarding-title";
    screen.append(headline);

    screen.append(text("p", step.subcopy, "onboarding-subcopy"));

    const list = el("ul", "onboarding-list");
    for (const item of step.bullets) {
      const li = el("li", "onboarding-list-item");
      const check = text("span", "✓", "onboarding-check");
      // Decorative only — hide from assistive tech so screen readers announce just the bullet text.
      check.setAttribute("aria-hidden", "true");
      li.append(check, text("span", item));
      list.append(li);
    }
    screen.append(list);

    const actions = el("div", "onboarding-actions");

    if (index > 0) {
      const backBtn = el("button", "onboarding-btn onboarding-btn--secondary");
      backBtn.type = "button";
      backBtn.textContent = "Back";
      backBtn.addEventListener("click", () => {
        index -= 1;
        render();
      });
      actions.append(backBtn);
    }

    const nextBtn = el("button", "onboarding-btn onboarding-btn--primary");
    nextBtn.type = "button";
    nextBtn.textContent = isLast ? "Continue to pairing" : "Continue";
    nextBtn.addEventListener("click", () => {
      if (isLast) {
        markOnboardingComplete(storage);
        complete();
        return;
      }
      index += 1;
      render();
    });
    actions.append(nextBtn);

    screen.append(actions);
    shell.append(screen);
    root.append(shell);
  }

  render();
}

// ── Gate entry point ─────────────────────────────────────────────────────────────────────────────

/** Options for {@link mountOnboardingGate}. */
export interface OnboardingGateOptions {
  /** The DOM element to render the walkthrough into (when shown). */
  readonly root: HTMLElement;
  /** Injectable storage seam for the "already onboarded" flag. Production callers pass `window.localStorage`. */
  readonly storage: Storage;
  /**
   * Whether a device identity is already stored (i.e. this browser is already paired). When
   * `true` the walkthrough is never shown — issue #151 scopes this flow to pre-enrollment only.
   */
  readonly hasStoredIdentity: boolean;
  /**
   * Called once the walkthrough should hand off to the next step of the boot sequence (the
   * pairing gate). Fires immediately, without rendering anything, when the walkthrough is
   * skipped by the pre-enrollment gating above.
   */
  readonly onComplete: () => void;
}

/**
 * Gate the onboarding walkthrough behind "pre-enrollment and not already shown" (issue #151).
 *
 * - **Already paired** (`hasStoredIdentity: true`) → `onComplete` fires immediately; the
 *   walkthrough is never rendered for an enrolled device.
 * - **Already onboarded** (`allw:onboarding:v1` set) → `onComplete` fires immediately.
 * - **Otherwise** → the walkthrough renders; `onComplete` fires (and the flag is persisted) once
 *   the human reaches the final step's "Continue to pairing" or clicks "Skip walkthrough".
 *
 * This function holds no reference to `WebApproverController`/`WebApproverRuntime` — it can only
 * ever call `onComplete`, never mount an approve-capable surface itself.
 */
export function mountOnboardingGate(options: OnboardingGateOptions): void {
  const { root, storage, hasStoredIdentity, onComplete } = options;
  if (hasStoredIdentity || isOnboardingComplete(storage)) {
    onComplete();
    return;
  }
  mountOnboardingWalkthrough({ root, storage, onComplete });
}
