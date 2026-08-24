/**
 * Tests for the first-run onboarding walkthrough (issue #151).
 *
 * Maps to issue #151's acceptance criteria:
 *
 *   - "explain the approval model" → covered by "walkthrough explains the human-in-the-loop
 *     approval model on the first step".
 *   - "explain ... number-match" → covered by "walkthrough explains the number-match challenge
 *     on the final step".
 *   - "explain ... WYSIWYS" → covered by "walkthrough explains WYSIWYS on the second step".
 *   - "Show only pre-enrollment" → covered by "mountOnboardingGate skips the walkthrough when a
 *     device identity is already stored" and "...skips the walkthrough once already
 *     completed/skipped".
 *   - "Wire into the app.ts boot sequence as a first-run flow (localStorage-flagged)" → covered
 *     by "completing the walkthrough persists the flag" and "isOnboardingComplete" describe
 *     block, plus "skipping the walkthrough persists the flag".
 *   - "onboarding must never make the approve path reachable before a root-verified identity
 *     exists" → covered by "the walkthrough renders no approve/deny controls" and "onComplete
 *     fires exactly once, never more".
 *
 * @see ../src/onboarding.ts
 * @see design/web-approver/onboarding/flow-notes.md
 * @see docs/contract.md §Invariants #6 (fail-closed), §WYSIWYS, §number-match challenge derivation
 */

import assert from "node:assert/strict";
import test, { describe } from "node:test";

import { JSDOM } from "jsdom";

import {
  isOnboardingComplete,
  mountOnboardingGate,
  mountOnboardingWalkthrough,
} from "../dist/onboarding.js";

// ── Fixture helpers ───────────────────────────────────────────────────────

/** A fake in-memory Storage implementation, avoiding a dependency on real `localStorage`. */
function memoryStorage() {
  const map = new Map();
  return {
    getItem(key) {
      return map.has(key) ? map.get(key) : null;
    },
    setItem(key, value) {
      map.set(key, value);
    },
    removeItem(key) {
      map.delete(key);
    },
    get size() {
      return map.size;
    },
  };
}

/**
 * A storage stub whose `getItem`/`setItem` always throw — exercises the fail-soft (never
 * fail-closed-on-storage-error, since this flow is explanatory only) branches.
 */
function throwingStorage() {
  return {
    getItem() {
      throw new Error("storage unavailable");
    },
    setItem() {
      throw new Error("storage unavailable");
    },
    removeItem() {
      throw new Error("storage unavailable");
    },
  };
}

/** Install a fresh jsdom and the `document`/`window` globals `onboarding.ts` reads. */
function installDom() {
  const dom = new JSDOM('<div id="app"></div>', { url: "https://approver.local/" });
  const root = dom.window.document.getElementById("app");
  const saved = { document: globalThis.document, window: globalThis.window };
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  return {
    root,
    restore() {
      globalThis.document = saved.document;
      globalThis.window = saved.window;
    },
  };
}

function findButtonByText(root, label) {
  return [...root.querySelectorAll("button")].find((b) => b.textContent === label);
}

// ── isOnboardingComplete / persistence ─────────────────────────────────────

describe("isOnboardingComplete", () => {
  test("returns false when nothing is stored", () => {
    assert.equal(isOnboardingComplete(memoryStorage()), false);
  });

  test("returns true once the walkthrough has recorded completion", () => {
    const storage = memoryStorage();
    storage.setItem("allw:onboarding:v1", "1");
    assert.equal(isOnboardingComplete(storage), true);
  });

  test("returns false (fail-soft) when storage reads throw", () => {
    assert.equal(isOnboardingComplete(throwingStorage()), false);
  });
});

// ── mountOnboardingWalkthrough: required explanatory content ───────────────

describe("mountOnboardingWalkthrough — required explanatory content", () => {
  test("first step explains the human-in-the-loop approval model", () => {
    const { root, restore } = installDom();
    try {
      mountOnboardingWalkthrough({ root, storage: memoryStorage(), onComplete: () => undefined });
      const screenText = root.querySelector(".onboarding-screen").textContent;
      assert.match(screenText, /human/i, "first step must explain the human-in-the-loop model");
      assert.match(screenText, /approve or deny/i);
      assert.match(screenText, /denied/i, "must explain fail-closed default");
    } finally {
      restore();
    }
  });

  test("second step explains WYSIWYS", () => {
    const { root, restore } = installDom();
    try {
      mountOnboardingWalkthrough({ root, storage: memoryStorage(), onComplete: () => undefined });
      findButtonByText(root, "Continue").click();
      const screenText = root.querySelector(".onboarding-screen").textContent;
      assert.match(screenText, /what you see is what you sign/i);
      assert.match(screenText, /exact/i);
    } finally {
      restore();
    }
  });

  test("third (final) step explains the number-match challenge", () => {
    const { root, restore } = installDom();
    try {
      mountOnboardingWalkthrough({ root, storage: memoryStorage(), onComplete: () => undefined });
      findButtonByText(root, "Continue").click();
      findButtonByText(root, "Continue").click();
      const screenText = root.querySelector(".onboarding-screen").textContent;
      assert.match(screenText, /number-match/i);
      assert.match(screenText, /code/i);
      assert.ok(
        findButtonByText(root, "Continue to pairing"),
        "final step's CTA must read 'Continue to pairing'",
      );
    } finally {
      restore();
    }
  });

  test("progress indicator reflects the current step (aria-valuenow)", () => {
    const { root, restore } = installDom();
    try {
      mountOnboardingWalkthrough({ root, storage: memoryStorage(), onComplete: () => undefined });
      const progress = root.querySelector(".onboarding-progress");
      assert.equal(progress.getAttribute("aria-valuenow"), "1");
      assert.equal(progress.getAttribute("aria-valuemax"), "3");

      findButtonByText(root, "Continue").click();
      assert.equal(root.querySelector(".onboarding-progress").getAttribute("aria-valuenow"), "2");
    } finally {
      restore();
    }
  });

  test("'Back' returns to the previous step and is absent on the first step", () => {
    const { root, restore } = installDom();
    try {
      mountOnboardingWalkthrough({ root, storage: memoryStorage(), onComplete: () => undefined });
      assert.equal(findButtonByText(root, "Back"), undefined, "no Back button on the first step");

      findButtonByText(root, "Continue").click();
      const backBtn = findButtonByText(root, "Back");
      assert.ok(backBtn, "Back button present on the second step");

      backBtn.click();
      assert.match(
        root.querySelector(".onboarding-screen").textContent,
        /human-in-the-loop approvals/i,
      );
    } finally {
      restore();
    }
  });
});

// ── mountOnboardingWalkthrough: completion / skip / onComplete contract ────

describe("mountOnboardingWalkthrough — completion and onComplete contract", () => {
  test("completing all steps persists the flag and calls onComplete exactly once", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      let completions = 0;
      mountOnboardingWalkthrough({
        root,
        storage,
        onComplete: () => {
          completions += 1;
        },
      });

      findButtonByText(root, "Continue").click();
      findButtonByText(root, "Continue").click();
      assert.equal(completions, 0, "onComplete must not fire before the final CTA");

      findButtonByText(root, "Continue to pairing").click();

      assert.equal(completions, 1, "onComplete fires exactly once after the final step");
      assert.equal(isOnboardingComplete(storage), true, "completion flag must be persisted");
    } finally {
      restore();
    }
  });

  test("'Skip walkthrough' persists the flag and calls onComplete immediately", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      let completions = 0;
      mountOnboardingWalkthrough({
        root,
        storage,
        onComplete: () => {
          completions += 1;
        },
      });

      const skipBtn = findButtonByText(root, "Skip walkthrough");
      assert.ok(skipBtn, "Skip walkthrough control must be present");
      skipBtn.click();

      assert.equal(completions, 1);
      assert.equal(isOnboardingComplete(storage), true);
    } finally {
      restore();
    }
  });

  test("the walkthrough renders no approve/deny controls (structural: cannot reach the approve path)", () => {
    const { root, restore } = installDom();
    try {
      mountOnboardingWalkthrough({ root, storage: memoryStorage(), onComplete: () => undefined });
      for (let i = 0; i < 2; i++) {
        assert.equal(findButtonByText(root, "Approve"), undefined);
        assert.equal(findButtonByText(root, "Deny"), undefined);
        assert.equal(root.querySelector(".approver-shell"), null);
        assert.equal(root.querySelector("form.pairing-form"), null);
        const next =
          findButtonByText(root, "Continue") ?? findButtonByText(root, "Continue to pairing");
        next.click();
      }
    } finally {
      restore();
    }
  });
});

// ── mountOnboardingGate: pre-enrollment scoping (issue #151's "Show only pre-enrollment") ──

describe("mountOnboardingGate — pre-enrollment scoping", () => {
  test("renders the walkthrough when there is no stored identity and it has not been shown before", () => {
    const { root, restore } = installDom();
    try {
      let completions = 0;
      mountOnboardingGate({
        root,
        storage: memoryStorage(),
        hasStoredIdentity: false,
        onComplete: () => {
          completions += 1;
        },
      });

      assert.ok(root.querySelector(".onboarding-shell"), "walkthrough must be rendered");
      assert.equal(completions, 0, "onComplete must not fire before the walkthrough completes");
    } finally {
      restore();
    }
  });

  test("skips the walkthrough and fires onComplete immediately when a device identity is already stored", () => {
    const { root, restore } = installDom();
    try {
      let completions = 0;
      mountOnboardingGate({
        root,
        storage: memoryStorage(),
        hasStoredIdentity: true,
        onComplete: () => {
          completions += 1;
        },
      });

      assert.equal(
        root.querySelector(".onboarding-shell"),
        null,
        "walkthrough must never render for an already-paired device",
      );
      assert.equal(completions, 1, "onComplete must fire immediately for an enrolled device");
    } finally {
      restore();
    }
  });

  test("skips the walkthrough and fires onComplete immediately once already completed/skipped", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      storage.setItem("allw:onboarding:v1", "1");
      let completions = 0;
      mountOnboardingGate({
        root,
        storage,
        hasStoredIdentity: false,
        onComplete: () => {
          completions += 1;
        },
      });

      assert.equal(
        root.querySelector(".onboarding-shell"),
        null,
        "walkthrough must not re-render once already completed",
      );
      assert.equal(completions, 1);
    } finally {
      restore();
    }
  });

  test("without a stored identity or a completion flag, the walkthrough must complete before pairing renders", () => {
    const { root, restore } = installDom();
    try {
      const storage = memoryStorage();
      let pairingRendered = false;
      mountOnboardingGate({
        root,
        storage,
        hasStoredIdentity: false,
        onComplete: () => {
          pairingRendered = true;
        },
      });

      assert.equal(pairingRendered, false);
      findButtonByText(root, "Skip walkthrough").click();
      assert.equal(pairingRendered, true);
    } finally {
      restore();
    }
  });
});
