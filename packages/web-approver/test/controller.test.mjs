import assert from "node:assert/strict";
import test from "node:test";

import { JSDOM } from "jsdom";

import { mountWebApprover } from "../dist/browser.js";
import { WebApproverController } from "../dist/index.js";

const NOW = Date.parse("2026-06-12T16:00:00.000Z");

function envelope(id, overrides = {}) {
  return {
    v: 1,
    id,
    created_at: NOW - 1_000,
    expires_at: NOW + 60_000,
    approver: "acct-web",
    context_ciphertext: `ciphertext-${id}`,
    ...overrides,
  };
}

function context(overrides = {}) {
  return {
    kind: "command",
    command: {
      cwd: "/repo",
      argv: ["git", "push", "origin", "main"],
      raw: "git push origin main",
    },
    actor: {
      id: "claude-code:local",
      display: "Claude Code on laptop",
      attestation: "verified",
    },
    risk: {
      level: "high",
      reversible: false,
      summary: "publishes local commits to the remote",
    },
    allowed_decisions: ["approved", "denied"],
    ...overrides,
  };
}

function runtime(fixtures) {
  const signCalls = [];

  return {
    signCalls,
    async prepare(envelopeInput) {
      const value = fixtures.get(envelopeInput.id);
      if (value instanceof Error) {
        throw value;
      }
      assert.ok(value, `missing fixture for ${envelopeInput.id}`);
      return { expiresAt: envelopeInput.expires_at, ...value };
    },
    async signDecision(input) {
      signCalls.push(input);
      return {
        requestId: input.envelope.id,
        decision: input.decision,
        signedVerdictJson: JSON.stringify({
          request_id: input.envelope.id,
          decision: input.decision,
          challenge_response: input.challengeResponse,
        }),
      };
    },
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

test("sync builds a pending inbox first and keeps resolved history below the fold", async () => {
  const pending = envelope("req-pending");
  const resolved = envelope("req-resolved", { resolved_at: NOW - 5_000 });
  const fixtures = new Map([
    [
      pending.id,
      {
        requestHash: "hash-pending",
        context: context(),
      },
    ],
    [
      resolved.id,
      {
        requestHash: "hash-resolved",
        context: context({ risk: { level: "low", reversible: true, summary: "reads a file" } }),
        resolvedDecision: "approved",
      },
    ],
  ]);

  const controller = new WebApproverController({
    runtime: runtime(fixtures),
    nowMs: () => NOW,
  });

  await controller.sync([resolved, pending]);

  assert.deepEqual(
    controller.inbox().map((item) => item.id),
    ["req-pending"],
    "only active pending requests appear in the inbox",
  );
  assert.deepEqual(
    controller.history().map((item) => item.id),
    ["req-resolved"],
    "resolved requests are history, not active approval work",
  );
  assert.equal(controller.detail("req-pending")?.requestHash, "hash-pending");
  assert.equal(controller.detail("req-pending")?.countdownMs, 60_000);
});

test("tampered or undecryptable context fails closed as unverified and cannot approve", async () => {
  const tampered = envelope("req-tampered");
  const controller = new WebApproverController({
    runtime: runtime(new Map([[tampered.id, new Error("hash mismatch")]])),
    nowMs: () => NOW,
  });

  await controller.sync([tampered]);

  const detail = controller.detail("req-tampered");
  assert.equal(detail?.status, "unverified");
  assert.equal(detail?.denyOnly, true);
  assert.deepEqual(
    controller.inbox().map((item) => item.id),
    ["req-tampered"],
    "unverified requests stay visible as blocked inbox work",
  );
  assert.match(detail?.verificationError ?? "", /hash mismatch/);
  assert.equal(controller.canApprove("req-tampered"), false);
  await assert.rejects(() => controller.decide("req-tampered", "approved"), /not approvable/);
});

test("expired requests are visible but cannot be approved or signed", async () => {
  const expired = envelope("req-expired", { expires_at: NOW - 1 });
  const fakeRuntime = runtime(
    new Map([[expired.id, { requestHash: "hash-expired", context: context() }]]),
  );
  const controller = new WebApproverController({
    runtime: fakeRuntime,
    nowMs: () => NOW,
  });

  await controller.sync([expired]);

  assert.equal(controller.detail("req-expired")?.status, "expired");
  assert.deepEqual(
    controller.inbox().map((item) => item.id),
    ["req-expired"],
    "expired requests stay visible as blocked inbox work",
  );
  assert.equal(controller.canApprove("req-expired"), false);
  await assert.rejects(() => controller.decide("req-expired", "approved"), /expired/);
  assert.equal(fakeRuntime.signCalls.length, 0, "expired requests are never signed");
});

test("verified expiry from prepare controls lifecycle instead of relay-visible expiry", async () => {
  const relayLooksFresh = envelope("req-verified-expired", { expires_at: NOW + 60_000 });
  const fakeRuntime = runtime(
    new Map([
      [
        relayLooksFresh.id,
        {
          requestHash: "hash-verified-expired",
          context: context(),
          expiresAt: NOW - 1,
        },
      ],
    ]),
  );
  const controller = new WebApproverController({
    runtime: fakeRuntime,
    nowMs: () => NOW,
  });

  await controller.sync([relayLooksFresh]);

  const detail = controller.detail("req-verified-expired");
  assert.equal(detail?.status, "expired");
  assert.equal(detail?.expiresAt, NOW - 1);
  assert.equal(detail?.countdownMs, 0);
  assert.equal(controller.canApprove("req-verified-expired"), false);
  await assert.rejects(() => controller.decide("req-verified-expired", "approved"), /expired/);
  assert.equal(fakeRuntime.signCalls.length, 0, "core-expired requests are never signed");
});

test("verified expiry is rechecked after sync before signing a decision", async () => {
  let now = NOW;
  const expiresAfterSync = envelope("req-expire-after-sync", { expires_at: NOW + 60_000 });
  const fakeRuntime = runtime(
    new Map([
      [
        expiresAfterSync.id,
        {
          requestHash: "hash-expire-after-sync",
          context: context(),
          expiresAt: NOW + 1_000,
        },
      ],
    ]),
  );
  const controller = new WebApproverController({
    runtime: fakeRuntime,
    nowMs: () => now,
  });

  await controller.sync([expiresAfterSync]);

  assert.equal(controller.detail("req-expire-after-sync")?.status, "pending");
  assert.equal(controller.canApprove("req-expire-after-sync"), true);

  now = NOW + 1_001;

  assert.equal(controller.canApprove("req-expire-after-sync"), false);
  assert.equal(controller.detail("req-expire-after-sync")?.status, "expired");
  await assert.rejects(() => controller.decide("req-expire-after-sync", "approved"), /expired/);
  assert.equal(fakeRuntime.signCalls.length, 0, "requests expired after sync are never signed");
});

test("number-match challenge gates approval and is included in the signed verdict", async () => {
  const challenged = envelope("req-challenge");
  const fakeRuntime = runtime(
    new Map([
      [
        challenged.id,
        {
          requestHash: "hash-challenge",
          context: context({
            challenge: {
              kind: "number-match",
              code: "4821",
              prompt: "Enter the code shown by the requesting CLI.",
            },
          }),
        },
      ],
    ]),
  );
  const controller = new WebApproverController({
    runtime: fakeRuntime,
    nowMs: () => NOW,
  });

  await controller.sync([challenged]);

  assert.equal(controller.canApprove("req-challenge"), false);
  assert.equal(controller.canApprove("req-challenge", { challengeResponse: "1234" }), false);
  assert.equal(controller.canApprove("req-challenge", { challengeResponse: "4821" }), true);

  await assert.rejects(
    () => controller.decide("req-challenge", "approved", { challengeResponse: "1234" }),
    /number-match/,
  );

  const verdict = await controller.decide("req-challenge", "approved", {
    challengeResponse: "4821",
  });

  assert.equal(verdict.decision, "approved");
  assert.equal(fakeRuntime.signCalls[0]?.challengeResponse, "4821");
  assert.equal(controller.detail("req-challenge")?.status, "approved");
});

test("double-submit races are rejected before a second verdict can be signed", async () => {
  const request = envelope("req-double-submit");
  const signing = deferred();
  const signCalls = [];
  const fakeRuntime = {
    signCalls,
    async prepare() {
      return {
        requestHash: "hash-double-submit",
        expiresAt: request.expires_at,
        context: context(),
      };
    },
    async signDecision(input) {
      signCalls.push(input);
      return signing.promise;
    },
  };
  const controller = new WebApproverController({
    runtime: fakeRuntime,
    nowMs: () => NOW,
  });

  await controller.sync([request]);

  const firstDecision = controller.decide("req-double-submit", "approved");
  const secondDecision = controller.decide("req-double-submit", "approved");
  try {
    assert.equal(signCalls.length, 1, "only the first submit reaches the signing runtime");
    await assert.rejects(() => secondDecision, /already being decided/);
  } finally {
    signing.resolve({
      requestId: request.id,
      decision: "approved",
      signedVerdictJson: "{}",
    });
    await Promise.allSettled([firstDecision, secondDecision]);
  }
  assert.equal(controller.detail("req-double-submit")?.status, "approved");
});

test("disallowed decisions are rejected before signing", async () => {
  const deniedOnly = envelope("req-denied-only");
  const fakeRuntime = runtime(
    new Map([
      [
        deniedOnly.id,
        {
          requestHash: "hash-denied-only",
          context: context({ allowed_decisions: ["denied"] }),
        },
      ],
    ]),
  );
  const controller = new WebApproverController({
    runtime: fakeRuntime,
    nowMs: () => NOW,
  });

  await controller.sync([deniedOnly]);

  assert.equal(controller.canApprove("req-denied-only"), false);
  await assert.rejects(() => controller.decide("req-denied-only", "approved"), /not allowed/);
  assert.equal(fakeRuntime.signCalls.length, 0, "disallowed decisions are never signed");
});

test("malformed action contexts render as unknown actions without throwing", async () => {
  const missingCommand = envelope("req-missing-command");
  const missingMcp = envelope("req-missing-mcp");
  const controller = new WebApproverController({
    runtime: runtime(
      new Map([
        [
          missingCommand.id,
          {
            requestHash: "hash-missing-command",
            context: context({ kind: "command", command: undefined }),
          },
        ],
        [
          missingMcp.id,
          {
            requestHash: "hash-missing-mcp",
            context: context({ kind: "mcp", command: undefined, mcp: undefined }),
          },
        ],
      ]),
    ),
    nowMs: () => NOW,
  });

  await controller.sync([missingCommand, missingMcp]);

  assert.equal(controller.detail("req-missing-command")?.summary, "Unknown action");
  assert.equal(controller.detail("req-missing-command")?.exactPlaintext, "Unknown action");
  assert.equal(controller.detail("req-missing-mcp")?.summary, "Unknown action");
  assert.equal(controller.detail("req-missing-mcp")?.exactPlaintext, "Unknown action");
});

test("browser rendering treats attacker argv as inert text", async () => {
  const dom = new JSDOM('<div id="app"></div>', { url: "https://approver.local/" });
  const root = dom.window.document.getElementById("app");
  const attackArg = "<script>globalThis.__allwXss = true</script>";
  const globals = {
    document: globalThis.document,
    window: globalThis.window,
    HTMLButtonElement: globalThis.HTMLButtonElement,
  };

  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  globalThis.HTMLButtonElement = dom.window.HTMLButtonElement;

  try {
    await mountWebApprover({
      root,
      nowMs: () => NOW,
      fetchInbox: async () => [envelope("req-xss")],
      runtime: runtime(
        new Map([
          [
            "req-xss",
            {
              requestHash: "hash-xss",
              context: context({
                command: {
                  cwd: "/repo",
                  argv: ["echo", attackArg],
                },
              }),
            },
          ],
        ]),
      ),
    });

    assert.equal(root.querySelector("script"), null);
    assert.match(root.textContent ?? "", /<script>globalThis\.__allwXss = true<\/script>/);
    assert.equal(dom.window.__allwXss, undefined);
  } finally {
    globalThis.document = globals.document;
    globalThis.window = globals.window;
    globalThis.HTMLButtonElement = globals.HTMLButtonElement;
  }
});
