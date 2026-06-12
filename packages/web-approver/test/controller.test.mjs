import assert from "node:assert/strict";
import test from "node:test";

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
      return value;
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
  assert.equal(controller.canApprove("req-expired"), false);
  await assert.rejects(() => controller.decide("req-expired", "approved"), /expired/);
  assert.equal(fakeRuntime.signCalls.length, 0, "expired requests are never signed");
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
