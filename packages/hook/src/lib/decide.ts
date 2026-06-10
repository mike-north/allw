/**
 * The hook's decision core: turn a parsed PreToolUse input into a permission decision by routing a
 * gated tool call through a human approval and mapping the **verified** verdict to allow/deny.
 *
 * This module is deliberately I/O-free and dependency-injected — the WASM core, the approval
 * function, and a clock are all passed in — so the full decision matrix is unit-testable without
 * touching stdin/stdout, the network, or the real SDK. `runHook` in `../cli.ts` wires the real
 * `@allw/sdk` client into it.
 *
 * # Fail-closed mapping (contract §Invariants #6)
 * The primitive never returns a bare "allow"; the hook composes it:
 *
 * | Outcome                                            | Decision |
 * | -------------------------------------------------- | -------- |
 * | not a gated tool                                   | `allow` (pass-through; the human isn't bothered) |
 * | gated, `ActionRecord` build error                  | `deny`   |
 * | gated, verdict `decision === "approved"`           | `allow`  |
 * | gated, verdict `denied` / `expired` / `aborted`    | `deny`   |
 * | gated, `requestApproval` threw (network/config/…)  | `deny`   |
 *
 * Only a verdict whose `decision` is exactly `approved` (which the SDK resolves **only** for a
 * fully-verified, bound, fresh, human-approved verdict) becomes `allow`. Every other path denies.
 *
 * @see ../../../../docs/contract.md §Invariants #6 (fail-closed), §Lifecycle
 * @see ../../../sdk/src/index.ts (requestApproval is itself fail-closed: approved ⇒ verified)
 */

import type { HookWasm } from "./wasm.js";
import { gateToolCall } from "./gating.js";
import { allowOutput, denyOutput, type PreToolUseInput, type PreToolUseOutput } from "./hook-io.js";
import type { HookConfig } from "./config.js";

/**
 * The minimal surface of a `@allw/sdk` verdict the hook reads. Structurally compatible with the
 * SDK's `Verdict` (the SDK already resolves `decision === "approved"` only for a verified verdict),
 * so the real client satisfies this and a test double can implement just `decision`.
 */
export interface ApprovalVerdict {
  readonly decision: "approved" | "denied" | "expired" | "aborted";
}

/**
 * The minimal `ApprovalRequest` shape the hook builds. Mirrors `@allw/sdk`'s `ApprovalRequest`
 * (camelCase). `action` is typed `unknown` here because the hook produces it by translating the
 * core's snake_case `ActionRecord` JSON — the SDK validates/serializes it on the way to the core.
 */
export interface HookApprovalRequest {
  readonly action: unknown;
  readonly summary: string;
  readonly actor: { readonly id: string; readonly kind: string };
  readonly risk: "low" | "medium" | "high" | "critical";
  readonly reversible: boolean;
  readonly timeoutMs?: number;
}

/** The injectable approval function — the real one is `client.requestApproval` from `@allw/sdk`. */
export type RequestApprovalFn = (req: HookApprovalRequest) => Promise<ApprovalVerdict>;

/** Everything `decide` needs that isn't the parsed input — all injectable for tests. */
export interface DecideDeps {
  readonly wasm: HookWasm;
  readonly config: HookConfig;
  readonly requestApproval: RequestApprovalFn;
}

/** A coarse risk classification (the core's `ActionRecord.risk`, lower-cased on the wire). */
type Risk = "low" | "medium" | "high" | "critical";

/** The subset of the core's snake_case `ActionRecord` JSON the hook reads back after building it. */
interface CoreActionRecord {
  readonly record_schema_version: number;
  readonly surface: string;
  readonly syntactic: unknown;
  readonly risk: Risk;
}

/** Validate the parsed core `ActionRecord` JSON has the fields the hook depends on. */
function isCoreActionRecord(value: unknown): value is CoreActionRecord {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.record_schema_version === "number" &&
    typeof v.surface === "string" &&
    "syntactic" in v &&
    (v.risk === "low" || v.risk === "medium" || v.risk === "high" || v.risk === "critical")
  );
}

/**
 * Is a risk tier reversible by default? Coarse v1 heuristic: `high`/`critical` actions are treated
 * as irreversible (they typically destroy or push state), `low`/`medium` as reversible. This only
 * feeds the human-shown `reversible` hint; it never substitutes for the human's decision.
 */
function reversibleForRisk(risk: Risk): boolean {
  return risk === "low" || risk === "medium";
}

/**
 * Translate the core's snake_case `ActionRecord` JSON into the SDK's camelCase `action` and build
 * the full `ApprovalRequest`. Returns `null` if the core JSON is unparseable/unexpected (caller
 * fails closed) — though the core always emits a well-formed record, so this is defense in depth.
 */
function buildApprovalRequest(
  actionRecordJson: string,
  summary: string,
  config: HookConfig,
  hostname: string,
): HookApprovalRequest | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(actionRecordJson);
  } catch {
    return null;
  }
  if (!isCoreActionRecord(parsed)) return null;

  const action = {
    recordSchemaVersion: parsed.record_schema_version,
    surface: parsed.surface,
    syntactic: parsed.syntactic,
    risk: parsed.risk,
  };

  return {
    action,
    summary,
    actor: { id: `machine:${hostname}`, kind: "claude-code" },
    risk: parsed.risk,
    reversible: reversibleForRisk(parsed.risk),
    ...(config.timeoutMs !== undefined ? { timeoutMs: config.timeoutMs } : {}),
  };
}

/**
 * Decide a single PreToolUse call.
 *
 * Non-gated calls pass through as `allow` without contacting the relay. Gated calls build an
 * `ActionRecord` (via the WASM core), request a human approval (via the injected SDK), and map the
 * **verified** verdict to allow/deny. Every error path — build failure, a thrown
 * `requestApproval`, a non-`approved` verdict — denies (fail-closed).
 *
 * @param hostname the local machine name for the actor identity (`machine:<hostname>`).
 */
export async function decide(
  input: PreToolUseInput,
  deps: DecideDeps,
  hostname: string,
): Promise<PreToolUseOutput> {
  const gate = gateToolCall(deps.wasm, input.toolName, input.toolInput, input.cwd);

  if (gate.kind === "pass-through") {
    return allowOutput(gate.reason);
  }
  if (gate.kind === "build-error") {
    return denyOutput(gate.reason);
  }

  const req = buildApprovalRequest(gate.actionRecord, gate.summary, deps.config, hostname);
  if (req === null) {
    return denyOutput("allw: built ActionRecord was not in the expected shape (fail-closed deny)");
  }

  let verdict: ApprovalVerdict;
  try {
    verdict = await deps.requestApproval(req);
  } catch (err) {
    // Any thrown error (network, no enrolled devices, relay rejection) ⇒ deny. We never allow on a
    // failure to obtain a verified verdict.
    return denyOutput(
      `allw: approval request failed (fail-closed deny): ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  if (verdict.decision === "approved") {
    return allowOutput(`allw: ${gate.summary} — approved by the human`);
  }
  // denied / expired / aborted ⇒ deny (a verified human "no", a timeout, or a device abort).
  return denyOutput(`allw: ${gate.summary} — not approved (verdict: ${verdict.decision})`);
}
