/**
 * Codex decision core: classify a PreToolUse input, request allw approval for gated actions, and
 * map the verified verdict to Codex's allow/deny JSON.
 *
 * This deliberately mirrors the Claude Code hook's fail-closed matrix while using Codex-specific
 * actor identity. All syntactic `ActionRecord` construction stays delegated to the shared WASM
 * core through `@allw/hook` helpers.
 */

import { gateToolCall, type HookConfig, type HookWasm } from "@allw/hook";

import {
  allowOutput,
  denyOutput,
  type CodexPreToolUseInput,
  type CodexPreToolUseOutput,
} from "./codex-io.js";

/** The minimal verdict shape read from `@allw/sdk`. */
export interface ApprovalVerdict {
  readonly decision: "approved" | "denied" | "expired" | "aborted";
}

/** The approval request shape submitted to the SDK. */
export interface CodexApprovalRequest {
  readonly action: unknown;
  readonly summary: string;
  readonly actor: { readonly id: string; readonly kind: "codex" };
  readonly risk: "low" | "medium" | "high" | "critical";
  readonly reversible: boolean;
  /** Optional Codex call id carried for audit-chain correlation and dedupe. */
  readonly chain?: readonly string[];
  readonly timeoutMs?: number;
}

/** Injectable approval function; production uses `client.requestApproval`. */
export type RequestApprovalFn = (req: CodexApprovalRequest) => Promise<ApprovalVerdict>;

/** Dependencies for the I/O-free decision core. */
export interface DecideDeps {
  readonly wasm: HookWasm;
  readonly config: HookConfig;
  readonly requestApproval: RequestApprovalFn;
}

type Risk = "low" | "medium" | "high" | "critical";

interface CoreActionRecord {
  readonly record_schema_version: number;
  readonly surface: string;
  readonly syntactic: unknown;
  readonly risk: Risk;
}

/** Validate the parsed core `ActionRecord` fields this package maps into an SDK request. */
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

/** Low/medium actions default to reversible in the current coarse risk model. */
function reversibleForRisk(risk: Risk): boolean {
  return risk === "low" || risk === "medium";
}

/** Translate core snake_case JSON into the SDK request shape and attach Codex actor identity. */
function buildApprovalRequest(
  actionRecordJson: string,
  summary: string,
  config: HookConfig,
  hostname: string,
  toolUseId?: string,
): CodexApprovalRequest | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(actionRecordJson);
  } catch {
    return null;
  }
  if (!isCoreActionRecord(parsed)) return null;

  return {
    action: {
      recordSchemaVersion: parsed.record_schema_version,
      surface: parsed.surface,
      syntactic: parsed.syntactic,
      risk: parsed.risk,
    },
    summary,
    actor: { id: `codex:${hostname}`, kind: "codex" },
    risk: parsed.risk,
    reversible: reversibleForRisk(parsed.risk),
    ...(toolUseId !== undefined && toolUseId.length > 0
      ? { chain: [`codex:tool_use_id:${toolUseId}`] }
      : {}),
    ...(config.timeoutMs !== undefined ? { timeoutMs: config.timeoutMs } : {}),
  };
}

/**
 * Decide a Codex PreToolUse invocation.
 *
 * Non-gated tools pass through without contacting allw. Gated tools deny on build errors, approval
 * transport errors, and any verdict other than a verified `approved`.
 */
export async function decide(
  input: CodexPreToolUseInput,
  deps: DecideDeps,
  hostname: string,
): Promise<CodexPreToolUseOutput> {
  const gate = gateToolCall(deps.wasm, input.toolName, input.toolInput, input.cwd);

  if (gate.kind === "pass-through") {
    return allowOutput(gate.reason);
  }
  if (gate.kind === "build-error") {
    return denyOutput(gate.reason);
  }

  const req = buildApprovalRequest(
    gate.actionRecord,
    gate.summary,
    deps.config,
    hostname,
    input.toolUseId,
  );
  if (req === null) {
    return denyOutput("allw: built ActionRecord was not in the expected shape (fail-closed deny)");
  }

  let verdict: ApprovalVerdict;
  try {
    verdict = await deps.requestApproval(req);
  } catch (err) {
    return denyOutput(
      `allw: approval request failed (fail-closed deny): ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }

  if (verdict.decision === "approved") {
    return allowOutput(`allw: ${gate.summary} — approved by the human`);
  }
  return denyOutput(`allw: ${gate.summary} — not approved (verdict: ${verdict.decision})`);
}
