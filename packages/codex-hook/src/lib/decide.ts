/**
 * Codex decision core: classify a PreToolUse input, request allw approval for gated actions, and
 * map the verified verdict to a Codex hook result: no output (allw does not block the call) or a
 * `deny` JSON.
 *
 * This deliberately mirrors the Claude Code hook's fail-closed matrix while using Codex-specific
 * actor identity. All facts `ActionRecord` construction stays delegated to the shared WASM
 * core: a POSIX shell command (`Bash`, `Monitor`'s `command`) through `@allw/sdk`'s
 * `commandRequest`, exactly as the Claude Code hook does (#372), so a blank command or program is
 * denied with the same reason in both; every other surface through `@allw/hook`'s `gateToolCall`.
 */

import {
  agentSafeErrorText,
  agentSafeText,
  commandBuildFailureReason,
  gateToolCall,
  posixCommandCall,
  type CommandRequestFn,
  type HookConfig,
  type HookWasm,
} from "@allw/hook";

import {
  denyOutput,
  noBlockOutput,
  type CodexHookResult,
  type CodexPreToolUseInput,
  type DenyReason,
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
  /** Builds the request for a POSIX shell command; production uses `@allw/sdk`'s `commandRequest`. */
  readonly commandRequest: CommandRequestFn;
  readonly requestApproval: RequestApprovalFn;
}

interface CoreActionRecord {
  readonly record_schema_version: number;
  readonly surface: string;
  readonly facts: unknown;
}

/** Validate the parsed core `ActionRecord` fields this package maps into an SDK request. */
function isCoreActionRecord(value: unknown): value is CoreActionRecord {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.record_schema_version === "number" && typeof v.surface === "string" && "facts" in v
  );
}

/** The Codex machine actor: this host, acting as Codex. */
function codexActor(hostname: string): CodexApprovalRequest["actor"] {
  return { id: `codex:${hostname}`, kind: "codex" };
}

/** The audit-chain link for a Codex call id, when Codex sent a non-empty one. */
function codexChain(toolUseId: string | undefined): { chain?: readonly string[] } {
  return toolUseId !== undefined && toolUseId.length > 0
    ? { chain: [`codex:tool_use_id:${toolUseId}`] }
    : {};
}

/**
 * Build the request for a POSIX shell command through `commandRequest`, which builds the record
 * with the core's `action_from_command` without inferring danger or reversibility. The Codex values are explicit
 * overrides: the actor, the call-id chain, the configured timeout, and `cwd` (`null` when Codex
 * sent none, so the record is unbound rather than bound to the hook's own directory). No reversibility
 * assertion is made.
 *
 * @throws (as a rejection) whatever `commandRequest` throws; the caller denies.
 */
async function commandApprovalRequest(
  build: CommandRequestFn,
  command: string,
  summary: string,
  input: CodexPreToolUseInput,
  config: HookConfig,
  hostname: string,
): Promise<CodexApprovalRequest> {
  const req = await build({
    commandLine: command,
    summary,
    cwd: input.cwd ?? null,
    actor: codexActor(hostname),
    ...codexChain(input.toolUseId),
    ...(config.timeoutMs !== undefined ? { timeoutMs: config.timeoutMs } : {}),
  });
  return {
    action: req.action,
    summary: req.summary,
    actor: codexActor(hostname),

    ...(req.chain !== undefined ? { chain: req.chain } : {}),
    ...(req.timeoutMs !== undefined ? { timeoutMs: req.timeoutMs } : {}),
  };
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
      facts: parsed.facts,
    },
    summary,
    actor: codexActor(hostname),

    ...codexChain(toolUseId),
    ...(config.timeoutMs !== undefined ? { timeoutMs: config.timeoutMs } : {}),
  };
}

/**
 * A gated call reduced to what `decide` acts on: a request to submit (with the raw `summary` a deny
 * reason quotes), no decision (`pass-through`), or a fail-closed deny (`build-error`).
 */
type PreparedCall =
  | { readonly kind: "request"; readonly req: CodexApprovalRequest; readonly summary: string }
  | { readonly kind: "pass-through"; readonly reason: string }
  | { readonly kind: "build-error"; readonly reason: string };

/**
 * Reduce a call to the request to submit: a POSIX shell command through `commandRequest`, every
 * other gated surface through `gateToolCall`. A request that cannot be built is a `build-error`.
 */
async function prepareCall(
  input: CodexPreToolUseInput,
  deps: DecideDeps,
  hostname: string,
): Promise<PreparedCall> {
  const command = posixCommandCall(input.toolName, input.toolInput);
  if (command !== null) {
    if (command.kind !== "command") return command;
    try {
      const req = await commandApprovalRequest(
        deps.commandRequest,
        command.command,
        command.summary,
        input,
        deps.config,
        hostname,
      );
      return { kind: "request", req, summary: command.summary };
    } catch (err) {
      // A command the SDK refuses (a blank command or program, invalid shell syntax), or any other
      // failure to build the request, is never submitted: the human is not asked (fail-closed).
      return { kind: "build-error", reason: commandBuildFailureReason(deps.wasm, err) };
    }
  }

  const gate = gateToolCall(deps.wasm, input.toolName, input.toolInput, input.cwd);
  if (gate.kind !== "gated") return gate;
  const req = buildApprovalRequest(
    gate.actionRecord,
    gate.summary,
    deps.config,
    hostname,
    input.toolUseId,
  );
  if (req === null) {
    return {
      kind: "build-error",
      reason: "allw: built ActionRecord was not in the expected shape (fail-closed deny)",
    };
  }
  return { kind: "request", req, summary: gate.summary };
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
): Promise<CodexHookResult> {
  const prepared = await prepareCall(input, deps, hostname);

  if (prepared.kind === "pass-through") {
    return noBlockOutput();
  }
  if (prepared.kind === "build-error") {
    return denyOutput(prepared.reason, "build-error");
  }
  const { req, summary } = prepared;

  let verdict: ApprovalVerdict;
  try {
    verdict = await deps.requestApproval(req);
  } catch (err) {
    // The error text may carry relay-supplied text: escape and cap it before the agent reads it.
    return denyOutput(
      `allw: approval request failed (fail-closed deny): ${agentSafeErrorText(deps.wasm, err)}`,
      "transport-error",
    );
  }

  if (verdict.decision === "approved") {
    return noBlockOutput();
  }

  const verdictDenyReason: DenyReason =
    verdict.decision === "denied"
      ? "no-approval"
      : verdict.decision === "expired"
        ? "timeout"
        : "aborted";
  // The summary quotes the tool call, which can come from a third party, so it goes through the
  // core escape before the agent reads it (#364). The approver still gets the raw summary.
  return denyOutput(
    `allw: ${agentSafeText(deps.wasm, summary)} — not approved (verdict: ${verdict.decision})`,
    verdictDenyReason,
  );
}
