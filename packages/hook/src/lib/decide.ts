/**
 * The hook's decision core: turn a parsed PreToolUse input into a permission decision by routing a
 * gated tool call through a human approval and mapping the **verified** verdict to "no decision" or
 * deny.
 *
 * This module is deliberately free of stdin/stdout and network I/O and is dependency-injected — the
 * WASM core, the command-request builder and the approval function are passed in — so the full
 * decision matrix is unit-testable without the relay. `runHook` in `../cli.ts` wires the real
 * `@allw/sdk` functions into it.
 *
 * # Building the request
 * A POSIX shell command (`Bash`, or `Monitor` with a `command`) is built through `@allw/sdk`'s
 * `commandRequest` (#269), the same core-built path a plain script uses, with the hook's own actor,
 * timeout as an explicit override and no reversibility assertion. (`commandRequest` loads the SDK's copy
 * of the WASM core, the same vendored artifact the hook's `wasm` is.) Every other gated surface (MCP,
 * file edits, PowerShell) has no SDK builder yet, so its record comes from {@link gateToolCall} and
 * is translated here.
 *
 * # Fail-closed, deny-only mapping (contract §Invariants)
 * A verdict may only tighten access, so the hook never emits `allow` (see `./hook-io.ts`):
 *
 * | Outcome                                            | Decision                       |
 * | -------------------------------------------------- | ------------------------------ |
 * | not a gated tool (`pass-through`)                  | none (empty stdout)            |
 * | gated, `ActionRecord` build error                  | `deny`                         |
 * | gated, verdict `decision === "approved"`           | none (empty stdout)            |
 * | gated, verdict `denied` / `expired` / `aborted`    | `deny`                         |
 * | gated, `requestApproval` threw (network/config/…)  | `deny`                         |
 *
 * "None" hands the call back to Claude Code's own permission rules. Only a verdict whose `decision`
 * is exactly `approved` (which the SDK resolves **only** for a fully-verified, bound, fresh,
 * human-approved verdict) gets there; every other gated path denies. (`../cli.ts` also returns no
 * decision for a non-gated tool before reading config, so `decide` normally sees gated tools only.)
 *
 * @see ../../../../docs/contract.md §Invariants #6 (fail-closed), §Lifecycle
 * @see ../../../sdk/src/index.ts (requestApproval is itself fail-closed: approved ⇒ verified)
 */

import type { commandRequest } from "@allw/sdk";

import type { HookWasm } from "./wasm.js";
import { agentSafeErrorText, agentSafeText } from "./agent-text.js";
import { commandBuildFailureReason, gateToolCall, posixCommandCall } from "./gating.js";
import {
  denyOutput,
  noDecisionOutput,
  type ClaudeHookResult,
  type PreToolUseInput,
} from "./hook-io.js";
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
 * (camelCase). `action` is typed `unknown` here because, outside the command surface, the hook
 * produces it by translating the core's snake_case `ActionRecord` JSON — the SDK validates and
 * serializes it on the way to the core.
 */
export interface HookApprovalRequest {
  readonly action: unknown;
  readonly summary: string;
  readonly actor: { readonly id: string; readonly kind: string };

  readonly timeoutMs?: number;
}

/** The injectable approval function — the real one is `client.requestApproval` from `@allw/sdk`. */
export type RequestApprovalFn = (req: HookApprovalRequest) => Promise<ApprovalVerdict>;

/**
 * The injectable command-request builder — the real one is `@allw/sdk`'s `commandRequest`. It
 * rejects with a `CommandActionError` for a command it refuses; any rejection denies.
 */
export type CommandRequestFn = typeof commandRequest;

export { MAX_ERROR_TEXT_CHARS, agentSafeErrorText, agentSafeText } from "./agent-text.js";

/** Everything `decide` needs that isn't the parsed input — all injectable for tests. */
export interface DecideDeps {
  readonly wasm: HookWasm;
  readonly config: HookConfig;
  /** Builds the request for a POSIX shell command (`Bash`, `Monitor`'s `command`). */
  readonly commandRequest: CommandRequestFn;
  readonly requestApproval: RequestApprovalFn;
}

/** The subset of the core's snake_case `ActionRecord` JSON the hook reads back after building it. */
interface CoreActionRecord {
  readonly record_schema_version: number;
  readonly surface: string;
  readonly syntactic: unknown;
}

/** Validate the parsed core `ActionRecord` JSON has the fields the hook depends on. */
function isCoreActionRecord(value: unknown): value is CoreActionRecord {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.record_schema_version === "number" && typeof v.surface === "string" && "syntactic" in v
  );
}

/** The machine actor the hook submits as: this host, acting as Claude Code. */
function hookActor(hostname: string): HookApprovalRequest["actor"] {
  return { id: `machine:${hostname}`, kind: "claude-code" };
}

/**
 * Build the `ApprovalRequest` for a POSIX shell command through `@allw/sdk`'s `commandRequest`,
 * which builds the record with the core's `action_from_command` without inferring danger or reversibility.
 *
 * The hook's own values are explicit overrides: its actor, the configured timeout, and `cwd`
 * (`null` when Claude Code sent none, so the record is unbound rather than bound to the hook's own
 * working directory). No reversibility assertion is made.
 *
 * @throws `CommandActionError` (as a rejection) when the SDK refuses the command: invalid
 * shell syntax, or a blank command or program. (It also refuses a blank `cwd`, which the stdin
 * parser has already turned into an absent one.) The caller denies.
 */
async function commandApprovalRequest(
  build: CommandRequestFn,
  command: string,
  summary: string,
  cwd: string | undefined,
  config: HookConfig,
  hostname: string,
): Promise<HookApprovalRequest> {
  const req = await build({
    commandLine: command,
    summary,
    cwd: cwd ?? null,
    actor: hookActor(hostname),
    ...(config.timeoutMs !== undefined ? { timeoutMs: config.timeoutMs } : {}),
  });
  return req;
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
  };

  return {
    action,
    summary,
    actor: hookActor(hostname),

    ...(config.timeoutMs !== undefined ? { timeoutMs: config.timeoutMs } : {}),
  };
}

/**
 * A gated call reduced to what `decide` acts on: a request to submit (with the raw `summary` a deny
 * reason quotes), no decision (`pass-through`), or a fail-closed deny (`build-error`).
 */
type PreparedCall =
  | { readonly kind: "request"; readonly req: HookApprovalRequest; readonly summary: string }
  | { readonly kind: "pass-through"; readonly reason: string }
  | { readonly kind: "build-error"; readonly reason: string };

/**
 * Reduce a call to the request to submit. A POSIX shell command goes through the SDK
 * ({@link commandApprovalRequest}); every other gated surface through {@link gateToolCall}. A
 * record that cannot be built is a `build-error`, so the caller denies.
 */
async function prepareCall(
  input: PreToolUseInput,
  deps: DecideDeps,
  hostname: string,
): Promise<PreparedCall> {
  const { config, wasm } = deps;
  const command = posixCommandCall(input.toolName, input.toolInput);
  if (command !== null) {
    if (command.kind !== "command") return command;
    try {
      const req = await commandApprovalRequest(
        deps.commandRequest,
        command.command,
        command.summary,
        input.cwd,
        config,
        hostname,
      );
      return { kind: "request", req, summary: command.summary };
    } catch (err) {
      // A command the SDK refuses, or any other failure to build the request (the SDK's WASM
      // loader, say), is never submitted; the human is not asked (fail-closed).
      return { kind: "build-error", reason: commandBuildFailureReason(wasm, err) };
    }
  }

  const gate = gateToolCall(wasm, input.toolName, input.toolInput, input.cwd);
  if (gate.kind !== "gated") return gate;
  const req = buildApprovalRequest(gate.actionRecord, gate.summary, config, hostname);
  if (req === null) {
    return {
      kind: "build-error",
      reason: "allw: built ActionRecord was not in the expected shape (fail-closed deny)",
    };
  }
  return { kind: "request", req, summary: gate.summary };
}

/**
 * Decide a single PreToolUse call.
 *
 * Pass-through calls get no decision without contacting the relay. Gated calls build an
 * `ActionRecord` (via the WASM core), request a human approval (via the injected SDK), and map the
 * **verified** verdict: approved ⇒ no decision (Claude Code's own rules apply), anything else ⇒ deny. Every error path — build failure, a thrown
 * `requestApproval`, a non-`approved` verdict — denies (fail-closed).
 *
 * @param hostname the local machine name for the actor identity (`machine:<hostname>`).
 */
export async function decide(
  input: PreToolUseInput,
  deps: DecideDeps,
  hostname: string,
): Promise<ClaudeHookResult> {
  const prepared = await prepareCall(input, deps, hostname);

  if (prepared.kind === "pass-through") {
    return noDecisionOutput();
  }
  if (prepared.kind === "build-error") {
    return denyOutput(prepared.reason);
  }
  const { req, summary } = prepared;

  let verdict: ApprovalVerdict;
  try {
    verdict = await deps.requestApproval(req);
  } catch (err) {
    // Any thrown error (network, no usable account state, relay rejection) ⇒ deny. We never allow on a
    // failure to obtain a verified verdict. The error text may carry relay-supplied text, so it is
    // escaped and capped before the agent reads it.
    return denyOutput(
      `allw: approval request failed (fail-closed deny): ${agentSafeErrorText(deps.wasm, err)}`,
    );
  }

  if (verdict.decision === "approved") {
    // A verified human "yes" removes allw's objection; it does not grant. Claude Code still applies
    // the user's own permission rules to the call.
    return noDecisionOutput();
  }
  // denied / expired / aborted ⇒ deny (a verified human "no", a timeout, or a device abort).
  // The summary quotes the tool call (a command, tool and server names, MCP params), which can come
  // from a third party, so it goes through the core escape before the agent reads it (#364). The
  // approver still gets the raw summary and applies its own display escape.
  return denyOutput(
    `allw: ${agentSafeText(deps.wasm, summary)} — not approved (verdict: ${verdict.decision})`,
  );
}
