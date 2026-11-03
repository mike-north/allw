/**
 * Command-surface request builders: gate a command from a plain script in a few lines.
 *
 * A script that is about to run a command (for example `stripe refunds create --charge ch_…`) is a
 * `command`-surface caller, exactly like the agent hooks — there is no separate "generic" or
 * "script" surface (`docs/policy-seam.md` §ActionRecord). This module removes the agent-specific
 * setup a script would otherwise do by hand:
 *
 * - {@link commandAction} / {@link commandActionFromLine} return an {@link ActionRecord} built **by
 *   the audited core** (`action_from_argv` / `action_from_command` via WASM). The SDK does no
 *   tokenization, flag splitting, or risk classification of its own (thin-shell rule,
 *   `CLAUDE.md` §Architecture); it only translates the core's top-level snake_case keys to the
 *   SDK's camelCase {@link ActionRecord} and passes `syntactic` through unchanged, so the record
 *   keeps every field policy matches on (`bin` / `flags` / `positionals` / `env_refs` / …).
 * - {@link commandRequest} wraps that record into a complete {@link ApprovalRequest} with
 *   conservative defaults for the fields that only make sense for agents.
 *
 * Every builder is **fail-closed**: malformed input rejects with a {@link CommandActionError} that
 * names the problem, so nothing is ever submitted for a record the caller did not mean
 * (`docs/contract.md` §Invariants). Nothing here decides access — the caller still composes
 * `allow = approved ∧ verified ∧ policy ∧ other gates` from the verdict `requestApproval` returns.
 *
 * @see ../../../docs/policy-seam.md §ActionRecord (the syntactic substrate; `surface: "command"`)
 * @see ../../../docs/contract.md §Invariants (never returns "allow"; fail-closed; WYSIWYS)
 * @see ../../../crates/allw-wasm/src/lib.rs (`action_from_argv`, `action_from_command`)
 */

import { hostname } from "node:os";

import type { ActionRecord, Actor, ApprovalRequest, Constraints, Risk } from "./index.js";
import { loadWasm } from "./wasm.js";

/**
 * Why a command builder refused to produce a record. Stable, machine-readable companion to the
 * human-readable {@link CommandActionError.message}.
 *
 * - `argv_not_array` — `argv` was not an array.
 * - `argv_empty` — `argv` had no elements (there is no program to show the human).
 * - `argv_element_not_string` — an `argv` element was not a string.
 * - `argv_program_empty` — `argv[0]` (the program) was the empty string.
 * - `command_line_not_string` — `commandLine` was not a string.
 * - `command_line_unparseable` — the core could not tokenize `commandLine` (e.g. an unmatched quote).
 * - `command_line_empty` — `commandLine` tokenized to no command at all (blank or whitespace).
 * - `invalid_option` — an option (`cwd`, `raw`, `summary`, …) had the wrong type or was blank.
 * - `ambiguous_command` — {@link commandRequest} got both or neither of `argv` / `commandLine`.
 * - `core_record_invalid` — the core returned a record that is not a v1 `command` `ActionRecord`
 *   (defense in depth; the SDK refuses to forward a record it cannot faithfully represent).
 */
export type CommandActionErrorReason =
  | "argv_not_array"
  | "argv_empty"
  | "argv_element_not_string"
  | "argv_program_empty"
  | "command_line_not_string"
  | "command_line_unparseable"
  | "command_line_empty"
  | "invalid_option"
  | "ambiguous_command"
  | "core_record_invalid";

/**
 * Thrown (as a rejected promise) by {@link commandAction}, {@link commandActionFromLine}, and
 * {@link commandRequest} when the input cannot become a faithful command record. A caller that
 * catches it must treat the action as **not approved** (fail-closed): no request was submitted.
 */
export class CommandActionError extends Error {
  constructor(
    /** The machine-readable cause. */
    readonly reason: CommandActionErrorReason,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(`allw: ${message}`, options);
    this.name = "CommandActionError";
  }
}

/** Options for {@link commandAction}. */
export interface CommandActionOptions {
  /**
   * The working directory the command will run in, bound into `syntactic.cwd` so the human sees
   * where it runs. Omitted ⇒ the record is not bound to a directory.
   */
  readonly cwd?: string;
  /**
   * The original command text, if the caller has one. The core records it verbatim in
   * `syntactic.raw` and extracts `env_refs` names from it; it is **never** re-tokenized, so the
   * bound tokens are always exactly `argv`. Omitted ⇒ no `raw` and no `env_refs`.
   */
  readonly raw?: string;
}

/** Options for {@link commandActionFromLine}. */
export interface CommandActionFromLineOptions {
  /** The working directory the command will run in (see {@link CommandActionOptions.cwd}). */
  readonly cwd?: string;
}

/** Fields of {@link CommandRequestInput} shared by the `argv` and `commandLine` forms. */
interface CommandRequestCommon {
  /** One-line, human-readable summary shown in the notification. Must be non-blank. */
  readonly summary: string;
  /** The working directory the command will run in (see {@link CommandActionOptions.cwd}). */
  readonly cwd?: string;
  /**
   * The automation requesting approval.
   *
   * @defaultValue `{ id: "machine:<os.hostname()>", kind: "script" }` — the local machine, as a
   * script. (The agent hooks use their own `kind`, e.g. `"claude-code"`.)
   */
  readonly actor?: Actor;
  /**
   * Whether the action can be undone if approved; shown to the human.
   *
   * @defaultValue `false` — the conservative choice: the human is told the action cannot be undone
   * unless the caller says otherwise.
   */
  readonly reversible?: boolean;
  /** Fail-closed deadline (ms from now); see {@link ApprovalRequest.timeoutMs}. */
  readonly timeoutMs?: number;
  /** Integrator-initiated cancellation; see {@link ApprovalRequest.signal}. */
  readonly signal?: AbortSignal;
  /** Allowed decisions + challenge policy; see {@link ApprovalRequest.constraints}. */
  readonly constraints?: Constraints;
  /** Upstream-gate IDs for audit-chain correlation; see {@link ApprovalRequest.chain}. */
  readonly chain?: readonly string[];
}

/**
 * Input to {@link commandRequest}: exactly one of `argv` (a pre-tokenized argument vector — the
 * tokens that will actually run) or `commandLine` (shell-style text the core tokenizes).
 *
 * Prefer `argv` when the script holds the exact token vector it will execute: re-tokenizing text
 * could bind different tokens than the ones that run (`docs/openclaw-integration.md` §5.1).
 */
export type CommandRequestInput = CommandRequestCommon &
  (
    | {
        /** The exact argument vector that will run (`argv[0]` is the program). */
        readonly argv: readonly string[];
        /** Original command text, recorded verbatim (see {@link CommandActionOptions.raw}). */
        readonly raw?: string;
        readonly commandLine?: never;
      }
    | {
        /** A shell-style command line; the core tokenizes it (quotes respected, no expansion). */
        readonly commandLine: string;
        readonly argv?: never;
        readonly raw?: never;
      }
  );

/**
 * Build a `command` {@link ActionRecord} from a pre-tokenized `argv`, using the core's
 * `action_from_argv`. The result is exactly the core's record (top-level keys camelCased,
 * `syntactic` passed through unchanged).
 *
 * @throws {@link CommandActionError} (as a rejection) if `argv` is not a non-empty array of
 * strings with a non-empty program, or an option has the wrong type.
 */
export async function commandAction(
  argv: readonly string[],
  options: CommandActionOptions = {},
): Promise<ActionRecord> {
  const tokens = validateArgv(argv);
  const cwd = optionalString(options.cwd, "cwd");
  const raw = optionalString(options.raw, "raw");
  const wasm = await loadWasm();
  // The core only fails here on a non-string-array argv, which `validateArgv` already ruled out;
  // any throw is still wrapped so the caller sees one error type.
  const json = callCore(
    () => wasm.action_from_argv(JSON.stringify(tokens), raw ?? null, cwd ?? null),
    "core_record_invalid",
    "the core refused to build a command record from argv",
  );
  return actionRecordFromCoreJson(json);
}

/**
 * Build a `command` {@link ActionRecord} from a shell-style command line, using the core's
 * `action_from_command` (which tokenizes it; quotes are respected and nothing is expanded). The
 * result is exactly the core's record (top-level keys camelCased, `syntactic` passed through).
 *
 * @throws {@link CommandActionError} (as a rejection) if `commandLine` is not a string, cannot be
 * tokenized (e.g. an unmatched quote), or contains no command.
 */
export async function commandActionFromLine(
  commandLine: string,
  options: CommandActionFromLineOptions = {},
): Promise<ActionRecord> {
  if (typeof commandLine !== "string") {
    throw new CommandActionError(
      "command_line_not_string",
      `commandLine must be a string (got ${describe(commandLine)})`,
    );
  }
  const cwd = optionalString(options.cwd, "cwd");
  const wasm = await loadWasm();
  const json = callCore(
    () => wasm.action_from_command(commandLine, cwd ?? null),
    "command_line_unparseable",
    // The text itself is not echoed: a command line can carry secrets.
    "commandLine could not be parsed as a command (check for an unmatched quote)",
  );
  const action = actionRecordFromCoreJson(json);
  // A blank line tokenizes to nothing: the core then records no argv. Refuse rather than ask a
  // human to approve an empty command. (This reads the core's output; it does not re-tokenize.)
  const syntacticArgv = (action.syntactic as { argv?: unknown }).argv;
  if (!Array.isArray(syntacticArgv) || syntacticArgv.length === 0) {
    throw new CommandActionError("command_line_empty", "commandLine contains no command");
  }
  return action;
}

/**
 * Build a complete {@link ApprovalRequest} for a command, ready for `client.requestApproval`.
 * `requestApproval` is unchanged; this only fills in the request.
 *
 * Defaults (each overridable):
 * - `action` — built by the core from `argv` ({@link commandAction}) or `commandLine`
 *   ({@link commandActionFromLine}).
 * - `risk` — **taken from the core-built `action.risk`**, so the caller never states it twice and
 *   cannot contradict the core's classification. (Not overridable.)
 * - `actor` — `{ id: "machine:<os.hostname()>", kind: "script" }`.
 * - `reversible` — `false` (the human is told the action cannot be undone unless the caller says
 *   otherwise).
 * - `timeoutMs`, `signal`, `constraints`, `chain` — passed through when given; otherwise
 *   `requestApproval`'s own defaults apply.
 *
 * The verdict is a decision, not permission: the caller still checks
 * `verdict.decision === "approved"` and composes its own `allow` (fail-closed on anything else).
 *
 * @throws {@link CommandActionError} (as a rejection) if both or neither of `argv` / `commandLine`
 * is given, the command input is malformed (see {@link commandAction} /
 * {@link commandActionFromLine}), `summary` is blank, or an option has the wrong type.
 */
export async function commandRequest(input: CommandRequestInput): Promise<ApprovalRequest> {
  const hasArgv = input.argv !== undefined;
  const hasLine = input.commandLine !== undefined;
  if (hasArgv === hasLine) {
    throw new CommandActionError(
      "ambiguous_command",
      "commandRequest needs exactly one of `argv` or `commandLine`",
    );
  }
  if (typeof input.summary !== "string" || input.summary.trim() === "") {
    throw new CommandActionError(
      "invalid_option",
      "summary must be a non-blank string (it is what the human is shown)",
    );
  }
  if (input.reversible !== undefined && typeof input.reversible !== "boolean") {
    throw new CommandActionError(
      "invalid_option",
      `reversible must be a boolean (got ${describe(input.reversible)})`,
    );
  }

  const cwdOption = input.cwd !== undefined ? { cwd: input.cwd } : {};
  const action =
    input.argv !== undefined
      ? await commandAction(input.argv, {
          ...cwdOption,
          ...(input.raw !== undefined ? { raw: input.raw } : {}),
        })
      : await commandActionFromLine(input.commandLine, cwdOption);

  return {
    action,
    summary: input.summary,
    actor: input.actor ?? defaultActor(),
    risk: action.risk,
    reversible: input.reversible ?? false,
    // Optional fields are spread only when present so absent values omit the key
    // (exactOptionalPropertyTypes), matching a hand-built request byte for byte.
    ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
    ...(input.signal !== undefined ? { signal: input.signal } : {}),
    ...(input.constraints !== undefined ? { constraints: input.constraints } : {}),
    ...(input.chain !== undefined ? { chain: input.chain } : {}),
  };
}

// ── Internals ──────────────────────────────────────────────────────────────────────────────────

/** The default script actor: this machine, acting as a script. */
function defaultActor(): Actor {
  return { id: `machine:${hostname()}`, kind: "script" };
}

/**
 * Check `argv` is a non-empty array of strings with a non-empty program, returning a plain copy.
 * This is input validation of the SDK's own API, not tokenization: the core still does all
 * splitting and classification.
 */
function validateArgv(argv: unknown): string[] {
  if (!Array.isArray(argv)) {
    throw new CommandActionError(
      "argv_not_array",
      `argv must be an array of strings (got ${describe(argv)})`,
    );
  }
  if (argv.length === 0) {
    throw new CommandActionError("argv_empty", "argv must not be empty (argv[0] is the program)");
  }
  const tokens: string[] = [];
  for (const [i, token] of (argv as unknown[]).entries()) {
    if (typeof token !== "string") {
      throw new CommandActionError(
        "argv_element_not_string",
        `argv[${String(i)}] must be a string (got ${describe(token)})`,
      );
    }
    tokens.push(token);
  }
  if (tokens[0] === "") {
    throw new CommandActionError(
      "argv_program_empty",
      "argv[0] (the program) must be a non-empty string",
    );
  }
  return tokens;
}

/** Validate an optional string option, returning it (or `undefined`). */
function optionalString(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new CommandActionError(
      "invalid_option",
      `${name} must be a string (got ${describe(value)})`,
    );
  }
  return value;
}

/** Run a core builder, wrapping any thrown error as a {@link CommandActionError}. */
function callCore(build: () => string, reason: CommandActionErrorReason, message: string): string {
  try {
    return build();
  } catch (cause) {
    throw new CommandActionError(reason, message, { cause });
  }
}

/** The exact top-level keys a v1 core `command` record carries (reserved T3 slots are omitted). */
const CORE_RECORD_KEYS = ["record_schema_version", "surface", "syntactic", "risk"] as const;

const RISKS: readonly Risk[] = ["low", "medium", "high", "critical"];

/**
 * Translate the core's snake_case `ActionRecord` JSON into the SDK's camelCase
 * {@link ActionRecord}. Fails closed unless the record is a v1 `command` record with exactly the
 * keys the SDK represents — an extra key (e.g. a populated reserved `capabilities` slot) would be
 * silently dropped by the translation, so the result would no longer be the core's record.
 *
 * @internal Exported only so its fail-closed branches can be tested directly; not re-exported
 * from the package entry point.
 */
export function actionRecordFromCoreJson(json: string): ActionRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (cause) {
    throw new CommandActionError("core_record_invalid", "the core returned invalid JSON", {
      cause,
    });
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new CommandActionError("core_record_invalid", "the core record is not a JSON object");
  }
  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const expected = [...CORE_RECORD_KEYS].sort();
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) {
    throw new CommandActionError(
      "core_record_invalid",
      `the core record has unexpected keys: ${JSON.stringify(Object.keys(record))}`,
    );
  }
  const version = record.record_schema_version;
  const surface = record.surface;
  const risk = record.risk;
  const syntactic = record.syntactic;
  if (typeof version !== "number" || !Number.isInteger(version)) {
    throw new CommandActionError("core_record_invalid", "the core record has no schema version");
  }
  if (surface !== "command") {
    throw new CommandActionError(
      "core_record_invalid",
      `the core record surface is ${JSON.stringify(surface)}, not "command"`,
    );
  }
  if (!RISKS.includes(risk as Risk)) {
    throw new CommandActionError(
      "core_record_invalid",
      `the core record risk ${JSON.stringify(risk)} is not a known tier`,
    );
  }
  if (typeof syntactic !== "object" || syntactic === null || Array.isArray(syntactic)) {
    throw new CommandActionError("core_record_invalid", "the core record has no syntactic object");
  }
  return { recordSchemaVersion: version, surface, syntactic, risk: risk as Risk };
}

/** A short type description for error messages (never echoes the value itself). */
function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
