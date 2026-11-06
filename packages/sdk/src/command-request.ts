/**
 * Command-surface request builders: gate a command from a plain script in a few lines.
 *
 * A script that is about to run a command (for example `stripe refunds create --charge ch_…`) is a
 * `command`-surface caller, exactly like the agent hooks — there is no separate "generic" or
 * "script" surface (`docs/action-record.md` §ActionRecord). This module removes the agent-specific
 * setup a script would otherwise do by hand:
 *
 * - {@link commandAction} / {@link commandActionFromLine} return an {@link ActionRecord} built **by
 *   the audited core** (`action_from_argv` / `action_from_command` via WASM). The SDK does no
 *   interpretation of its own. It translates top-level keys to the SDK's camelCase shape and
 *   preserves the caller's raw/cwd/argv without deriving additional facts.
 * - {@link commandRequest} wraps that record into a complete {@link ApprovalRequest} with
 *   conservative defaults for the fields that only make sense for agents.
 *
 * Every builder is **fail-closed**: malformed input rejects with a {@link CommandActionError} that
 * names the problem, so nothing is ever submitted for a record the caller did not mean
 * (`docs/contract.md` §Invariants). Nothing here decides access — the caller still composes
 * `allow = approved ∧ verified ∧ policy ∧ other gates` from the verdict `requestApproval` returns.
 *
 * @see ../../../docs/action-record.md §ActionRecord (the facts substrate; `surface: "command"`)
 * @see ../../../docs/contract.md §Invariants (never returns "allow"; fail-closed; WYSIWYS)
 * @see ../../../crates/allw-wasm/src/lib.rs (`action_from_argv`, `action_from_command`)
 */

import { hostname } from "node:os";

import type { ActionRecord, Actor, ApprovalRequest, Constraints } from "./index.js";
import { loadWasm } from "./wasm.js";

/**
 * Why a command builder refused to produce a record. Stable, machine-readable companion to the
 * human-readable {@link CommandActionError.message}.
 *
 * - `argv_not_array` — `argv` was not an array.
 * - `argv_empty` — `argv` had no elements (there is no program to show the human).
 * - `argv_element_not_string` — an `argv` element was not a string.
 * - `command_line_not_string` — `commandLine` was not a string.
 * - `command_line_empty` — the line is empty or entirely Unicode whitespace.
 * - `invalid_option` — an option (`cwd`, `raw`, `summary`, `actor`, `timeoutMs`, …) had the wrong
 *   type or was blank, or `raw` was passed to {@link commandRequest}.
 * - `ambiguous_command` — {@link commandRequest} got both or neither of `argv` / `commandLine`.
 * - `core_record_invalid` — the core returned a record that is not a v1 `command` `ActionRecord`
 *   (defense in depth; the SDK refuses to forward a record it cannot faithfully represent).
 */
export type CommandActionErrorReason =
  | "argv_not_array"
  | "argv_empty"
  | "argv_element_not_string"
  | "command_line_not_string"
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
   * The working directory the command will run in, bound into `facts.cwd` so the human sees
   * where it runs. Must be non-blank. Omitted ⇒ the record is not bound to a directory.
   */
  readonly cwd?: string;
  /**
   * The original command text, for an upstream gate that already renders the command as text
   * (e.g. an agent runtime's own display string). The core records it verbatim in `facts.raw`
   * without deriving any metadata from it; the bound vector remains exactly `argv`.
   * Omitted ⇒ no `raw`.
   *
   * It **must be the exact text of `argv`**. Some approvers display `raw` in place of `argv`, so a
   * `raw` that differs from `argv` shows the human a different command than the one the verdict
   * binds. Leave it out unless you hold that exact text.
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
  /**
   * The working directory the command will run in, bound into `facts.cwd` so the human sees
   * where it runs. Must be non-blank when given.
   *
   * @defaultValue `process.cwd()`, which is where `execFile` / `spawn` run the command unless told
   * otherwise. **If you run the command somewhere else, pass that directory**, or the human is
   * shown the wrong one. Pass `null` to leave the record unbound to any directory.
   */
  readonly cwd?: string | null;
  /**
   * The automation requesting approval. `id` and `kind` must be non-blank strings.
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
  /**
   * Fail-closed deadline (ms from now, a positive integer); see {@link ApprovalRequest.timeoutMs}.
   */
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
 * tokens that will actually run) or `commandLine` (opaque command text the core records).
 *
 * Prefer `argv`, and run exactly that `argv` with `execFile` / `spawn`: re-tokenizing text could
 * bind different tokens than the ones that run (`docs/openclaw-integration.md` §5.1). There is no
 * `raw` here; a pre-rendered display string belongs only on {@link commandAction}.
 */
export type CommandRequestInput = CommandRequestCommon &
  (
    | {
        /** The exact argument vector that will run (`argv[0]` is the program). */
        readonly argv: readonly string[];
        readonly commandLine?: never;
        readonly raw?: never;
      }
    | {
        /**
         * Opaque command text, retained byte-for-byte. The caller owns choosing the execution
         * API/interpreter; this form never manufactures an argv or program identity.
         */
        readonly commandLine: string;
        readonly argv?: never;
        readonly raw?: never;
      }
  );

/**
 * Build a `command` {@link ActionRecord} from a pre-tokenized `argv`, using the core's
 * `action_from_argv`. The result is exactly the core's record (top-level keys camelCased,
 * `facts` passed through unchanged).
 *
 * @throws {@link CommandActionError} (as a rejection) if `argv` is not a non-empty array of
 * strings, or an option has the wrong type.
 */
export async function commandAction(
  argv: readonly string[],
  options: CommandActionOptions = {},
): Promise<ActionRecord> {
  const tokens = validateArgv(argv);
  const cwd = optionalCwd(options.cwd);
  const raw = optionalString(options.raw, "raw");
  const wasm = await loadWasm();
  let json: string;
  try {
    json = wasm.action_from_argv(JSON.stringify(tokens), raw ?? null, cwd ?? null);
  } catch (cause) {
    const refusal = refusalFor(ARGV_REFUSALS, cause);
    if (refusal !== undefined) throw new CommandActionError(refusal.reason, refusal.message);
    // Any other throw is still wrapped so the caller sees one error type.
    throw new CommandActionError(
      "core_record_invalid",
      "the core refused to build a command record from argv",
      { cause },
    );
  }
  return actionRecordFromCoreJson(json);
}

/**
 * Build a `command` {@link ActionRecord} from a shell-style command line, using the core's
 * `action_from_command`. The result is exactly the core's record (top-level keys camelCased,
 * `facts` passed through).
 *
 * A nonblank line is opaque caller text, including quotes, comments, operators, substitutions
 * and newlines. The builder records it verbatim without manufacturing argv or a program identity.
 * The caller owns choosing the interpreter and binding the text to what actually executes.
 *
 * @throws {@link CommandActionError} for non-string or blank text, malformed options, or a core
 * failure. Every error denies; no request is submitted.
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
  const cwd = optionalCwd(options.cwd);
  const wasm = await loadWasm();
  let json: string;
  try {
    json = wasm.action_from_command(commandLine, cwd ?? null);
  } catch (cause) {
    // Blank text has no presentation; other core failures remain fail-closed.
    const refusal = refusalFor(LINE_REFUSALS, cause);
    if (refusal !== undefined) throw new CommandActionError(refusal.reason, refusal.message);
    throw new CommandActionError(
      "core_record_invalid",
      // The text itself is not echoed: a command line can carry secrets.
      "the core refused to record commandLine",
      { cause },
    );
  }
  const action = actionRecordFromCoreJson(json);
  return action;
}

/** Blank-line refusal; other failures are not classified by human-readable error text. */
const LINE_REFUSALS = {
  no_command: { reason: "command_line_empty", message: "commandLine contains no command" },
} as const satisfies Record<string, Refusal>;

/** Empty-vector refusal; word contents are never inspected for shell meaning. */
const ARGV_REFUSALS = {
  no_command: { reason: "argv_empty", message: "argv must not be empty" },
} as const satisfies Record<string, Refusal>;

/**
 * The SDK refusal in `table` for a core error's `kind`, or `undefined` when the error has no `kind`
 * the table knows. Looked up as an own property only, so a `kind` such as `toString` never matches.
 */
function refusalFor(table: Readonly<Record<string, Refusal>>, err: unknown): Refusal | undefined {
  const kind = coreRefusalKind(err);
  return Object.hasOwn(table, kind) ? table[kind] : undefined;
}

/** An SDK reason and message for a core refusal. */
interface Refusal {
  readonly reason: CommandActionErrorReason;
  readonly message: string;
}

/** The `kind` own property of an error the core threw, or `""` when it has none. */
function coreRefusalKind(err: unknown): string {
  if (typeof err !== "object" || err === null || !Object.hasOwn(err, "kind")) return "";
  const kind = (err as { kind?: unknown }).kind;
  return typeof kind === "string" ? kind : "";
}

/**
 * Build a complete {@link ApprovalRequest} for a command, ready for `client.requestApproval`.
 * `requestApproval` is unchanged; this only fills in the request.
 *
 * Defaults (each overridable):
 * - `action` — built by the core from `argv` ({@link commandAction}) or `commandLine`
 *   ({@link commandActionFromLine}).
 * - `cwd` — `process.cwd()`. Pass the directory you will run the command in if it differs, or
 *   `null` to leave the record unbound.
 * - `reversible` — omitted unless the caller supplies a boolean assertion.
 * - `timeoutMs`, `signal`, `constraints`, `chain` — passed through when given; otherwise
 *   `requestApproval`'s own defaults apply.
 *
 * The verdict is a decision, not permission: the caller still checks
 * `verdict.decision === "approved"` and composes its own `allow` (fail-closed on anything else).
 *
 * @throws {@link CommandActionError} (as a rejection) if both or neither of `argv` / `commandLine`
 * is given, the command input is malformed (see {@link commandAction} /
 * {@link commandActionFromLine}), `summary` is blank, `raw` is given, or an option has the wrong
 * type or is blank (`cwd`, `actor`, `timeoutMs`, `reversible`).
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
  // `raw` is a commandAction-only display string (it must be argv's exact text); refuse it here
  // rather than silently dropping or forwarding something the human might be shown instead.
  if ((input as { raw?: unknown }).raw !== undefined) {
    throw new CommandActionError(
      "invalid_option",
      "commandRequest does not take `raw`; pass `argv` (or use commandAction for a display string)",
    );
  }
  const actor = input.actor === undefined ? defaultActor() : validateActor(input.actor);
  if (input.timeoutMs !== undefined && !isPositiveInteger(input.timeoutMs)) {
    throw new CommandActionError(
      "invalid_option",
      `timeoutMs must be a positive integer (got ${describe(input.timeoutMs)})`,
    );
  }

  // `undefined` ⇒ where execFile/spawn run by default; `null` ⇒ explicitly unbound.
  const cwd = input.cwd === undefined ? process.cwd() : input.cwd;
  const cwdOption = cwd === null ? {} : { cwd };
  const action =
    input.argv !== undefined
      ? await commandAction(input.argv, cwdOption)
      : await commandActionFromLine(input.commandLine, cwdOption);

  return {
    action,
    summary: input.summary,
    actor,

    ...(input.reversible !== undefined ? { reversible: input.reversible } : {}),
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
 * Check `argv` is a non-empty array of strings, returning a plain copy.
 * This validates SDK input types; word contents remain opaque caller facts.
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
  return tokens;
}

/** Validate an optional `cwd`: a non-blank string, or `undefined`. */
function optionalCwd(value: unknown): string | undefined {
  const cwd = optionalString(value, "cwd");
  if (cwd?.trim() === "") {
    throw new CommandActionError("invalid_option", "cwd must be a non-blank string");
  }
  return cwd;
}

/** Validate a caller-supplied actor: a plain object with non-blank string `id` and `kind`. */
function validateActor(value: unknown): Actor {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new CommandActionError(
      "invalid_option",
      `actor must be an object with id and kind (got ${describe(value)})`,
    );
  }
  const actor = value as Record<string, unknown>;
  for (const field of ["id", "kind"] as const) {
    const v = actor[field];
    if (typeof v !== "string" || v.trim() === "") {
      throw new CommandActionError(
        "invalid_option",
        `actor.${field} must be a non-blank string (got ${describe(v)})`,
      );
    }
  }
  if (actor.attestation !== undefined && typeof actor.attestation !== "string") {
    throw new CommandActionError(
      "invalid_option",
      `actor.attestation must be a string (got ${describe(actor.attestation)})`,
    );
  }
  return value as Actor;
}

/** Is `value` a positive safe integer? */
function isPositiveInteger(value: unknown): boolean {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
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

/** The exact top-level keys of the current core command record; no policy/risk slots exist. */
const CORE_RECORD_KEYS = ["record_schema_version", "surface", "facts"] as const;

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
  const rawFacts = record.facts;
  if (version !== 3) {
    throw new CommandActionError("core_record_invalid", "the core record has no schema version");
  }
  if (surface !== "command") {
    throw new CommandActionError(
      "core_record_invalid",
      `the core record surface is ${JSON.stringify(surface)}, not "command"`,
    );
  }
  if (typeof rawFacts !== "object" || rawFacts === null || Array.isArray(rawFacts)) {
    throw new CommandActionError("core_record_invalid", "the core record has no facts object");
  }
  // A command builder emits only these caller facts. Reject drift rather than silently
  // forwarding a record whose meaning or shape the SDK cannot represent faithfully.
  const facts = Object.fromEntries(Object.entries(rawFacts));
  if (
    Object.keys(facts).some((key) => !["raw", "cwd", "argv"].includes(key)) ||
    (facts.raw !== undefined && typeof facts.raw !== "string") ||
    (facts.cwd !== undefined && typeof facts.cwd !== "string") ||
    (facts.argv !== undefined &&
      (!Array.isArray(facts.argv) ||
        facts.argv.length === 0 ||
        !facts.argv.every((word: unknown) => typeof word === "string"))) ||
    (facts.argv === undefined && (typeof facts.raw !== "string" || facts.raw.trim() === ""))
  ) {
    throw new CommandActionError(
      "core_record_invalid",
      "the core command record has malformed caller facts",
    );
  }
  return { recordSchemaVersion: version, surface, facts: rawFacts };
}

/** A short type description for error messages (never echoes the value itself). */
function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
