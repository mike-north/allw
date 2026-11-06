/**
 * Gating: decide whether a pending PreToolUse tool call needs a human approval, and — when it does
 * — build the `ActionRecord` for it through the WASM core.
 *
 * # What is gated (v0)
 * Deliberately conservative, so the human is only bothered for actions that actually mutate state:
 *
 * - **`Bash`** — a shell command. Gated; the substrate is built from `tool_input.command` (+ `cwd`).
 * - **`mcp__<server>__<tool>`** — any MCP tool call. Gated; the substrate is built from the parsed
 *   server/tool name and `tool_input` (the raw params object).
 * - **`apply_patch` / `Edit` / `Write` / `MultiEdit`** — file edits. Gated; the substrate is
 *   built from the operation kind, target paths, a compact summary, and a hash of the full edit
 *   bytes.
 * - **everything else** (`Read`, `Glob`, `Grep`, `WebFetch`, …) — **not gated**. These either
 *   don't run shell/MCP/file-edit side effects or are out of v0 scope; allw makes no decision for
 *   them (empty stdout), so Claude Code's own permission rules and mode decide. Widening the set of
 *   gated tools is a future, additive change.
 *
 * Tool-name gating decides whether to ask the human. The hook does not infer what the action
 * means, rate danger, or assert reversibility; caller policy remains outside allw.
 *
 * # Fail-closed
 * If a call is gated but its `ActionRecord` cannot be built (a malformed command, unparseable MCP
 * params, the wrong `tool_input` shape), this returns a `build-error` outcome carrying a reason —
 * the caller denies. A gated call is never silently allowed.
 *
 * @see ../../../../docs/action-record.md §The action record (the syntactic substrate, surfaces)
 * @see https://code.claude.com/docs/en/hooks (tool_name / tool_input; mcp__server__tool naming)
 */

import { agentSafeErrorText, agentSafeText } from "./agent-text.js";
import type { HookWasm } from "./wasm.js";

/** The `mcp__<server>__<tool>` prefix Claude Code uses for every MCP tool name. */
const MCP_TOOL_PREFIX = "mcp__";

/** The Bash tool name (the v0 command surface). */
const BASH_TOOL_NAME = "Bash";

/**
 * Claude Code's PowerShell tool: a shell command in `tool_input.command`, like Bash, but in
 * PowerShell syntax, recorded opaquely by the same line builder as other command tools.
 */
const POWERSHELL_TOOL_NAME = "PowerShell";

/**
 * Claude Code's Monitor tool. With `tool_input.command` it runs a shell command in the background,
 * exactly as Bash would (and under Bash's permission rules), so it is gated like Bash. With
 * `tool_input.ws` it opens a WebSocket watch instead and runs nothing (#298).
 */
const MONITOR_TOOL_NAME = "Monitor";

/** Codex's patch application tool name. */
const APPLY_PATCH_TOOL_NAME = "apply_patch";

/** Claude Code file-editing tool names that can mutate files without going through Bash. */
const CLAUDE_FILE_EDIT_TOOLS = new Set(["Edit", "MultiEdit", "Write", "NotebookEdit"]);

/**
 * The outcome of classifying + reducing a tool call:
 * - `gated`: build succeeded; `actionRecord` (JSON) + a one-line `summary` are ready to submit.
 * - `pass-through`: not a gated tool, or a call that runs nothing (a `Monitor` WebSocket watch);
 *   allw makes no decision (`reason` explains why).
 * - `build-error`: gated, but the `ActionRecord` could not be built; deny (`reason` explains why).
 *
 * A `reason` is safe to hand the agent as is: every third-party segment it quotes (a tool or server
 * name, tool input, a core error) has been through the core escape (#364). The `summary` is raw: it
 * goes to the approver, which applies its own display escape, and a deny reason that quotes it must
 * escape it first.
 */
export type GateOutcome =
  | {
      readonly kind: "gated";
      readonly actionRecord: string;
      readonly summary: string;
    }
  | { readonly kind: "pass-through"; readonly reason: string }
  | { readonly kind: "build-error"; readonly reason: string };

/** Narrow `tool_input` to a `Bash`-shaped `{ command: string }` (also PowerShell and Monitor). */
function readBashCommand(toolInput: unknown): string | null {
  if (typeof toolInput !== "object" || toolInput === null) return null;
  const command = (toolInput as { command?: unknown }).command;
  return typeof command === "string" ? command : null;
}

/** Read a string field from an untrusted tool_input record. */
function readStringField(toolInput: unknown, key: string): string | null {
  if (typeof toolInput !== "object" || toolInput === null || Array.isArray(toolInput)) return null;
  const value = (toolInput as Record<string, unknown>)[key];
  return typeof value === "string" ? value : null;
}

/**
 * Split a Claude Code MCP tool name into `{ server, tool }`.
 *
 * The format is `mcp__<server>__<tool>` (e.g. `mcp__omnifocus__delete_project`). The server is the
 * single segment after the `mcp__` prefix; everything after the next `__` is the tool (which may
 * itself contain `__`). Returns `null` if the name doesn't have both parts.
 */
export function parseMcpToolName(toolName: string): { server: string; tool: string } | null {
  if (!toolName.startsWith(MCP_TOOL_PREFIX)) return null;
  const rest = toolName.slice(MCP_TOOL_PREFIX.length);
  const sep = rest.indexOf("__");
  if (sep <= 0) return null;
  const server = rest.slice(0, sep);
  const tool = rest.slice(sep + 2);
  if (server.length === 0 || tool.length === 0) return null;
  return { server, tool };
}

/** True if a tool name carries the `mcp__` prefix — whether or not it fully parses. */
function hasMcpPrefix(toolName: string): boolean {
  return toolName.startsWith(MCP_TOOL_PREFIX);
}

/** True if a tool name represents a direct file-edit operation this hook must gate. */
function isFileEditTool(toolName: string): boolean {
  return toolName === APPLY_PATCH_TOOL_NAME || CLAUDE_FILE_EDIT_TOOLS.has(toolName);
}

/**
 * True if a tool name is one this hook gates: the shell tools (`Bash`, `PowerShell`, `Monitor`),
 * the file edit tools (including `NotebookEdit`), or **any** `mcp__`-prefixed name. A `Monitor`
 * call is routed here even when it turns out to be a WebSocket watch; `gateToolCall` then makes no
 * decision for it.
 *
 * Crucially, gating an MCP name does NOT require it to fully parse as `mcp__<server>__<tool>`. The
 * recommended `.claude/settings.json` matcher includes `^mcp__`, so Claude Code routes every
 * `mcp__`-prefixed name — including malformed ones like `mcp__server__` or `mcp__onlytwo` — to this
 * hook. Treating a malformed MCP name as non-gated would make no decision for it, leaving it to
 * Claude Code's own rules and breaking fail-closed for MCP calls. So the prefix alone gates; `gateToolCall` then denies the ones that
 * cannot be reduced to an `ActionRecord`.
 */
export function isGatedTool(toolName: string): boolean {
  return (
    toolName === BASH_TOOL_NAME ||
    toolName === POWERSHELL_TOOL_NAME ||
    toolName === MONITOR_TOOL_NAME ||
    isFileEditTool(toolName) ||
    hasMcpPrefix(toolName)
  );
}

/**
 * What a `Monitor` call asks for: a shell `command`, a WebSocket `ws` watch, or neither (malformed).
 * Claude Code accepts exactly one of the two, so a call carrying both is malformed too.
 */
type MonitorRequest =
  | { readonly kind: "command"; readonly command: string }
  | { readonly kind: "ws" }
  | { readonly kind: "malformed" };

/**
 * The `Monitor` input keys a WebSocket watch may carry, top level and inside `ws`, from Claude
 * Code's closed Monitor input schema. A watch with any other key is not one the hook can vouch runs
 * nothing, so it is malformed (denied) rather than passed through.
 */
const MONITOR_WS_KEYS = new Set(["ws", "description", "timeout_ms"]);
const MONITOR_WS_FIELDS = new Set(["url", "protocols"]);

/**
 * True if the optional fields of a WebSocket watch have the types Claude Code's schema gives them,
 * when present: `ws.protocols` an array of strings, `description` a string, `timeout_ms` a finite
 * number. A watch with a field of any other type is malformed (denied).
 */
function monitorWsFieldTypesValid(
  record: Record<string, unknown>,
  ws: Record<string, unknown>,
): boolean {
  const { protocols } = ws;
  const { description, timeout_ms: timeoutMs } = record;
  return (
    (protocols === undefined ||
      (Array.isArray(protocols) && protocols.every((p) => typeof p === "string"))) &&
    (description === undefined || typeof description === "string") &&
    (timeoutMs === undefined || (typeof timeoutMs === "number" && Number.isFinite(timeoutMs)))
  );
}

/** True if every key of `value` is in `allowed`. */
function onlyKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

/**
 * Classify a `Monitor` `tool_input`. A `ws` watch needs an object with a string `url`, no key
 * outside the watch schema at either level, and correctly typed optional fields.
 */
function readMonitorRequest(toolInput: unknown): MonitorRequest {
  if (typeof toolInput !== "object" || toolInput === null || Array.isArray(toolInput)) {
    return { kind: "malformed" };
  }
  const record = toolInput as Record<string, unknown>;
  const hasCommand = "command" in record;
  const hasWs = "ws" in record;
  if (hasCommand && !hasWs) {
    return typeof record.command === "string"
      ? { kind: "command", command: record.command }
      : { kind: "malformed" };
  }
  if (hasWs && !hasCommand) {
    const ws = record.ws;
    const wellFormed =
      readStringField(ws, "url") !== null &&
      onlyKeys(record, MONITOR_WS_KEYS) &&
      onlyKeys(ws as Record<string, unknown>, MONITOR_WS_FIELDS) &&
      monitorWsFieldTypesValid(record, ws as Record<string, unknown>);
    return wellFormed ? { kind: "ws" } : { kind: "malformed" };
  }
  return { kind: "malformed" };
}

/** Truncate a summary so a long command/params blob stays a one-liner in the notification. */
function oneLine(s: string, max = 160): string {
  const collapsed = s.replace(/\s+/g, " ").trim();
  return collapsed.length > max ? `${collapsed.slice(0, max - 1)}…` : collapsed;
}

/** Add a path once, preserving first-seen order so the human sees a stable target list. */
function addUniquePath(paths: string[], path: string): void {
  const trimmed = path.trim();
  if (trimmed.length === 0 || paths.includes(trimmed)) return;
  paths.push(trimmed);
}

/** Extract target paths from Codex's apply_patch grammar. */
function extractApplyPatchPaths(patch: string): string[] | null {
  if (!patch.includes("*** Begin Patch") || !patch.includes("*** End Patch")) return null;

  const paths: string[] = [];
  for (const line of patch.split(/\r?\n/)) {
    for (const prefix of [
      "*** Add File: ",
      "*** Update File: ",
      "*** Delete File: ",
      "*** Move to: ",
    ]) {
      if (line.startsWith(prefix)) addUniquePath(paths, line.slice(prefix.length));
    }
  }
  return paths.length > 0 ? paths : null;
}

/** Read Codex apply_patch input, which may arrive as a raw string or a small object wrapper. */
function readApplyPatch(toolInput: unknown): { patch: string; paths: string[] } | null {
  const patch =
    typeof toolInput === "string"
      ? toolInput
      : (readStringField(toolInput, "patch") ??
        readStringField(toolInput, "input") ??
        readStringField(toolInput, "diff"));
  if (patch === null) return null;

  const paths = extractApplyPatchPaths(patch);
  return paths === null ? null : { patch, paths };
}

/** Compact path list for notification and ActionRecord raw summary lines. */
function formatPathList(paths: readonly string[]): string {
  if (paths.length === 1) return paths[0] ?? "";
  const shown = paths.slice(0, 3).join(", ");
  return paths.length > 3 ? `${shown}, +${String(paths.length - 3)} more` : shown;
}

/** Build the one-line summary stored in the hash-bound file-edit substrate. */
function summarizeFileEdit(operation: string, paths: readonly string[], detail?: string): string {
  const suffix = detail === undefined ? "" : ` ${detail}`;
  return oneLine(`${operation} ${formatPathList(paths)}${suffix}`);
}

type FileEditReduction =
  | {
      readonly operation: string;
      readonly paths: readonly string[];
      readonly diffSummary: string;
      readonly diffBytes: string;
    }
  | { readonly error: string };

/** The edit modes Claude Code's `NotebookEdit` accepts; `replace` is its default. */
const NOTEBOOK_EDIT_MODES = new Set(["replace", "insert", "delete"]);

/**
 * Every `NotebookEdit` input key the hook understands. A call carrying any other key (for example
 * the older `cell_number` targeting field) is denied: a key the hook drops would be neither bound
 * nor shown, so it could change which cell is edited without the human seeing it.
 */
const NOTEBOOK_EDIT_KEYS = new Set([
  "notebook_path",
  "cell_id",
  "cell_type",
  "edit_mode",
  "new_source",
]);

/**
 * Reduce a `NotebookEdit` call (one cell of a Jupyter notebook) into the core's file_edit builder
 * inputs. The hash-bound bytes are the cell-level change itself: which cell, how, and the new source.
 * The summary names the cell: `replace` and `delete` must target one by `cell_id`, and `insert`
 * adds a cell after the given one, or at the start of the notebook without one.
 */
function reduceNotebookEdit(toolInput: unknown): FileEditReduction {
  const notebookPath = readStringField(toolInput, "notebook_path");
  if (notebookPath === null || notebookPath.trim().length === 0) {
    return { error: "NotebookEdit tool_input missing a string 'notebook_path'" };
  }
  const record = toolInput as Record<string, unknown>;
  const unknownKey = Object.keys(record).find((key) => !NOTEBOOK_EDIT_KEYS.has(key));
  if (unknownKey !== undefined) {
    return { error: `NotebookEdit tool_input has an unsupported key '${unknownKey}'` };
  }
  const optionalString = (key: string): string | null | undefined => {
    const value = record[key];
    if (value === undefined || value === null) return null;
    return typeof value === "string" ? value : undefined;
  };
  const cellId = optionalString("cell_id");
  const cellType = optionalString("cell_type");
  const editMode = optionalString("edit_mode");
  const newSource = optionalString("new_source");
  if (cellId === undefined || cellType === undefined || editMode === undefined) {
    return {
      error: "NotebookEdit tool_input has a non-string 'cell_id', 'cell_type' or 'edit_mode'",
    };
  }
  const mode = editMode ?? "replace";
  if (!NOTEBOOK_EDIT_MODES.has(mode)) {
    return { error: `NotebookEdit tool_input has an unknown 'edit_mode' '${mode}'` };
  }
  if (newSource === undefined || (newSource === null && mode !== "delete")) {
    return { error: "NotebookEdit tool_input missing a string 'new_source'" };
  }
  // An empty `cell_id` names no cell, so it counts as absent; the hash still binds the value sent.
  const namedCell = cellId === null || cellId === "" ? null : cellId;
  if (namedCell === null && mode !== "insert") {
    return { error: `NotebookEdit '${mode}' needs a string 'cell_id' naming the cell` };
  }
  const paths = [notebookPath];
  const target =
    mode === "insert"
      ? namedCell === null
        ? "insert at start"
        : `insert after cell ${namedCell}`
      : `${mode} cell ${namedCell ?? ""}`;
  return {
    operation: "notebook_edit",
    paths,
    diffSummary: summarizeFileEdit("notebook_edit", paths, `(${target})`),
    diffBytes: JSON.stringify({
      notebook_path: notebookPath,
      cell_id: cellId,
      cell_type: cellType,
      edit_mode: mode,
      new_source: newSource,
    }),
  };
}

/** Reduce a direct file-edit tool call into the core's file_edit builder inputs. */
function reduceFileEdit(toolName: string, toolInput: unknown): FileEditReduction {
  if (toolName === APPLY_PATCH_TOOL_NAME) {
    const patch = readApplyPatch(toolInput);
    if (patch === null) {
      return { error: "apply_patch tool_input must contain a valid patch with target paths" };
    }
    return {
      operation: "patch",
      paths: patch.paths,
      diffSummary: summarizeFileEdit("patch", patch.paths),
      diffBytes: patch.patch,
    };
  }

  if (toolName === "NotebookEdit") return reduceNotebookEdit(toolInput);

  const filePath = readStringField(toolInput, "file_path");
  if (filePath === null || filePath.trim().length === 0) {
    return { error: `${toolName} tool_input missing a string 'file_path'` };
  }
  const paths = [filePath];

  if (toolName === "Edit") {
    const oldString = readStringField(toolInput, "old_string");
    const newString = readStringField(toolInput, "new_string");
    if (oldString === null || newString === null) {
      return { error: "Edit tool_input missing string 'old_string' or 'new_string'" };
    }
    return {
      operation: "edit",
      paths,
      diffSummary: summarizeFileEdit("edit", paths),
      diffBytes: JSON.stringify({
        file_path: filePath,
        old_string: oldString,
        new_string: newString,
        replace_all: (toolInput as Record<string, unknown>).replace_all,
      }),
    };
  }

  if (toolName === "Write") {
    const content = readStringField(toolInput, "content");
    if (content === null) return { error: "Write tool_input missing string 'content'" };
    return {
      operation: "write",
      paths,
      diffSummary: summarizeFileEdit("write", paths, `(${String(content.length)} bytes)`),
      diffBytes: JSON.stringify({ file_path: filePath, content }),
    };
  }

  if (toolName === "MultiEdit") {
    const edits =
      typeof toolInput === "object" && toolInput !== null && !Array.isArray(toolInput)
        ? (toolInput as Record<string, unknown>).edits
        : undefined;
    if (!Array.isArray(edits)) return { error: "MultiEdit tool_input missing array 'edits'" };
    return {
      operation: "multi_edit",
      paths,
      diffSummary: summarizeFileEdit("multi_edit", paths, `(${String(edits.length)} edits)`),
      diffBytes: JSON.stringify({ file_path: filePath, edits }),
    };
  }

  return { error: `unsupported file edit tool '${toolName}'` };
}

/**
 * A POSIX shell command call (`Bash`, or `Monitor` with a `command`), read from its `tool_input`
 * but not yet built into a record:
 * - `command`: the command line to record, and the one-line `summary` the human is shown.
 * - `pass-through`: a `Monitor` WebSocket watch, which runs no command.
 * - `build-error`: the `tool_input` has the wrong shape; deny (`reason` is a constant).
 *
 * Both hooks build the request for a `command` through `@allw/sdk`'s `commandRequest` (#269,
 * #372), which also refuses a blank command or program. {@link gateToolCall} still builds a core
 * record for one directly, for a caller that uses it on its own, and refuses the same commands with
 * the same reason.
 */
export type PosixCommandCall =
  | { readonly kind: "command"; readonly command: string; readonly summary: string }
  | { readonly kind: "pass-through"; readonly reason: string }
  | { readonly kind: "build-error"; readonly reason: string };

/**
 * Read a POSIX shell command call (`Bash`, or `Monitor`'s `command`) from its `tool_input`.
 * Returns `null` for any other tool. This only reads the input; the record is built by the caller.
 */
export function posixCommandCall(toolName: string, toolInput: unknown): PosixCommandCall | null {
  if (toolName === BASH_TOOL_NAME) {
    const command = readBashCommand(toolInput);
    if (command === null) {
      return {
        kind: "build-error",
        reason: "allw: Bash tool_input missing a string 'command' (fail-closed deny)",
      };
    }
    return { kind: "command", command, summary: oneLine(`Run command: ${command}`) };
  }

  if (toolName === MONITOR_TOOL_NAME) {
    const request = readMonitorRequest(toolInput);
    if (request.kind === "ws") {
      // A WebSocket watch runs no command: it is a read-only network subscription, and allw does
      // not gate raw egress (docs/action-record.md). Claude Code's own WebSocket prompt still applies.
      return { kind: "pass-through", reason: "allw: Monitor WebSocket watch runs no command" };
    }
    if (request.kind === "malformed") {
      return {
        kind: "build-error",
        reason:
          "allw: Monitor tool_input must have either a string 'command' or a 'ws' object with a " +
          "string 'url' (fail-closed deny)",
      };
    }
    return {
      kind: "command",
      command: request.command,
      summary: oneLine(`Run command (Monitor): ${request.command}`),
    };
  }

  return null;
}

/**
 * True if `err` is `@allw/sdk`'s `CommandActionError`. Checked by its name and `reason` field, not
 * `instanceof`: a published install can hold two copies of the SDK (the codex-hook's and this
 * package's), and an error from one copy is not an instance of the other's class.
 */
function isCommandActionError(err: unknown): err is Error & { readonly reason: string } {
  return (
    err instanceof Error &&
    err.name === "CommandActionError" &&
    typeof (err as { reason?: unknown }).reason === "string"
  );
}

/**
 * The deny reason for a command whose request could not be built: the SDK refused it (a
 * `CommandActionError`), the core refused it, or anything else failed while building it. Both hooks
 * and {@link gateToolCall} use this, so the same command is denied with the same reason everywhere
 * (#372).
 *
 * For invalid shell syntax the SDK wraps the core's own error, which names the problem; quoting that
 * keeps the reason the same as before #269. Otherwise the SDK's message is used, without its
 * `allw: ` prefix (the reason already carries one). Either way the text goes through the core escape
 * and cap before the agent reads it.
 */
export function commandBuildFailureReason(wasm: HookWasm, err: unknown): string {
  const quoted = isCommandActionError(err)
    ? err.cause instanceof Error
      ? err.cause
      : err.message.replace(/^allw: /u, "")
    : err;
  return `allw: could not build an ActionRecord for the command (fail-closed deny): ${agentSafeErrorText(
    wasm,
    quoted,
  )}`;
}

/** Blank command text leaves no presentation and fails closed with the SDK's wording. */
const NO_COMMAND = "commandLine contains no command";
/** Only a missing presentation is a command-content refusal; other text stays opaque. */
function coreNoCommandRefusal(err: unknown): string | null {
  return typeof err === "object" &&
    err !== null &&
    Object.hasOwn(err, "kind") &&
    "kind" in err &&
    err.kind === "no_command"
    ? NO_COMMAND
    : null;
}

/** Refuse an unreadable or malformed line-builder result without inferring an argv. */
function commandRecordRefusal(actionRecord: string): string | null {
  try {
    const record: unknown = JSON.parse(actionRecord);
    if (typeof record !== "object" || record === null || !("syntactic" in record)) {
      return "the core returned a malformed command record";
    }
    const facts = record.syntactic;
    if (
      typeof facts !== "object" ||
      facts === null ||
      !("raw" in facts) ||
      typeof facts.raw !== "string" ||
      facts.raw.trim() === ""
    )
      return NO_COMMAND;
    return null;
  } catch {
    return "the core returned an unreadable command record";
  }
}

/** Build opaque command text through the core; every build/output failure denies. */
function gateCommandLine(
  wasm: HookWasm,
  command: string,
  cwd: string | undefined,
  summary: string,
): GateOutcome {
  try {
    // Pass cwd through to the core only when present; the FFI maps `undefined` → `None`.
    const actionRecord =
      cwd === undefined
        ? wasm.action_from_command(command)
        : wasm.action_from_command(command, cwd);
    const refusal = commandRecordRefusal(actionRecord);
    if (refusal !== null) {
      return { kind: "build-error", reason: commandBuildFailureReason(wasm, refusal) };
    }
    return { kind: "gated", actionRecord, summary };
  } catch (err) {
    const refusal = coreNoCommandRefusal(err);
    return { kind: "build-error", reason: commandBuildFailureReason(wasm, refusal ?? err) };
  }
}

/**
 * Classify a tool call and, when gated, build its `ActionRecord` through the WASM core.
 *
 * All `ActionRecord` construction is delegated to the core — the hook never reimplements the
 * syntactic substrate. A thrown core error (invalid shell syntax, unparseable params) is caught and
 * returned as a `build-error` so the caller fails closed.
 */
export function gateToolCall(
  wasm: HookWasm,
  toolName: string,
  toolInput: unknown,
  cwd: string | undefined,
): GateOutcome {
  const posix = posixCommandCall(toolName, toolInput);
  if (posix !== null) {
    return posix.kind === "command"
      ? gateCommandLine(wasm, posix.command, cwd, posix.summary)
      : posix;
  }

  if (toolName === POWERSHELL_TOOL_NAME) {
    const command = readBashCommand(toolInput);
    if (command === null) {
      return {
        kind: "build-error",
        reason: "allw: PowerShell tool_input missing a string 'command' (fail-closed deny)",
      };
    }
    return gateCommandLine(wasm, command, cwd, oneLine(`PowerShell: ${command}`));
  }

  if (isFileEditTool(toolName)) {
    const fileEdit = reduceFileEdit(toolName, toolInput);
    if ("error" in fileEdit) {
      return {
        kind: "build-error",
        // The error can quote tool input (a key or an edit mode), so it is escaped (#364).
        reason: `allw: ${agentSafeText(wasm, fileEdit.error)} (fail-closed deny)`,
      };
    }

    try {
      const actionRecord = wasm.action_from_file_edit(
        fileEdit.operation,
        JSON.stringify(fileEdit.paths),
        fileEdit.diffSummary,
        fileEdit.diffBytes,
      );
      return {
        kind: "gated",
        actionRecord,
        summary: oneLine(`File edit: ${fileEdit.diffSummary}`),
      };
    } catch (err) {
      return {
        kind: "build-error",
        reason: `allw: could not build an ActionRecord for the file edit (fail-closed deny): ${agentSafeErrorText(
          wasm,
          err,
        )}`,
      };
    }
  }

  if (hasMcpPrefix(toolName)) {
    const mcp = parseMcpToolName(toolName);
    if (mcp === null) {
      // The name is `mcp__`-prefixed (so the `^mcp__` matcher routed it here) but does NOT parse
      // as `mcp__<server>__<tool>` (e.g. `mcp__server__`, `mcp__onlytwo`). It is still an MCP call;
      // we cannot build a record for it, so we DENY rather than pass through (fail-closed).
      return {
        kind: "build-error",
        // The name comes from a third-party MCP server, so it is escaped (#364).
        reason: `allw: MCP tool name '${agentSafeText(wasm, toolName)}' is not a well-formed 'mcp__<server>__<tool>' (fail-closed deny)`,
      };
    }
    // The MCP tool params are the raw `tool_input` object; serialize verbatim for the core.
    const paramsJson = JSON.stringify(toolInput ?? {});
    try {
      const actionRecord = wasm.action_from_mcp_tool_call(mcp.server, mcp.tool, paramsJson);
      return {
        kind: "gated",
        actionRecord,
        summary: oneLine(`MCP tool call: ${mcp.server}.${mcp.tool}(${paramsJson})`),
      };
    } catch (err) {
      return {
        kind: "build-error",
        reason: `allw: could not build an ActionRecord for the MCP tool call (fail-closed deny): ${agentSafeErrorText(
          wasm,
          err,
        )}`,
      };
    }
  }

  // A genuinely non-Bash, non-MCP, non-file-edit tool (Read/Grep/…) is not gated.
  return {
    kind: "pass-through",
    reason: `allw: tool '${agentSafeText(wasm, toolName)}' is not gated by allw; passing through`,
  };
}
