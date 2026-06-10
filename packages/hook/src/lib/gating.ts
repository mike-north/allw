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
 * - **everything else** (`Read`, `Edit`, `Write`, `Glob`, `Grep`, `WebFetch`, …) — **not gated**.
 *   These either don't run shell/MCP side effects or are out of v0 scope; they pass through as
 *   `allow` without prompting. Widening the matcher is a future, additive change.
 *
 * Gating is intentionally separate from risk: *whether* to ask the human is a matcher decision
 * here; *how risky* the action is, is the `ActionRecord.risk` the core assigns. A finer policy tier
 * (skip-on-low-risk, etc.) is the policy layer's job (`docs/policy-seam.md`), not the hook's.
 *
 * # Fail-closed
 * If a call is gated but its `ActionRecord` cannot be built (a malformed command, unparseable MCP
 * params, the wrong `tool_input` shape), this returns a `build-error` outcome carrying a reason —
 * the caller denies. A gated call is never silently allowed.
 *
 * @see ../../../../docs/policy-seam.md §The three tiers (the syntactic substrate, surfaces)
 * @see https://code.claude.com/docs/en/hooks (tool_name / tool_input; mcp__server__tool naming)
 */

import type { HookWasm } from "./wasm.js";

/** The `mcp__<server>__<tool>` prefix Claude Code uses for every MCP tool name. */
const MCP_TOOL_PREFIX = "mcp__";

/** The Bash tool name (the v0 command surface). */
const BASH_TOOL_NAME = "Bash";

/**
 * The outcome of classifying + reducing a tool call:
 * - `gated`: build succeeded; `actionRecord` (JSON) + a one-line `summary` are ready to submit.
 * - `pass-through`: not a gated tool; allow without prompting (`reason` explains why).
 * - `build-error`: gated, but the `ActionRecord` could not be built; deny (`reason` explains why).
 */
export type GateOutcome =
  | {
      readonly kind: "gated";
      readonly actionRecord: string;
      readonly summary: string;
    }
  | { readonly kind: "pass-through"; readonly reason: string }
  | { readonly kind: "build-error"; readonly reason: string };

/** Narrow `tool_input` to a `Bash` shape: a `{ command: string }`. */
function readBashCommand(toolInput: unknown): string | null {
  if (typeof toolInput !== "object" || toolInput === null) return null;
  const command = (toolInput as { command?: unknown }).command;
  return typeof command === "string" ? command : null;
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

/**
 * True if a tool name is one this hook gates: `Bash`, or **any** `mcp__`-prefixed name.
 *
 * Crucially, gating an MCP name does NOT require it to fully parse as `mcp__<server>__<tool>`. The
 * recommended `.claude/settings.json` matcher is `mcp__.*`, so Claude Code routes every
 * `mcp__`-prefixed name — including malformed ones like `mcp__server__` or `mcp__onlytwo` — to this
 * hook. Treating a malformed MCP name as non-gated would pass it through as `allow`, breaking
 * fail-closed for MCP calls. So the prefix alone gates; `gateToolCall` then denies the ones that
 * cannot be reduced to an `ActionRecord`.
 */
export function isGatedTool(toolName: string): boolean {
  return toolName === BASH_TOOL_NAME || hasMcpPrefix(toolName);
}

/** Truncate a summary so a long command/params blob stays a one-liner in the notification. */
function oneLine(s: string, max = 160): string {
  const collapsed = s.replace(/\s+/g, " ").trim();
  return collapsed.length > max ? `${collapsed.slice(0, max - 1)}…` : collapsed;
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
  if (toolName === BASH_TOOL_NAME) {
    const command = readBashCommand(toolInput);
    if (command === null) {
      return {
        kind: "build-error",
        reason: "allw: Bash tool_input missing a string 'command' (fail-closed deny)",
      };
    }
    try {
      // Pass cwd through to the core only when present; the FFI maps `undefined` → `None`.
      const actionRecord =
        cwd === undefined
          ? wasm.action_from_command(command)
          : wasm.action_from_command(command, cwd);
      return { kind: "gated", actionRecord, summary: oneLine(`Run command: ${command}`) };
    } catch (err) {
      return {
        kind: "build-error",
        reason: `allw: could not build an ActionRecord for the command (fail-closed deny): ${
          err instanceof Error ? err.message : String(err)
        }`,
      };
    }
  }

  if (hasMcpPrefix(toolName)) {
    const mcp = parseMcpToolName(toolName);
    if (mcp === null) {
      // The name is `mcp__`-prefixed (so the `mcp__.*` matcher routed it here) but does NOT parse
      // as `mcp__<server>__<tool>` (e.g. `mcp__server__`, `mcp__onlytwo`). It is still an MCP call;
      // we cannot build a record for it, so we DENY rather than pass through (fail-closed).
      return {
        kind: "build-error",
        reason: `allw: MCP tool name '${toolName}' is not a well-formed 'mcp__<server>__<tool>' (fail-closed deny)`,
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
        reason: `allw: could not build an ActionRecord for the MCP tool call (fail-closed deny): ${
          err instanceof Error ? err.message : String(err)
        }`,
      };
    }
  }

  // A genuinely non-Bash, non-MCP tool (Read/Edit/Grep/…) is not gated — pass through as before.
  return {
    kind: "pass-through",
    reason: `allw: tool '${toolName}' is not gated by allw; passing through`,
  };
}
