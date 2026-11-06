# Codex Approval Gating

Issue #97 adds a Codex-local approval hook that mirrors the Claude Code hook while preserving the
project's Node + WASM local-surface constraint. For the Claude Code hook's own structural peer of
this document, see [`docs/claude-code-integration.md`](./claude-code-integration.md).

## Integration Shape

Codex exposes lifecycle hooks through `~/.codex/hooks.json`, `.codex/hooks.json`, or inline
`[hooks]` tables in `config.toml`. The allw integration uses Codex `PreToolUse`: it is the only
event that fires for **every** matched tool call — independent of the user's `approval_policy`,
`sandbox_mode`, `permission_mode`, or execpolicy `.rules` — and can block that call before it runs.
Codex's `PermissionRequest` event can also block, and its no-decision fallback is safer, but it
runs only inside Codex's approval path and "doesn't run for commands that don't need approval,"
so its coverage is a function of local Codex configuration. That disqualifies it as allw's
enforcement point. See
[Event Choice: `PreToolUse` vs `PermissionRequest`](#event-choice-pretooluse-vs-permissionrequest)
for the re-verified analysis behind this decision.

Recommended hook configuration:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|apply_patch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "npx --no-install allw-codex-hook",
            "timeout": 480,
            "statusMessage": "Requesting allw approval"
          }
        ]
      }
    ]
  }
}
```

> **Use `npx --no-install allw-codex-hook`, never plain `npx allw-codex-hook`.** `--no-install` runs
> the installed bin (project or global) and exits 1 if there is none; plain `npx` would download and
> run whatever registry package has that name, so a squatted package would run as the gate (checked
> on npm 10.9.4 and 11.21.1). If your Codex launch environment doesn't run from the project
> directory, use the absolute path to the installed bin instead (find it with
> `node -e "console.log(require.resolve('@allw/codex-hook/package.json'))"` → the `dist/cli.js`
> beside it), e.g. `"command": "node /abs/path/to/@allw/codex-hook/dist/cli.js"`.

### If the hook can't start

If Codex can't start the hook (a wrong path, `node` missing from `PATH`, `npx --no-install` finding
no installed bin), **the tool call goes ahead ungated.** Codex reports the hook run as failed and
continues; it has no setting to block on hook failure (Claude Code's `onFailure: "block"` has no
Codex equivalent). The [Codex hooks docs](https://learn.chatgpt.com/docs/hooks) don't spell out the
spawn-failure case, so this was checked in the source: in
[`pre_tool_use.rs`](https://github.com/openai/codex/blob/29eed280828d498fead76c3c5dedd9642836b571/codex-rs/hooks/src/events/pre_tool_use.rs#L211-L216)
a run error marks the hook `Failed` and leaves `should_block` false (checked 2026-11-02). After any
change to the hook command, run one gated call and confirm it reaches your approver; a hook error
in the Codex transcript means nothing was gated. See [Fail-Open Residual](#fail-open-residual).

## Quickstart

This is the Codex-parallel install path for developers who already have a paired allw approver
(see [`docs/quickstart.md`](./quickstart.md) for pairing a device from scratch):

1. Install the CLI (no Rust toolchain needed — the audited core ships pre-built as WASM inside
   `@allw/sdk`, pulled in automatically):

   ```sh
   npm install @allw/codex-hook
   ```

   Confirm it's installed and which version you have (useful for bug reports):

   ```sh
   npx --no-install allw-codex-hook --version
   ```

2. Write the integrator config file `~/.allw/config.json` (`0600`, in a `0700` `~/.allw`) with the
   relay and account trust anchor printed by `allw-approver pair` — the same file the Claude Code
   hook and `@allw/sdk` read ([`docs/quickstart.md`](./quickstart.md) §4). The hosted relay,
   `https://allw-relay.mnorth.workers.dev`, needs no Cloudflare account; substitute your own URL if
   you self-hosted per [`docs/relay-deploy.md`](./relay-deploy.md):

   ```json
   {
     "version": 1,
     "relay_url": "https://allw-relay.mnorth.workers.dev",
     "account_id": "<account id from pair>",
     "approver_root_key": "<account-root public key from pair>"
   }
   ```

   The `ALLW_RELAY_URL` / `ALLW_ACCOUNT_ID` / `ALLW_APPROVER_ROOT_KEY` env vars still work as
   per-field overrides (env wins), and `ALLW_CONFIG` moves the file (it must be an absolute path;
   a leading `~/` is expanded).

3. Add the `PreToolUse` block above to `~/.codex/hooks.json` or a trusted project
   `.codex/hooks.json`.

4. Start Codex, run `/hooks`, review the hook, and trust it. Codex skips untrusted non-managed
   hooks by design.

5. Trigger a gated action such as a Bash command, `apply_patch`, or an `mcp__<server>__<tool>`
   call. The hook submits a Codex-scoped approval request (`actor.id = "codex:<hostname>"`), and
   Codex proceeds only after a verified allw approval.

## Human-Run UAT Setup

The real-Codex UAT is intentionally operator-run. The automated/headless attempt triggered macOS
malware detection on the local Codex binary, so repository automation must prepare the environment
but must not spawn Codex.

Use the helper from the repo root:

```sh
scripts/uat-codex.sh
```

The script builds the WASM and TypeScript packages, starts a local relay, pairs a temporary
`allw-approver` keyfile, and then writes a self-contained temporary project to a system temp
directory. The project contains:

- `.codex/allw-hook.sh` — a small wrapper script that `export`s the three `ALLW_*` env vars
  (relay URL, account ID, approver root key) baked in at generation time, then `exec`s the hook
  CLI. The Codex command-hook schema has no per-handler `env` field, so the variables are baked
  into the wrapper rather than placed in `hooks.json`.
- `.codex/hooks.json` — the project-scoped Codex hook config; its `"command"` field invokes the
  wrapper via `bash <abs-path>/allw-hook.sh`. No manual `export` step is needed.
- `.codex/config.toml` — the fail-closed granular `approval_policy` from
  [Granular `approval_policy`](#granular-approval_policy), so the UAT exercises the recommended posture rather than
  Codex's defaults.
- `.codex/rules/uat.rules` — one execpolicy `prefix_rule` per decision (`allow`, `prompt`, `forbidden`), each on
  its own `echo allw-uat-rules-…` command, for the `.rules` interaction cases.

The project is also a git repository, because `codex exec` exits outside one unless it gets
`--skip-git-repo-check` (`codex-rs/exec/src/lib.rs`).

**One-time trust step.** Codex loads a project's `.codex/` config, hooks and rules only when the project is
trusted. It runs a hook that isn't managed only after the hook is approved, and that approval is stored as a hash of
the hook's config. A plain `codex exec` can grant neither, and an untrusted hook is **silently skipped**, so the gate
fails open ([Fail-Open Residual](#structural-residual-unchanged-inherent-to-pretooluse),
[#348](https://github.com/mike-north/allw/issues/348)). Before the cases, the operator runs the interactive `codex`
once in the project, trusts the folder, approves the allw `PreToolUse` hook in the startup hook review, and quits.
The helper prints this step.

`codex exec --dangerously-bypass-hook-trust` is the one exception. Verified from codex-rs source at `openai/codex`
main `ac558e2` (read, not run):

- It runs every **enabled** hook without stored hook trust, for that one invocation. Disabled hooks stay off
  (`codex-rs/hooks/src/engine/discovery.rs:917-923`).
- It is a CLI flag, off by default (`codex-rs/utils/cli/src/shared_options.rs:61-64`). `codex exec` makes it
  global (`codex-rs/exec/src/cli.rs:168`) and forwards it as a runtime override (`codex-rs/exec/src/lib.rs:618`).
- It is not a `config.toml` key. The `Config` field is documented as runtime-only
  (`codex-rs/core/src/config/mod.rs:1027-1030`).
- It does not grant project trust. The config loader never reads it
  (`codex-rs/config/src/loader/mod.rs:project_trust_context`).

**The UAT does not use it.** It skips the exact check the trust step exists for, so a pass under it says nothing
about whether the hook runs in a normal session. It also makes every enabled hook run unreviewed, not just allw's.

The helper prints the exact `codex exec` commands for the operator to run in a second terminal,
then runs `allw-approver watch` in the foreground. It never touches `~/.codex` global config
and never invokes `codex`; the human runs Codex directly.

When UAT is complete, press `Ctrl-C` in the script terminal. Its exit trap stops the relay and
removes the temporary keyfile/project.

## UAT Checklist

Run a live Codex session against the temporary project prepared by `scripts/uat-codex.sh` and
record the result on issue #97:

1. **Approve path**: ask Codex to run a harmless gated Bash command, approve it on the second
   device, and confirm Codex proceeds.
2. **Deny path**: ask Codex to run another gated Bash command, deny it on the second device, and
   confirm Codex receives `permissionDecision: "deny"` and does not run the tool.
3. **Timeout path**: set a short `ALLW_TIMEOUT_MS`, leave the approval unanswered, and confirm
   Codex denies before its 480 second hook timeout.
4. **Actor identity**: confirm the approval inbox shows the request as `codex:<hostname>` rather
   than the Claude Code actor.
5. **File-edit path**: ask Codex for a simple file edit through `apply_patch` and confirm the hook
   gates the resulting `file_edit` action with the target path, summary, and diff hash visible.
6. **Schema conformance (catches drift)**: for the deny in step 2, capture the raw JSON the hook
   wrote to stdout (e.g. temporarily redirect the wrapper's `exec` to `tee /tmp/allw-hook-stdout`)
   and confirm `hookSpecificOutput` has only `hookEventName`, `permissionDecision`, and
   `permissionDecisionReason` — no `denyReason` or other field — and that `permissionDecisionReason`
   is non-empty and starts with `allw[`. This is the live-Codex proof that the automated
   schema-conformance tests (`packages/codex-hook/test/codex-io.test.mjs`, `regression-191.test.mjs`)
   match what a real Codex build actually accepts; a future Codex schema change would show up here
   as a rejected/ignored field before it reaches production.
7. **`.rules` `allow`**: run `echo allw-uat-rules-allow`. The allw approval must still be requested on the second
   device: an `allow` rule can't skip the gate. This is the coverage claim behind staying on `PreToolUse`.
8. **`.rules` `prompt` (interactive `codex`)**: run `echo allw-uat-rules-prompt` in the TUI, because `codex exec`
   never prompts. Record which prompt appears first. Expected: the allw approval first, then Codex's own prompt, and
   a denial in allw skips Codex's prompt (see [execpolicy `.rules`](#execpolicy-rules)).
9. **`.rules` `forbidden`**: run `echo allw-uat-rules-forbidden` and approve it on the second device. Codex must
   still block it: tightening-only, consistent with `docs/contract.md` §6.
10. **Granular auto-reject (interactive `codex`)**: ask Codex to use `request_permissions` for network access. With
    `request_permissions = false` the request must be rejected without reaching a human.
11. **Permission mode**: in the deny case, capture the hook's stdin as well, and confirm the hook ran with
    `permission_mode: "bypassPermissions"` under `codex exec`.

Fixed in [#191](https://github.com/mike-north/allw/issues/191): the hook used to emit an
undocumented `denyReason` field that Codex rejected, silently discarding every deny (step 2 was
expected to FAIL). See [Fail-Open Residual](#fail-open-residual).

Use this comment template on #97:

```md
Approve: PASS/FAIL - command ran only after approval
Deny: PASS/FAIL - command was blocked after denial
Timeout: PASS/FAIL - command failed closed after ALLW_TIMEOUT_MS
Actor identity: PASS/FAIL - inbox showed codex:<hostname>
File edit: PASS/FAIL - apply_patch was gated with path, summary, and diff hash
Schema conformance: PASS/FAIL - deny stdout had only documented fields, no denyReason
.rules allow: PASS/FAIL - the allw approval was still required
.rules prompt: PASS/FAIL - order: allw first / Codex first; a denial in allw skipped Codex's prompt
.rules forbidden: PASS/FAIL - an allw-approved command was still blocked
Granular auto-reject: PASS/FAIL - request_permissions was rejected without reaching a human
Permission mode: PASS/FAIL - the hook ran under codex exec (permission_mode bypassPermissions)
Notes:
```

The automated tests cover the same SDK/WASM verification path with a relay double; this checklist
is the remaining product acceptance proof that Codex itself invokes the hook and honors the result.

The matcher intentionally matches the hook's v1 surfaces:

- `Bash` commands are converted to command `ActionRecord`s through `@allw/sdk`'s `commandRequest`,
  which builds them with the WASM core, exactly as the Claude Code hook does
  ([#372](https://github.com/mike-north/allw/issues/372)). A blank or whitespace-only command is denied (`allw[build-error]`) without asking.
  Every nonblank line is carried verbatim without interpreting quotes, operators or shell meaning. A
  blank `cwd` counts as unknown, so the record is bound to no directory. Codex reports
  **every** shell exec to `PreToolUse` as `Bash`, including `shell`, `exec_command` and unified exec
  (each handler's `pre_tool_use_payload` names it `HookToolName::bash()` in `codex-rs/core`, checked
  2026-11-03). So Codex has no separately named exec tool to match, unlike Claude Code's `Monitor` and
  `PowerShell`. Input typed into a running session is the exception; see
  [Interactive exec sessions](#interactive-exec-sessions-write_stdin).
- `apply_patch` calls are converted to file-edit `ActionRecord`s through the WASM core.
- `mcp__<server>__<tool>` calls are converted to MCP `ActionRecord`s through the WASM core.
- Other Codex tools pass through when they do not map to a supported allw approval surface.

## Decision Mapping

The hook reads the same allw config as the Claude Code hook — `~/.allw/config.json` through
`@allw/sdk`'s `loadClientConfig` — with these env vars as overrides:

| Variable                 | Required | Meaning                                                                                                                                                                                                 |
| ------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ALLW_CONFIG`            | no       | Config-file path (default `~/.allw/config.json`); must be an **absolute** path (a leading `~/` is expanded; a relative path is rejected, since it would resolve against the agent's working directory). |
| `ALLW_RELAY_URL`         | no       | Overrides `relay_url`: base URL of the zero-knowledge relay.                                                                                                                                            |
| `ALLW_ACCOUNT_ID`        | no       | Overrides `account_id`: the approver's self-certifying relay account id.                                                                                                                                |
| `ALLW_APPROVER_ROOT_KEY` | no       | Overrides `approver_root_key`: the approver account-root Ed25519 key.                                                                                                                                   |
| `ALLW_TIMEOUT_MS`        | no       | Fail-closed approval deadline in ms, capped below hook time.                                                                                                                                            |
| `ALLW_FETCH_TIMEOUT_MS`  | no       | Per-relay-fetch timeout in ms, only allowed to lower the cap.                                                                                                                                           |

With neither the file nor the overrides, or with an invalid file, every gated call is denied with a
reason naming both ways to configure.

For gated calls, the hook builds the syntactic `ActionRecord`, requests approval through
`@allw/sdk`, and maps the verdict to what it writes to stdout. Only `deny` is ever an explicit wire
decision; "allw does not block" is empty stdout and exit 0, never a bare
`permissionDecision: "allow"` — see [Fail-Open Residual](#fail-open-residual) item 3 for why:

| allw result                              | Hook output              | `permissionDecisionReason` prefix |
| ---------------------------------------- | ------------------------ | --------------------------------- |
| verified verdict `decision === approved` | _(empty stdout, exit 0)_ | —                                 |
| verified verdict `decision === denied`   | `deny`                   | `allw[no-approval]: …`            |
| verified verdict `decision === expired`  | `deny`                   | `allw[timeout]: …`                |
| verified verdict `decision === aborted`  | `deny`                   | `allw[aborted]: …`                |
| malformed gated input / ActionRecord     | `deny`                   | `allw[build-error]: …`            |
| missing or invalid allw config           | `deny`                   | `allw[config-error]: …`           |
| relay/network/approval error             | `deny`                   | `allw[transport-error]: …`        |
| malformed hook stdin                     | `deny`                   | `allw[input-parse-error]: …`      |
| non-gated tool                           | _(empty stdout, exit 0)_ | —                                 |
| process exited or was signalled first    | `deny`                   | `allw[premature-exit]: …`         |

**Exit backstop.** Because empty stdout + exit 0 is how allw says "no objection", a process that
exits _before_ deciding must not read as one. The hook installs a backstop shared with
`@allw/hook` (`packages/hook/src/lib/decision-output.ts`): if the process reaches Node's
`beforeExit` or `exit` without having written its decision (the event loop drained while an
approval was pending, the shape of [#254](https://github.com/mike-north/allw/issues/254); an uncaught
exception; a stray `process.exit(n)`), or receives `SIGTERM`, `SIGINT` or `SIGHUP` while waiting, it
prints the `premature-exit` deny above once and exits 0
([#265](https://github.com/mike-north/allw/issues/265)). If that deny, or the hook's own decision,
can't be written in full, it exits 1 instead and never appends a second decision; Codex treats that
as a non-blocking hook error. A `SIGKILL`, a native crash or a Codex
timeout can't be answered from inside the process, and Codex has no setting to block the call in
those cases (see [If the hook can't start](#if-the-hook-cant-start)). Both hooks write decisions through that one
deny-only writer, so the Claude Code hook uses the same encoding (no decision, or `deny`).

A `deny`'s `hookSpecificOutput` contains only `hookEventName`, `permissionDecision`, and
`permissionDecisionReason` — the exact fields Codex's `PreToolUse` output schema documents
(`additionalProperties: false`). There is no `denyReason` field: the machine-readable category is
instead carried as an `allw[<category>]: ` prefix on `permissionDecisionReason`, so operators can
still distinguish no-approval from timeout from config errors without parsing the rest of the
string. An earlier version of this hook added a `denyReason` field directly to
`hookSpecificOutput`; Codex rejected it as an unknown field, which discarded the _entire_ deny
payload and let the tool call proceed. Fixed in
[#191](https://github.com/mike-north/allw/issues/191) — see
[Fail-Open Residual](#fail-open-residual) for the full defect writeup.

The actor is distinct from the Claude Code hook: Codex requests use `actor.kind = "codex"` and
`actor.id = "codex:<hostname>"`, so a single allw inbox can distinguish "Claude Code on devbox-1"
from "Codex on devbox-1".

## Event Choice: `PreToolUse` vs `PermissionRequest`

Re-verified against the Codex docs on **2026-08-23** (issue
[#179](https://github.com/mike-north/allw/issues/179)). The 2026-06-12 check predated Codex's
`PermissionRequest` hook event and the granular `approval_policy`, so the justification for
`PreToolUse` had to be re-derived rather than re-asserted.

### What `PermissionRequest` actually is

| Property                       | Verified behavior                                                                                                                                                               |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| When it runs                   | "Runs when Codex is about to ask for approval, such as a shell escalation or managed-network approval… **It doesn't run for commands that don't need approval.**"               |
| `matcher`                      | Matches `tool_name` and aliases — `Bash`, `apply_patch` (also `Edit` / `Write`), and `mcp__<server>__<tool>`. Same vocabulary as `PreToolUse`.                                  |
| Output shape                   | `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"allow"\|"deny","message":"…"}}}`. `exit 2` + a stderr reason is an equivalent deny channel. |
| Folding across hooks           | Any `deny` wins; otherwise an `allow` lets the request proceed **without surfacing the approval prompt**.                                                                       |
| No decision                    | "If no matching hook decides, Codex uses the normal approval flow." A crashed, killed, timed-out, or malformed handler produces no decision and therefore falls into this case. |
| Reserved fields                | `updatedInput`, `updatedPermissions`, and `interrupt` are reserved and **fail closed** today.                                                                                   |
| Position in the approval chain | Runs in the approval path **before** the auto-review reviewer agent or the user approval UI is shown.                                                                           |

The last two rows come from the open-source implementation
([`codex-rs/hooks/src/events/permission_request.rs`](https://github.com/openai/codex/blob/main/codex-rs/hooks/src/events/permission_request.rs)
and the generated `permission-request.command.output` schema) as a cross-check on the docs page,
which is the release-behavior reference.

### The options

| Option                                  | Coverage                                                                                               | Behavior when the handler dies                                                   | Verdict                                                     |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| **(a) `PreToolUse` only** _(current)_   | Every matched tool call, independent of `approval_policy`, `sandbox_mode`, `permission_mode`, `.rules` | Hook error → **the tool call proceeds**                                          | **Chosen**                                                  |
| **(b) `PermissionRequest` only**        | Only actions Codex already decided to ask about — a function of the user's local config                | No decision → Codex's own approval flow (local prompt, or the auto-review agent) | Rejected: coverage is not ours to guarantee                 |
| **(c) Dual-home, `allow` on both**      | Union of (a) and (b)                                                                                   | Mixed                                                                            | Rejected: a `PermissionRequest` `allow` widens, see below   |
| **(c′) Dual-home, deny-only companion** | Union of (a) and (b), tightening-only                                                                  | No decision → Codex's own approval flow                                          | Deferred: no enforcement value today, real correlation cost |

### Decision: stay on `PreToolUse` only

**Coverage is the load-bearing property, and only `PreToolUse` has coverage allw controls.**
`PermissionRequest` fires only when Codex was already going to ask. Under the default
`workspace-write` sandbox most commands run inside the sandbox with no approval step at all, and
under `approval_policy = "never"` there are no approval prompts to hook. A gate whose reach shrinks
silently when the user edits `config.toml` is not an approval primitive — it is a suggestion. This
is the same conclusion the 2026-06-12 check reached, but it now rests on the current docs rather
than on an event that has since changed shape.

**`PermissionRequest`'s failure semantics really are better, and that still does not win.** This is
the one place where the older doc understated the alternative: a dead `PreToolUse` handler lets the
tool run unattended, whereas a dead `PermissionRequest` handler falls back to Codex's _normal
approval flow_ — a local prompt (or the auto-review agent), never silent execution. Moving events
would trade a smaller residual for a coverage hole whose size is set by someone else's config. We
take the residual and shrink it by other means (see [Fail-Open Residual](#fail-open-residual)).

**Emitting `allow` on `PermissionRequest` would violate the contract.** A `PermissionRequest`
`allow` "lets the request proceed without surfacing the approval prompt" — it _removes_ a gate that
would otherwise have run. `docs/contract.md` §6 is explicit that the primitive never returns
"allow" and that a verdict may only **tighten**. Using an allw approval to suppress Codex's own
approval prompt is a widening, and it is disallowed regardless of how convenient the
double-prompt cleanup would be. If allw is ever dual-homed, the `PermissionRequest` handler may
emit `deny` and nothing else.

**A deny-only companion is permitted but currently pointless.** Anything that reaches
`PermissionRequest` as a tool call has already passed (or will pass) the `PreToolUse` gate, so a
deny-only handler adds no enforcement. The categories `PreToolUse` cannot see — MCP elicitations,
`request_permissions` grants, skill-script approvals — are better handled at the config layer,
where Codex already auto-rejects them (see the next section). Deny-only dual-homing is worth
revisiting only if Codex adds a _tool-call_ approval category that bypasses the `PreToolUse` path.

**Correlation cost, for the record.** `PermissionRequest` input carries `session_id`, `turn_id`,
`tool_name`, and `tool_input` — but **no `tool_use_id`** (`PreToolUse` has one). Any dual-homed
design would have to correlate the two events by hashing canonicalized `tool_input`, and would
need the two events' relative ordering. That ordering is not documented, but the source settles it:
`PreToolUse` fires first, before the tool's handler runs, and `PermissionRequest` fires later, at the approval point
inside the handler (`codex-rs/core/src/tools/approvals.rs`). Verified from codex-rs source at `openai/codex` main
`ac558e2` (read, not run); see [execpolicy `.rules`](#execpolicy-rules).

### Revisit this decision if

- `PermissionRequest` gains a "fires for every tool call" mode, or `approval_policy` gains a mode
  that guarantees every tool call raises an approval request.
- `PreToolUse`'s failure handling changes from "report and continue" to "report and block".
- Codex adds an approval category that runs tool-equivalent side effects without a `PreToolUse`
  event.

## Approval Policy, Auto-Review, and execpolicy `.rules`

Three Codex mechanisms sit near the allw gate. None of them can weaken it; two of them need
configuration to stay fail-closed.

### Granular `approval_policy`

`approval_policy` is now `untrusted | on-request | never | { granular = { … } }`. The older
`suggest` / `auto-edit` / `full-auto` vocabulary is no longer part of that enumeration
(`on-failure` is deprecated in favor of `on-request`, and `codex exec --full-auto` survives only as
a deprecated compatibility flag that prints a warning). The granular form takes five booleans — `sandbox_approval`, `rules`,
`mcp_elicitations`, `request_permissions`, `skill_approval` — and each means "prompts in this
category are **allowed to surface**." Setting one to `false` **auto-rejects** that category. The
granular policy is therefore fail-closed by construction and aligns with `docs/contract.md` §7.

Because `PreToolUse` sees tool calls and nothing else, three categories are structurally invisible
to the allw hook: MCP elicitations (server-initiated), `request_permissions` grants (permission
widening rather than a tool call), and skill-script approvals. The config layer, not a second hook,
is the right answer for those:

```toml
approvals_reviewer = "user"

[approval_policy.granular]
sandbox_approval = true      # a second gate after allw; it can only tighten
rules = true                 # execpolicy `prompt` rules stay interactive
mcp_elicitations = false     # invisible to the allw hook, so auto-reject
request_permissions = false  # permission widening the hook can't see, so auto-reject
skill_approval = false       # auto-reject
```

This is the same value as the one-line inline form
`approval_policy = { granular = { sandbox_approval = true, … } }`. It is written as a standard table because an
inline table spread over several lines is TOML 1.1 syntax, which a TOML 1.0 parser rejects.
`scripts/uat-codex.sh` writes exactly this block into the temporary project's `.codex/config.toml`
(#192), and `scripts/uat-codex.test.mjs` parses it and checks every key.

This posture governs the interactive `codex`. `codex exec` overrides it with `approval_policy = "never"` (unless
the reviewer is `auto_review`), which also rejects every prompt rather than surfacing it, so headless runs are
fail-closed too. Verified from codex-rs source at `openai/codex` main `ac558e2` (read, not run):
`codex-rs/exec/src/lib.rs`, the headless `ConfigOverrides`. In the same source, `false` for `request_permissions`
returns an empty grant without a prompt, for `mcp_elicitations` declines the elicitation, and for `rules` /
`sandbox_approval` turns the prompt into a rejection. For `skill_approval`, the source shows no runtime enforcement
beyond the prompt text, so its auto-reject is unconfirmed until the UAT.

### `approvals_reviewer = "auto_review"`

`approvals_reviewer` selects who reviews _Codex's own_ approval prompts: `user` (default) or
`auto_review`, a reviewer subagent. It **cannot** weaken the allw gate, because that gate is a
`PreToolUse` hook that runs whether or not Codex raises an approval request at all. When
auto-review is enabled it replaces the _second_, Codex-side gate with a model — and since every
gate is an `∧` term (`docs/contract.md` §6), a model that can only deny is a tightening.

One correction to an earlier assumption: `request_permissions` prompts are **not** exempt from
auto-review. The docs list them among what the reviewer evaluates; the only category that always
surfaces directly to the user is Computer Use app approval. This does not change the decision
above — under `PreToolUse` the allw gate is upstream of the reviewer either way — but it does mean
"a human always sees `request_permissions`" is not a property to rely on. Auto-rejecting that
category (above) is the property to rely on.

### execpolicy `.rules`

`.rules` files (Starlark `prefix_rule`) decide whether a command may run **outside the sandbox**,
with `decision` in `allow | prompt | forbidden` and most-restrictive-wins across matching rules.
Their interaction with the allw gate:

| `.rules` decision | Codex behavior                                | Effect on the allw gate                                                                       |
| ----------------- | --------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `allow`           | Runs outside the sandbox without prompting    | **No hole.** `PreToolUse` still fires for the tool call; the allw approval is still required. |
| `prompt`          | Codex prompts before each matching invocation | Redundant second gate — a **double prompt** (allw on the second device, then Codex locally).  |
| `forbidden`       | Blocked without prompting                     | Tightening: an allw-approved command can still be refused. Correct per `docs/contract.md` §6. |

The `allow` row is the reason this section exists. If allw had moved to `PermissionRequest`, a
`.rules` `allow` — including one Codex itself proposes during an escalation, or one the TUI writes
to `~/.codex/rules/default.rules` when the user picks "always allow" — would suppress the approval
request and therefore the allw gate with it. On `PreToolUse` that path is closed.

Double-prompting under `prompt` rules is a real UX cost and is the honest price of refusing to
emit `PermissionRequest` `allow`. `approval_policy.granular.rules = false` converts it into an
auto-reject instead, which is fail-closed but blunt.

**Ordering**, verified from codex-rs source at `openai/codex` main `ac558e2` (read, not run):

- `PreToolUse` runs **before** any Codex approval. `codex-rs/core/src/tools/registry.rs:dispatch_any_with_state`
  calls `apply_pre_tool_use` before the tool's handler, and the execpolicy / sandbox approval requirement is
  computed only inside that handler (`ToolOrchestrator::run` → `request_approval`).
- So under a `prompt` rule the allw approval comes first and Codex's prompt second. If allw denies, the handler never
  runs, so Codex never prompts.
- A `.rules` `allow` becomes "skip approval" inside the handler, after the hook has already run, so it can't skip
  the gate.
- A `forbidden` rule rejects in the same place, also after the hook. If allw denies first, allw's reason is the one
  Codex reports.
- Shell commands the user types with `!` are not model tool calls and get no `PreToolUse`.

The UAT checklist items 7–9 confirm this on a live build.

## Fail-Open Residual

Re-analyzed 2026-08-23 against the current surface. **The residual is larger than previously
documented** — not because the event choice changed, but because two of the hook's own output
paths turn out to land inside it.

### Structural residual (unchanged, inherent to `PreToolUse`)

Codex reports a failed, malformed, or timed-out command hook as a non-blocking error and continues
the tool call. So allw's fail-closed behavior depends on the hook process starting and returning an
explicit, well-formed `deny` before Codex's pinned 480 second hook timeout:

- Process never starts (missing `node`, bad path, unresolvable bin, `PATH` differences under the
  Codex launch environment).
- Process is killed externally (SIGKILL, OOM) before writing stdout.
- Codex's own hook timeout elapses. This is the timeout-ordering invariant from
  [#52](https://github.com/mike-north/allw/issues/52): `ALLW_TIMEOUT_MS` must stay below the pinned
  hook timeout so the SDK reaches a verified approval or explicit denial first.
- Hooks are disabled or never trusted: `[features] hooks = false`, a hook left un-trusted in
  `/hooks`, or an enterprise `allow_managed_hooks_only = true` that skips user and project hooks.
  A hook that isn't managed runs only while its stored `trusted_hash` matches its current config. So an
  **edited** allw hook (a new command path, matcher or timeout) is dropped silently, just like a new one, until it is
  re-approved. `codex exec` has no review step to grant trust. Only the explicit, off-by-default
  `--dangerously-bypass-hook-trust` flag runs such a hook, and it skips trust for every enabled hook
  ([Human-Run UAT Setup](#human-run-uat-setup)). A project's `.codex/hooks.json` also needs a trusted project, which that
  flag does not grant. Verified from codex-rs source at `openai/codex` main `ac558e2`:
  `codex-rs/hooks/src/engine/discovery.rs:hook_trust_status`. Mitigation is tracked in
  [#348](https://github.com/mike-north/allw/issues/348).
- The handler is misconfigured as `"async": true`. Background hooks "can't block, approve, rewrite,
  or otherwise control the operation that triggered them" — the gate silently becomes advisory.
  **Never set `async` on the allw handler.**

The CLI catch-all still converts internal throws into a `deny`, so in-process failures are covered.

### Implementation residual (fixed in #191)

1. **Every deny was dropped.** `hookSpecificOutput.denyReason` was not part of Codex's
   `PreToolUse` output contract, and Codex rejects unknown fields inside that object, so the whole
   payload failed to parse and the tool call continued. This was the single largest gap on this
   surface: the deny path was _inside_ the fail-open set rather than outside it. Fixed in
   [#191](https://github.com/mike-north/allw/issues/191) — the machine-readable category now rides
   as an `allw[<category>]: ` prefix on `permissionDecisionReason` instead of a separate field (see
   [Decision Mapping](#decision-mapping)).
2. **Deny without a reason degrades to fail-open.** `permissionDecision: "deny"` requires a
   non-empty `permissionDecisionReason`; an empty one is treated as an invalid decision, i.e. a
   hook error, i.e. proceed. Also fixed in [#191](https://github.com/mike-north/allw/issues/191):
   the `allw[<category>]: ` prefix means `permissionDecisionReason` can never be empty, even if the
   underlying detail string is.
3. **`allow` was not the right encoding of an approval.** A bare `permissionDecision: "allow"`
   without `updatedInput` is an unsupported decision that Codex reports as a hook failure (the
   tool then proceeds, which is the intended outcome, so this was noise rather than risk). Fixed in
   [#191](https://github.com/mike-north/allw/issues/191): the hook now encodes "allw did not block"
   as **empty stdout and exit 0** — which is also the encoding `docs/contract.md` §6 requires,
   since the primitive never returns "allow."

### Interactive exec sessions (`write_stdin`)

Unified exec can start a long-running interactive process (`exec_command`) and later write more input
into it (`write_stdin`). Only the start is gated: `write_stdin` emits **no** `PreToolUse`, because
Codex treats the initial exec, already gated as `Bash`, as covering the session
(`codex-rs/core/src/tools/handlers/unified_exec/write_stdin.rs`). So approving an interactive
command such as `bash`, `python` or `node` approves whatever the agent types into it afterwards,
with no further prompt. **Treat approving an interactive shell or REPL as approving everything that
runs inside it**, and deny it when you wouldn't approve that.

### What is _not_ residual

- `approvals_reviewer = "auto_review"` — a second, downstream gate; can only tighten.
- `.rules` `allow` — does not suppress `PreToolUse`.
- `approval_policy = "never"` / `granular` with categories set to `false` — auto-rejects; tightening.
- `permission_mode` — Codex reports the mode to the hook rather than skipping it. Verified from codex-rs source at `openai/codex` main `ac558e2` (read, not run):
  - `apply_pre_tool_use` has no approval-policy check, so no mode skips the hook.
  - `codex-rs/core/src/hook_runtime.rs:hook_permission_mode` only ever sends two values:
    - `bypassPermissions` for `approval_policy = never`, which includes `--dangerously-bypass-approvals-and-sandbox`
      / `--yolo`, `-a never` and every `codex exec` run;
    - `default` for everything else, including `granular` (`Granular(_)`, `OnRequest` and `UnlessTrusted`).
  - `acceptEdits`, `plan` and `dontAsk` are in the input schema but never sent.
  - So `--dangerously-bypass-approvals-and-sandbox` is not a hook residual. It removes Codex's own second gate, not
    allw's.
  - UAT checklist item 11 confirms this live.

## Codex Hook Constraints

This design depends on the OpenAI Codex hooks contract, re-checked on **2026-08-23** (previously
checked 2026-06-12):

- Hook commands receive one JSON object on stdin and may return JSON on stdout. Exit 0 with no
  output is a clean success.
- **Only `type: "command"` handlers execute.** `prompt` and `agent` handler types are parsed from
  config and skipped — so the allw handler must stay a command handler, and a `prompt`/`agent`
  handler is never a fallback.
- `PreToolUse` can intercept Bash / unified exec, `apply_patch` (aliases `Edit`, `Write`), MCP tool
  calls, and other local function tools. Hosted tools such as `WebSearch` do not use the local
  function-tool hook path. The docs describe tool hooks as "a useful guardrail, not a complete
  enforcement boundary."
- A failed, malformed, or timed-out hook invocation is a non-blocking error: Codex reports the hook
  problem and continues the tool call.
- `PreToolUse` output supports `permissionDecision` (`allow` with `updatedInput`, or `deny` with a
  non-empty `permissionDecisionReason`), `additionalContext`, and `systemMessage`. `ask`, legacy
  `decision: "approve"`, `continue`, `stopReason`, and `suppressOutput` are parsed but unsupported
  and are reported as hook failures. Unknown fields are rejected.
- Matching command hooks can run concurrently, and multiple hook sources all load; higher-precedence
  config layers do not replace lower-precedence hooks.
- Non-managed hooks must be reviewed and trusted with `/hooks` before Codex runs them. Trust is
  recorded against the hook definition's hash, so changing the `command` string re-arms review.
- Enterprise deployments can pin the handler as a **managed** hook from `requirements.toml`
  (with `[features].hooks = true`), which cannot be disabled from the user hook browser. That is
  the deployment shape for making the allw gate non-optional on a fleet.
- Hook `timeout` is in seconds and defaults to 600; allw pins 480 seconds so the SDK deadline wins
  before Codex can time the hook out.
- `async: true` makes a handler advisory — it cannot block. The allw handler must never set it.
- Oversized hook output is spilled to `<temp_dir>/hook_outputs/<session_id>/<uuid>.txt`, so hook
  output must never carry plaintext action data. allw's reason strings are categories and
  human-readable summaries, never the `ActionRecord` payload.
- `notify` fires only for `agent-turn-complete`; it never fires for approval requests. No part of
  this integration may be built on `notify`.

Sources (all re-checked 2026-08-23):

- Codex hooks: <https://learn.chatgpt.com/docs/hooks>
  (the former <https://developers.openai.com/codex/hooks> now redirects here).
- Configuration reference (`approval_policy`, `approvals_reviewer`, `notify`):
  <https://learn.chatgpt.com/docs/config-file/config-reference>
- Advanced configuration (`notify` events): <https://learn.chatgpt.com/docs/config-file/config-advanced>
- Agent approvals & security (granular policy, auto-review): <https://learn.chatgpt.com/docs/agent-approvals-security>
- Auto-review lifecycle: <https://learn.chatgpt.com/docs/sandboxing/auto-review>
- execpolicy rules: <https://learn.chatgpt.com/docs/agent-configuration/rules>
- Cross-checks against the open-source implementation: <https://github.com/openai/codex/tree/main/codex-rs/hooks>
  (the docs note that `main`-branch schemas may include fields absent from the current release, so
  the docs page is the release-behavior reference and the source is corroboration only).
