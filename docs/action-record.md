# allw — Action Record

An `ActionRecord` carries what the caller describes for one human decision. allw faithfully shows
those facts and returns a verified decision bound to them. It does not interpret command meaning,
rate danger, infer capabilities, or evaluate, hold or generate policy rules.

## The action record

The same record is embedded in the encrypted `ApprovalContext` and in the `AuditRecord`.
`actor` belongs to the surrounding context/receipt, not to the action.

```text
ActionRecord {
  record_schema_version: 3
  surface: "command" | "mcp_tool_call" | "agent_tool_call" | "file_edit"
  syntactic: {
    argv?, cwd?                         // caller-supplied command facts
    server?, tool?, params?              // tool identity and structured caller parameters
    operation?, paths?, diff_summary?, diff_hash? // file-edit substrate
    raw?                                // exact original text or caller description
  }
}
```

The wire member remains named `syntactic`; it contains caller facts, with no parsed or derived
fields. Optional fields are omitted when absent. All action fields stay inside JWE ciphertext.
The relay sees routing/lifecycle metadata and ciphertext only, never action data. Structure
metadata/privacy tiers remain unimplemented proposals held in #216; no replacement metadata
source is chosen here.

## Command capture

`action_from_command` records a nonblank line byte-for-byte as `raw`, alongside optional caller
`cwd`. It never infers argv or a program identity. The same builder accepts Bash, PowerShell and
other command languages: punctuation, unmatched quotes, assignments, comments, substitutions,
operators and newlines are opaque text. Only empty or Unicode-whitespace-only text is refused
(`CommandError::NoCommand`, WASM `kind: "no_command"`). The SDK maps that to `command_line_empty`.

`action_from_argv` records caller-supplied argv verbatim, with optional original `raw` and `cwd`.
Only a vector with zero elements is refused (`no_command`; SDK `argv_empty`). Empty words,
assignment-looking words and operator-looking words remain caller facts. Malformed JSON, wrong
field types, missing required fields and invalid owning-contract options still fail closed. A
builder failure must deny and must never silently bypass the human gate.

The SDK's `commandAction` and `commandActionFromLine` wrap these core builders; `commandRequest`
adds request context. A plain script uses the `command` surface exactly as an agent hook does.
Its default actor is `machine:<hostname>` / `script` and default cwd is `process.cwd()`; explicit
`cwd: null` leaves it unbound. The caller owns choosing the execution API/interpreter and ensuring
that the supplied facts describe exactly what it will execute. allw never executes the command.

CLI and web approvers quote supplied argv faithfully for display. They do not split raw text into
words or fill in missing command metadata. When both raw and argv are supplied, both are shown;
a warning appears whenever raw differs from the literal quoted argv display form. Formatting
alone may therefore warn. This conservative comparison makes no claim of semantic equivalence.
Display escaping, multi-line `raw_lines`, control/hidden-character warnings and padding defenses
remain in the display layer. The human receives no automated warning about dangerous behavior and
must read the full action. Native escaped/material-field display wiring remains deferred to #273
as an M7 blocker; native hidden-character acceptance is not established.

## Tool calls and file edits

For `mcp_tool_call`, `server` / `tool` identify the MCP function and `params` carries its parameters.
For `agent_tool_call`, `server` is the gating provider (for example an OpenClaw plugin), `tool` is
its operation, and parameters may be absent. Hooks may split the host's `mcp__server__tool` naming
convention; this reads host identity rather than interpreting an action.

On a tool surface, raw is caller description, not the tool identity. Approvers head the request
with `server :: tool`, quote each identity component unambiguously and label raw as description.
A hand-built tool record carrying argv shows it too, with a warning; in-repo tool builders omit
command argv. Command callers use the `command` surface.

File-edit builders retain operation, target paths, summary, full-edit hash and original edit text.
The command removal does not change the file-edit grammar or owning malformed-input boundaries.

## Verification and history

The full retained record, summary, actor identity, optional reversibility assertion, constraints,
chain and shown expiry are bound into the request hash ([contract.md](./contract.md)). Core serde
objects ignore unknown fields, including removed `bin`, `flags`, `positionals`, `host` and
`env_refs`; those fields are neither reserialized, displayed nor hashed. SDK command-builder output
validation instead requires the exact current core output shape. No compatibility shim is provided.

Schema 3 uses request hash domain `allw/request-hash/v4` and audit domain `allw/audit-record/v3`.
Legacy bytes remain readable as artifacts, visibly unverifiable under this format. They must not be
silently discarded or migrated into apparently verified receipts. Existing web pairing keeps its `allw:pairing:v1` storage key and identity. In-session local
receipts retain their original evidence across relay polling refreshes. A persistent receipt store
across browser reloads is not implemented; this removal does not add one.

## External policy responsibility

The caller decides when to ask and computes `allow = approved ∧ verified ∧ policy ∧ other_gates`.
A human verdict is one-shot and scope-free, and can only tighten the caller's boundary. Rule
composition, standing grants, capability inference and credential policy belong outside allw.
Network egress is not a separate allw interception surface: command callers describe their command,
and vaultkeeper owns keeping credentials out of an agent's read set.

Future policy-modification work would carry the external layer's options to the human and return
the human's modification signal. It is not built or reserved here; authentication of that choice
remains open until scheduled ([hitl-seam.md](./hitl-seam.md) §6).
