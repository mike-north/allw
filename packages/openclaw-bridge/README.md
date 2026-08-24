# `@allw/openclaw-bridge`

allw as a **native OpenClaw approval client**: a gateway operator client holding exactly
`operator.approvals` that turns each pending OpenClaw approval into a verified human decision from
the allw inbox, then resolves the approval.

The governing spec is [`docs/openclaw-integration.md`](../../docs/openclaw-integration.md). Read it
before changing behavior here — every rule below is a spec section, not a preference.

## What it is (and is not)

- It is a **separate `node` process**, not an in-gateway OpenClaw plugin. A plugin would put allw's
  relay device token and account trust anchor in the same address space as the runtime whose actions
  they gate (§2).
- It is a **reviewer surface, not an interception point**. OpenClaw's gateway remains the enforcement
  point; allw contributes a verified human decision to an approval OpenClaw had already decided to
  raise. **allw cannot gate an action OpenClaw never asks about** (§3).
- It runs the Rust core as **WASM under `node`** — no `napi`, no packaged native binary
  ([`docs/architecture.md`](../../docs/architecture.md) §Local execution, §10). It is a thin shell:
  hashing, JWE/JWS, verdict verification, and `ActionRecord` construction all live in
  `crates/allw-core`.

## Current scope

This package currently implements the **exec** approval family (`surface: "command"`) end to end.

Plugin permission requests (§5.2, the `agent_tool_call` surface) are **not** mapped yet: they are
logged and left for a surface that understands them, exactly like an unsupported kind, because
denying a family the bridge cannot render would make it a denial-of-service on that family.
`system-agent` approvals (§5.3) are out of scope for v1 by design and get the same treatment.

## Operator prerequisites

Without these the gateway either never prompts or resolves approvals without a human, and the bridge
is decorative (§3):

| Setting                                              | Required value           |
| ---------------------------------------------------- | ------------------------ |
| `tools.exec.mode`                                    | `ask` (**never `auto`**) |
| host approvals `ask`                                 | `always` (or `on-miss`)  |
| host approvals `askFallback`                         | `deny` (the default)     |
| `autoAllowSkills`                                    | `false`                  |
| `tools.exec.strictInlineEval`                        | `true`                   |
| `approvals.exec.enabled`, `approvals.plugin.enabled` | `false` (recommended)    |
| `channels.<channel>.execApprovals.enabled`           | `false` (recommended)    |

The last two matter because OpenClaw resolves approvals **first-answer-wins**: when the bridge is the
intended gate, disable competing approval surfaces or you have accepted a race whose worst case is a
denial.

## Configuration

All configuration is environment-driven. Anything missing or malformed is a **startup failure** — a
bridge that cannot gate must not appear to be gating.

| Variable                        | Required | Default   | Meaning                                                                                             |
| ------------------------------- | -------- | --------- | --------------------------------------------------------------------------------------------------- |
| `ALLW_OPENCLAW_GATEWAY_URL`     | yes      | —         | `ws://` / `wss://` URL of the gateway.                                                              |
| `ALLW_OPENCLAW_GATEWAY_ID`      | yes      | —         | Operator-configured label; the inbox actor is `openclaw:<gateway-id>`. `[a-z0-9][a-z0-9._-]{0,62}`. |
| `ALLW_RELAY_URL`                | yes      | —         | allw relay base URL.                                                                                |
| `ALLW_ACCOUNT_ID`               | yes      | —         | Approver relay account id.                                                                          |
| `ALLW_APPROVER_ROOT_KEY`        | yes      | —         | Account-root Ed25519 public key (base64url) — the verdict trust anchor.                             |
| `ALLW_OPENCLAW_BOOTSTRAP_TOKEN` | no       | —         | One-time bootstrap credential, used only until a device token is paired.                            |
| `ALLW_OPENCLAW_STATE_DIR`       | no       | `~/.allw` | Where the device key + paired device token live (`0600`).                                           |
| `ALLW_DEADLINE_MARGIN_MS`       | no       | `60000`   | Subtracted from OpenClaw's `expiresAtMs`. Must be ≥ 60 s and above the fetch timeout.               |
| `ALLW_OPENCLAW_MIN_TIMEOUT_MS`  | no       | `15000`   | Below this the bridge denies `insufficient-budget` instead of raising a doomed prompt.              |
| `ALLW_OPENCLAW_MAX_TIMEOUT_MS`  | no       | `420000`  | Cap; only ever _lowers_ the derived budget.                                                         |
| `ALLW_FETCH_TIMEOUT_MS`         | no       | `30000`   | Per-relay-fetch timeout. May only _lower_ the SDK default.                                          |

`<gateway-id>` is **asserted, not cryptographically verified** — the inbox presents it as an asserted
origin (§7.1).

## Pairing

```sh
allw-openclaw-bridge
```

The first run generates an Ed25519 device identity and fails with `PAIRING_REQUIRED`, logging the
request id. Approve it on the gateway host:

```sh
openclaw devices approve <requestId>
```

Re-run the bridge; the `hello-ok` device token is persisted to the state directory and used from then
on. Do **not** run the bridge on shared-secret auth beyond that bootstrap step, and do not hand-edit
`openclaw.json` to mint a token — pairing is the supported path (§4.2).

## Timeout budgeting

allw's deadline must fire strictly inside OpenClaw's, with margin left for the verdict to travel and
the resolve to land (§8):

```
budget_ms  = expiresAtMs − now_ms − ALLW_DEADLINE_MARGIN_MS
timeout_ms = min(budget_ms, ALLW_OPENCLAW_MAX_TIMEOUT_MS)
budget_ms < ALLW_OPENCLAW_MIN_TIMEOUT_MS  ⇒  resolve deny (insufficient-budget), raise nothing
```

`expiresAtMs` is the gateway's own value and the budget is computed in the gateway's clock epoch —
the bridge never assumes its clock agrees.

## Decision mapping

| allw outcome                                | OpenClaw decision |
| ------------------------------------------- | ----------------- |
| verified verdict, `decision === "approved"` | `allow-once`      |
| verified verdict, any other decision        | `deny`            |
| any unverifiable / malformed / errored path | `deny`            |

**`allow-always` is never submitted, under any circumstance** (§7.3). An allw verdict is one-shot and
scope-free by construction; OpenClaw's `allow-always` writes durable standing trust. Turning one into
the other would let a single human tap authorize an unbounded set of future, never-approved
executions. The only artifact allowed to widen standing autonomy is a signed `PolicyRule`
([`docs/policy-seam.md`](../../docs/policy-seam.md)), and that path is deliberately not built here.

If `allow-once` is not in the approval's `allowedDecisions`, an approved verdict cannot be faithfully
expressed: the bridge submits `deny` with reason `no-expressible-allow` and logs loudly.

## Fail-closed reason codes

Every path either resolves `deny` or deliberately leaves the approval for OpenClaw's own
`askFallback` — never `allow-once`, and never silence where the bridge could have denied (§9).

`no-approval`, `timeout`, `aborted`, `verify-error`, `binding-error`, `replay`, `challenge-error`,
`presentation-divergence`, `build-error`, `insufficient-budget`, `no-expressible-allow`,
`transport-error`, `config-error`.

Two conditions deliberately do **not** deny: an approval kind the bridge cannot render
(`unsupported-approval-kind`), and a lost connection with no channel to submit on. A connection lost
and **restored while the approval is still pending** is not a deny either — the bridge re-reads
`approval.get` and submits the verified decision normally. Failing closed means never inventing an
allow, not discarding a human decision that is still valid.

## Logging

Structured NDJSON on stderr, with a field allowlist that carries ids, reason codes, counts, and
timings only. Command text, cwd, argv, and the human-shown summary are never logged: the bridge sits
on the plaintext side of the E2EE boundary and a log line is not an encrypted channel.

## UAT

`scripts/uat-openclaw.sh` prepares the environment (relay, paired approver, a throwaway OpenClaw
config carrying the §3 prerequisites, a bridge wrapper) and prints the operator steps. It never
starts the gateway, and does not require one to be installed — automating a live agent runtime has
already proven unreliable, so the human drives OpenClaw.
