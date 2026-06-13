# allw — Policy Layer Seam

**Scope:** the _seam_ between the approval primitive and the (later) policy layer — the parts that are expensive
to retrofit and must be pinned in `allw-core` v1: the **record of an action**, the **decision interface**, the
**rule shape**, and the **audit fields**. The policy _engine_ is built later. **And a tiering discipline:** early
allw matches actions **syntactically**; the **semantic** (capability/meaning) tier is the deferred north star.

> This aligns to the **AgentRC / Arc Flow** model (capabilities, per-command schemas, the syntactic→semantic
> tiering). allw's policy layer _is_ Arc Flow; the human gate is the **`ask`** outcome of its permission model,
> sitting after `attestation → approval → permission`.

---

## Where the policy layer sits

For each agent action, _before_ the primitive is invoked:

```
evaluate(ActionRecord) ──▶  Allow    → execute, no human
                            Deny     → refuse
                            Escalate → allw.requestApproval(...)   (= the "ask" effect; one-shot human gate)
```

The primitive fires only on **Escalate**. Auto-allow inside the envelope reduces fatigue; the primitive stays
one-shot and scope-free.

---

## The three tiers (and where early allw lives)

The cost of policy is not in any one command — it's in classifying actions **generally and semantically**.
That generality is what made Flow expensive. So we tier it:

| Tier                                | What it matches                                                                                                                                                  | Needs                                                                | allw                                |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------------------------------- |
| **T1 — pure syntactic**             | command name, `command_pattern` globs, `args_any` (exact-token/glob), flags, env; MCP `server`/`tool`/`params`-as-strings                                        | nothing (no schema)                                                  | **v1 lives here**                   |
| **T2 — curated-command syntactic**  | precise positional / path / target matching for ~15–20 high-value dangerous commands (`rm`, `find`, `git`, `curl`, `chmod`, `dd`, `kubectl`, key MCP CRUD tools) | hand-written arg grammar for _that curated set only_                 | optional early stretch              |
| **T3 — full semantic / capability** | abstract capabilities (`delete`, `network`, …) + named fields/scope, generalized across hundreds of commands ("`rm` _means_ delete; arg1 _is a path_")           | per-command schema DB, capability inference, doc-extraction pipeline | **deferred north star (paid tier)** |

> **Why the line is here:** T1/T2 are mechanical. T3 is the syntax→meaning bridge — the classification product
> (man-page extraction, capability inference, version graphs) that made Flow hard. allw must ship without it.

**Business-model alignment:** **syntactic = free**, **semantic = paid** — the same Sync/Flow line. Syntactic
rules are a strict subset of semantic, so nothing written at T1/T2 breaks when T3 lands.

---

## The action record (what `allw-core` captures)

`allw-core` reduces every approvable action to an `ActionRecord` and embeds it in both the `ApprovalRequest`
context and the `AuditRecord`. **v1 populates the syntactic fields; the semantic fields are reserved (null) and
filled later by the T3 engine** — adding them must not break the wire format.

`actor` is not part of `ActionRecord`: it is carried at the `ApprovalRequest` / `AuditRecord` envelope level, and
policy evaluation receives `actor` plus `ActionRecord` as separate inputs (`PolicyRule.subject` matches the actor;
`PolicyRule.match` matches the action).

```
ActionRecord {
  record_schema_version: int

  surface: "command" | "mcp_tool_call" | "file_edit"
                                              // interception paradigm (more added as needed:
                                              //   agent_tool_call, delegated_fetch …)

  // --- syntactic substrate (v1, always present) ---
  syntactic: {
    // surface=command:
    bin?, argv?, flags?, positionals?, cwd?, host?, env_refs?
    // surface=mcp_tool_call:
    server?, tool?, params?                    // params as raw/structured values
    // surface=file_edit:
    operation?, paths?, diff_summary?, diff_hash?
                                                // target paths + compact WYSIWYS summary/hash
    raw?                                        // original form, for fallback + display
  }

  // --- semantic enrichment (T3, reserved; null in v1) ---
  capabilities?: CapabilityAction[]            // Arc Flow taxonomy: filesystem.*, network.*, process.*,
                                               //   arbitrary.execute, privilege.*, environment.*, git.* …
  scope?:        CapabilityScope               // path/pattern/url/domain/resource/resourceName/namespace …

  risk: "low" | "medium" | "high" | "critical" // v1: coarse heuristic; T3: capability-derived
}
```

### Forward-compat requirements on `allw-core` v1 (cheap now, painful later)

1. **Capture the syntactic substrate** (tokenized command / MCP call) for every action — the durable base all
   three tiers match against.
2. **Stamp `record_schema_version`.**
3. **Reserve the optional `capabilities` / `scope` fields** so the semantic tier layers on with no wire break.
4. **Reserve a `policy` block in `AuditRecord`:** `{ decision: allow|deny|escalate, rule_id?, tier, schema_version }`.
   v1 always writes `escalate`; the field exists so history is policy-analyzable later.

Do **not** build capability inference or a schema DB in v1. Just don't foreclose them.

---

## The rule shape

A `PolicyRule` is **as trusted as a verdict** — signed by a device key. v1 rules are **syntactic**; semantic
(capability) rules are a strict-superset upgrade.

```
PolicyRule {
  id
  account_id: string                           // account root that must certify the signing device
  subject:    ActorMatcher                    // actor.id == "machine:macbook" | any
  match:      Predicate                       // T1/T2: surface + bin/tool + glob/args/flag/param matchers
                                              // T3 (later): capability + named-field/scope matchers
  effect:     "allow" | "ask" | "deny"
  bounds?:    { ttl?, max_uses?, time_window? }
  provenance: "manual" | "from_approval"
  tier:       "syntactic" | "semantic"
  created_at, expires_at?
  sig:        device-key compact JWS over every unsigned field above
  device_cert?: account-root compact JWS       // chains device key -> account root
}
```

**Precedence within a policy:** `deny` > `ask` > `allow`. **No match ⇒ `ask` (Escalate).** Unknown is fail-safe.

An empty `match: {}` is invalid. A rule must constrain the action through at least one surface,
command, or MCP predicate field; otherwise it would become an accidental match-everything grant.
For command argument matching, `args_any_globs` runs only against structured `argv` / positional
tokens, never raw shell text. Patterns without `*` or `?` are exact token matches; explicit glob
patterns are still anchored to one structured token and cannot span whitespace or shell
metacharacter boundaries.

Policy rule verification mirrors verdict verification for key trust: the verifier takes an account-root public key,
verifies `device_cert`, requires the signed cert `account_id` to match the rule `account_id`, verifies the policy JWS
with the certified device key, and requires the policy JWS `kid` to match the certified `device_id`. A rule missing a
cert, signed by an uncertified key, bound to a different account, or carrying a confused `kid` fails closed.
Multi-account verifiers that already know the account namespace they intended to verify SHOULD also pass that
`expected_account_id`; a rule whose signed `account_id` does not match it fails closed before policy evaluation.

---

## The approval → rule bridge ("approve & don't ask again")

The fatigue-reducing affordance emits a **signed `PolicyRule`, not a scoped verdict** (the verdict stays
one-shot). The scope chooser's options derive from the action's **syntactic** form in v1:

| Choice                      | Generated `match` (v1, syntactic)                           | `effect` |
| --------------------------- | ----------------------------------------------------------- | -------- |
| Just this once              | (none — one-shot verdict only)                              | —        |
| This exact call             | `surface + bin/tool + exact argv/params`                    | allow    |
| This command/tool, any args | `surface + bin/tool`                                        | allow    |
| This tool with param P = V  | `mcp + tool + params.P == V` (e.g. `list == "Agent Inbox"`) | allow    |
| Glob over a path-ish arg    | `args_any.match: "<glob>"`                                  | allow    |

(Once T3 exists, the chooser can also offer capability/scope-level rules — "any delete under this folder.")

---

## Composition & monotonicity

- **Within one user's policy:** matching rules combine by precedence (`deny` > `ask` > `allow`); no match ⇒ ask.
- **Across gates (a chain):** effective = **intersection** — a downstream gate can only further restrict.
  `allw` contributes `human_decision ∧ verified`; a corporate gate's policy intersects.
- **Widening your own envelope is not "loosening."** An `allow` rule is the user's deliberate grant; the
  most-restrictive-wins property governs _cross-gate_ composition, not a user's own policy.

---

## Network egress & the credential perimeter (why `http_request` is dropped)

Raw network egress (`curl`, `wget`, `node -e "fetch(...)"`, the agent's own web-fetch tools) is **deliberately
not an early surface or capability** — because gating egress is the wrong defense. The governing axiom:

> **Assume any value an agent can _read_ can be exfiltrated.** You cannot reliably block every egress path. The
> only durable defense is to keep sensitive values **out of the agent's read-set** — which is what **vaultkeeper**
> does: the agent _uses_ a secret via last-moment delegated injection, but never _reads_ one.

Consequences:

1. Raw http **collapses into `network.egress`** (a T3 capability), not a distinct kind.
2. **"Exfil a secret" is removed at the source, not policed at egress.** With vaultkeeper there is no readable
   `secret.txt` / `.env` for the agent to read and then POST anywhere. This is vaultkeeper's reason for existing —
   and what makes "lock the agent out of secrets" **non-Faustian**: the agent keeps its usefulness (it can still
   _use_ credentials) without holding exfiltratable ones.
3. **Ambient credentials** the agent can read (`~/.aws/credentials`, env vars, repo tokens) are not a vaultkeeper
   _gap_ — they're an **incomplete migration**. The fix is clear-cut: move them into vaultkeeper; until then,
   treat them as already compromised.

**Where credentialed-network approval lives:** not "parse curl args," but **gating the `delegated_fetch`
invocation** — the structured chokepoint (which credential, which host/path) vaultkeeper exposes. If allw gates
"network," it gates `delegated_fetch`.

**The one genuine residual** (neither vaultkeeper's nor allw's job): **non-secret sensitive data the agent must
read to do its work** — source code, PII in a database it queries, the file it's editing. You can't
delegate-inject "the content it needs to see," so if the agent reads it and has egress, it can leak it. That's
inherent DLP for agent working-material — handled by sandboxing / egress controls / not pointing agents at the
crown jewels, not by a credential vault or an approval gate.

---

## Explicitly out of scope (deferred)

- **The entire semantic / T3 engine:** capability inference, per-command schema DB, the doc-extraction &
  classification pipeline, capability-based rules, named-field/typed/scope matchers. (Reuse Arc Flow when we get
  there — do not rebuild it.)
- The **suggestion loop** ("approved 20× → propose a rule") — needs the audit data the v1 fields accumulate.
- Rule **storage/sync** and management UI; conflict resolution beyond precedence; org-distributed policy.

## Open questions

- **T2 curated set:** which ~15–20 commands + MCP tools earn hand-written arg grammar first.
- **Rule residence & sync:** device-local first, or E2EE-synced via the relay from day one.
- **Where T3 plugs in:** confirm allw reuses Arc Flow's capability model + schema DB wholesale (read
  `permission-model`, `policy-evaluation-v2` [privacy-preserving client-side eval — fits E2EE], `danger.ts`,
  `attestation-model` before building the semantic tier).
- **Instance identity stability** for param/scope matching: stable id vs human-readable label.
