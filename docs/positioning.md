# allw — Positioning

**One inbox for every agent approval, across every machine.**

> allw brings an exact action to the human and returns a verified decision. The caller owns the boundary.

---

## The problem

Agents now act faster than you can watch them, in more places than you can watch at once.

- **You're babysitting terminals.** Sometimes the only way to approve an agent's next step is to be staring at
  the right window at the right moment.
- **Approvals are scattered.** Work is increasingly parallelized across machines — a coding agent here, a web
  agent there, a job on a server. There's no single place to say yes or no.
- **The permission models are too crude.** ChatGPT-on-the-web gives you allow / deny / ask _per tool_ — with no
  way to express _under what conditions_ something should be allowed. You can't say "manage this list, but ask
  before touching that one."
- **The keys are too broad.** To let an agent do real work, people hand it an API key that's only as granular as
  the SaaS behind it — far more access than the task needs.

So today you're forced to choose between **babysitting** and **over-trusting**. Both are bad.

---

## What allw is

**A human-in-the-loop approval primitive for agents.** When an agent is about to do something sensitive, allw
puts a clear, contextual **Approve / Deny** in front of the right human — on their phone or desktop — and returns
a verifiable decision.

- **One inbox, every machine, every agent.** Pair a machine or agent once; all its approval requests land in a
  single place you can answer from anywhere. Stop watching terminals.
- **Ambient, not just a ping.** Pending approvals show as a glanceable live status on phone, watch, and desktop —
  with an expiry countdown — so you can decide from the lock screen or your wrist, not by hunting for a window.
- **End-to-end encrypted.** The sensitive context — the command, the diff, the record being changed — is readable
  only by you. Nothing sits in plaintext on a relay. Corporate-safe by construction.
- **Runs where locked-down machines won't run a CLI.** The on-machine piece executes as WebAssembly inside tooling
  you already trust — no unapproved native binary for enterprise allowlisting (Santa) or MDM to block. With the
  encryption above, it's safe to adopt inside strict corporate environments.
- **Verifiable, auditable decisions.** Every approval is a signed artifact bound to exactly what you saw, with a
  tamper-evident audit trail. You can prove who approved what, and when.
- **Works with anything.** A Claude Code hook, an MCP tool call, a web agent reaching your local apps, a CI job —
  allw is a small primitive that drops into all of them. It's a dependency you embed, not a destination you adopt.

---

## Human decisions within the caller's boundary

allw gives callers one encrypted, auditable way to ask a human. The caller's external policy decides when to
ask and whether an action may run. allw never widens that boundary or learns standing grants from approvals.

When policy modification is scheduled, the external layer will offer adjustment options, allw will carry them
to the human, and allw will return the human's modification signal. The external layer owns applying it. This
feature is not built now.

---

## Why not just…

| Alternative                             | What it gives you                                                       | What's missing                                                                                                                    |
| --------------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Clawvisor**                           | Vault + approval + E2EE, as a gateway over ~14 cloud-service connectors | Passes the literal permission and stops — no boundary-expansion journey; can't govern your _local_ tools; single deployment shape |
| **DIY ntfy / Telegram hooks**           | A free "ping my phone, tap a button"                                    | No E2EE, no audit trail, no native app, no Windows, no path to a real permission boundary                                         |
| **Web-agent settings (ChatGPT/Claude)** | allow / deny / ask per tool                                             | No predicates, no instance-level control, no cross-agent or cross-machine view                                                    |
| **HumanLayer**                          | Approvals via Slack / email / SMS                                       | No native apps, no E2EE, and a steep jump from free to enterprise pricing                                                         |

---

## Where it starts, where it goes

**v1 (now):** the approval primitive — one inbox, end-to-end encrypted, verifiable one-shot decisions, paired to
your machines and agents. A complete product on day one for anyone running agents.

**Policy integration:** the policy layer is a separate project. Its only allw-facing role is to offer policy
adjustments to the human through an approval and receive the human's modification signal. This is future work,
not a policy evaluator, rule store, or rule generator in allw.

**macts:** a macts host owns policy and decides which confirm-first operations reach allw. Host and API-key
policy composition stays in macts; allw supplies the verified human decision.

---

## Who it's for

**Individual developers first** — anyone running coding agents or MCP tools who's tired of babysitting terminals
and wants one secure place to approve things. Free, end-to-end encrypted.

**Then their employers** — teams that have blocked agent desktop apps because they couldn't keep control. allw
gives them auditable, user-owned oversight that composes with their own gateways and can only ever make access
_more_ restrictive — so it's safe to drop in anywhere, and it installs without a native binary for Santa or MDM to block.

---

_The category, in one line: let agents be as autonomous as possible while keeping auditability and control._
