# allw — Positioning

**One inbox for every agent approval, across every machine.**

> Clawvisor asks for permission. **allw helps you author the boundary** — and gets you to real agent
> autonomy without re-configuring every time you add a tool.

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

## Why it's different: you converge on autonomy, you don't configure it

Every approval tool is really trying to get you to the same place: **a richly-articulated permission boundary
inside which an agent can operate autonomously.** The hard part is getting there _without an overwhelming setup
process every time you add a new tool._

Two ways to fail:

- **Crude but easy** — per-tool allow/deny/ask. Trivial to set up, but you never reach a nuanced boundary.
- **Nuanced but overwhelming** — define every permission up front. You can reach nuance, but the setup is
  crushing, and you pay it again every time a new tool shows up. With MCP, new tools show up constantly.

**allw threads the needle.** A new tool starts at a safe, coarse default. The boundary then **widens from your
real decisions** — the system notices the patterns ("you've approved this 20 times, always yes") and offers to
let the agent do it autonomously. Over time you converge on a precise, personal boundary, and the system asks you
_less_. Marginal setup per new tool is effectively zero.

That convergence journey is the moat. A static gate that just forwards each permission request never gets you
there — and it never gets better the more you use it. allw does.

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

**Next:** a policy layer that sits in front of the primitive and holds your autonomy boundary — auto-allow inside
it, ask at its edge, deny beyond it — widened over time by your own decisions.

**Then:** governing your _local_ capabilities. Safely give a web agent access to your Reminders, Notes, Calendar,
or browser on a machine you own — you decide per item what's autonomous, what needs a tap, and what's forbidden;
enforced on your hardware, approved from your phone, with no all-powerful key ever issued.

---

## Who it's for

**Individual developers first** — anyone running coding agents or MCP tools who's tired of babysitting terminals
and wants one secure place to approve things. Free, end-to-end encrypted.

**Then their employers** — teams that have blocked agent desktop apps because they couldn't keep control. allw
gives them auditable, user-owned oversight that composes with their own gateways and can only ever make access
_more_ restrictive — so it's safe to drop in anywhere, and it installs without a native binary for Santa or MDM to block.

---

_The category, in one line: let agents be as autonomous as possible while keeping auditability and control._
