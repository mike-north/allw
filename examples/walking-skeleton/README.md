# allw walking skeleton — first end-to-end approval

The capstone for the **v0 walking skeleton** ([epic #42](https://github.com/mike-north/allw/issues/42)):
one real Claude Code action gets approved from a second surface, end-to-end over the zero-knowledge
relay — **fail-closed** and **cryptographically verified**. It proves the whole approval primitive
coheres by composing the existing surfaces (`@allw/sdk`, `@allw/approver`, `@allw/hook`, and the
`@allw/relay`), adding **no** crypto or contract logic of its own (all cryptography stays in the
audited Rust core, run as WASM under node — see [`docs/architecture.md`](../../docs/architecture.md)).

## The acceptance checklist (epic #42)

1. A Claude Code agent attempts a **destructive command** (`git push --force origin main`).
2. The hook **blocks**; a request appears on the second (approver) surface showing the **exact**
   command, actor, risk, and expiry (WYSIWYS).
3. **Approve** → the agent proceeds. **Deny** (or **timeout**) → the agent is blocked.
   _Fail-closed proven both ways._
4. The integrator **independently verifies** the signed verdict (`request_id` **and**
   `request_hash`, no-swap), and the relay never handled plaintext or a signing key (zero-knowledge).

Everything above is exercised automatically (see [Test layers](#test-layers)). The **one remaining
human step** is capturing the screen recording — see [Recording the demo](#recording-the-demo).

## Reproduce it (mostly one command)

From the repo root, build the workspace once, then run the live demo:

```sh
pnpm install
pnpm run build:wasm        # the shared Rust core, compiled to WASM
pnpm -r build              # build every surface (sdk → approver/hook → this example)

# Live end-to-end demo (boots a real `wrangler dev` relay, pairs a real approver, drives the real
# hook bin, auto-approves, and asserts the decision). Pick a mode:
pnpm --filter @allw/example-walking-skeleton demo:approve   # → hook emits allow
pnpm --filter @allw/example-walking-skeleton demo:deny      # → hook emits deny
pnpm --filter @allw/example-walking-skeleton demo:timeout   # → hook emits deny (fail-closed)
```

Each mode prints the WYSIWYS approval block (the exact command, actor, risk, expiry, and
`request_hash`) and then `✔ PASS — the live stack produced '<allow|deny>' as expected.` (exit 0).

What runs live, in order:

1. **Boot the relay** — `wrangler dev` for `@allw/relay` (the real zero-knowledge router, under
   workerd).
2. **Pair the approver** — the real `allw-approver pair` CLI generates software keys, registers the
   device X25519 key, mints a device certificate, and prints the **account-root pubkey** (the
   integrator's trust anchor). The keyfile is written to a throwaway temp dir.
3. **Export the hook env** — `ALLW_RELAY_URL` / `ALLW_ACCOUNT_ID` / `ALLW_APPROVER_ROOT_KEY` from
   that pairing.
4. **Start the approver watch loop** — the real `@allw/approver` `runWatch` over a live presence
   WebSocket, in an unattended auto-decision mode (approve / deny / never-answer).
5. **Drive the hook** — the real `@allw/hook` `bin` (`node packages/hook/dist/cli.js`) as a
   subprocess, fed the `PreToolUse` JSON for `git push --force origin main` on stdin; its decision is
   read from stdout.

> The auto-decision mode keeps the demo unattended and deterministic. The **interactive** approver
> (a human pressing Approve / Deny on the second surface) is the real `allw-approver watch` CLI —
> used for the recording below.

## How Approve / Deny / Timeout behave (fail-closed both ways)

The primitive **never returns a bare "allow"** — the integrator composes it
([`docs/contract.md` §Invariants #6](../../docs/contract.md)). The hook maps the **verified** verdict:

| Approver action             | Verdict the SDK resolves       | Hook decision |
| --------------------------- | ------------------------------ | ------------- |
| Approve                     | `approved` (verified)          | `allow`       |
| Deny                        | `denied` (verified human "no") | `deny`        |
| No response by the deadline | `expired` (timeout)            | `deny`        |
| Unverifiable / forged       | synthesized `denied`           | `deny`        |

Approve is the **only** path to `allow`, and only for a verdict that verifies against the approver's
account-root key. Deny and timeout both block.

## Observe the zero-knowledge property

The relay routes **ciphertext + signed verdicts only** — it never sees the plaintext
`ApprovalContext` (the command, summary, actor, …) or any signing key. Two ways to see it:

- **In the live demo logs**: the relay logs `POST /…/requests` and the verdict relay, but the
  human-shown command (`git push --force origin main`) never appears in them — it travels only inside
  the opaque `context_ciphertext` (a JWE) decrypted **on the approver device**.
- **In the automated tests**: the CI round-trip reaches into the relay's stored request/verdict and
  asserts the stored envelope contains the opaque ciphertext but **none** of the plaintext fields
  (`action`, `summary`, `actor`, `risk`, …) — mirroring `@allw/relay`'s own zero-knowledge test
  ([`packages/relay/test/relay-routing.test.ts`](../../packages/relay/test/relay-routing.test.ts)),
  which proves the same property against the **real** relay running under workerd.

## Test layers

Per [`manual-test-design`](https://github.com/mike-north), the suite is split by what can run where:

### CI-runnable — `test/e2e.test.mjs` (`pnpm --filter @allw/example-walking-skeleton test`)

A deterministic, all-real-crypto round-trip in one Node process (fixed clock, no real network):

> real `@allw/hook` `runHook` → real `@allw/sdk` `requestApproval` → in-process relay → real
> `@allw/approver` core (decrypt → recompute `request_hash` → `sign_verdict`) → SDK verifies → hook
> maps the verdict.

It proves, with **no verdict stubbing**:

- **approve → allow**, **deny → deny**, **timeout → deny** (fail-closed both ways);
- the integrator **independently re-verifies** the verdict (`request_id` + `request_hash`), and that
  it does **not** verify against a different (attacker) root key (no-swap);
- the relay stores **only** the opaque ciphertext envelope + signed verdict — never a plaintext
  context field, and never the command string.

**Boundary (a Decision, see below):** the only stand-in is the relay transport. The real relay runs
under **workerd** while the SDK/approver run under **node**, so a single-process `node --test` cannot
host both runtimes and dial real sockets between them. The CI test therefore drives the real
SDK/approver against an in-process relay that mirrors the relay's observable contract **and enforces
the same zero-knowledge envelope-key allowlist**. The genuinely-live workerd relay is exercised by
the local `demo:e2e` script below, and the relay's zero-knowledge property is independently proven by
`@allw/relay`'s own `workers-pool` suite.

### Locally-automatable (not CI) — `scripts/demo-e2e.mjs` (`pnpm run demo:e2e`)

The genuinely-live stack: real `wrangler dev` relay (workerd) + real `allw-approver` watch loop over
a live WebSocket + the real hook `bin` as a subprocess. It can't run in CI (needs `wrangler dev` and
several live processes), but it is fully unattended — a developer runs it and walks away; it
self-asserts pass/fail and exits non-zero on failure.

| Layer                      | What it proves                                                                               |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| relay under `wrangler dev` | the real zero-knowledge routing path runs under workerd, end to end                          |
| real hook `bin` subprocess | the Node + WASM entrypoint blocks the call and maps the verdict at the real process boundary |
| real approver watch loop   | decrypt → recompute WYSIWYS `request_hash` → sign, over a live socket                        |

### Human-verification — the screen recording (the one remaining manual step)

## Recording the demo

The recording is the single intrinsically-human step: a person watches the request appear on a second
surface and presses Approve / Deny, and the recording itself is the artifact. To capture it:

1. **Terminal A — boot the relay:**
   ```sh
   pnpm --filter @allw/relay dev          # wrangler dev; note the printed URL (e.g. http://localhost:8787)
   ```
2. **Terminal B — pair the approver (the "second device"):**
   ```sh
   node packages/approver/dist/cli.js pair \
     --relay http://localhost:8787 --account demo --label "my phone" \
     --keyfile /tmp/allw-demo-keyfile.json
   ```
   Copy the printed **account-root pubkey**.
3. **Terminal B — watch interactively** (this is the surface you record pressing a key on):
   ```sh
   node packages/approver/dist/cli.js watch --keyfile /tmp/allw-demo-keyfile.json
   ```
4. **Terminal C — drive a gated command through the hook** (using the pubkey from step 2):
   ```sh
   echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"},"cwd":"/workspace/project"}' \
   | ALLW_RELAY_URL=http://localhost:8787 ALLW_ACCOUNT_ID=demo \
     ALLW_APPROVER_ROOT_KEY=<account-root-pubkey> \
     node packages/hook/dist/cli.js
   ```
   The hook **blocks**. Switch to Terminal B: the WYSIWYS block shows the exact command — press `a`
   to approve or `d` to deny. The hook then prints `{"permissionDecision":"allow"}` (approve) or
   `"deny"` (deny). Let the prompt sit to demonstrate the **timeout** (set `ALLW_TIMEOUT_MS=4000` to
   keep it short).

> In a real Claude Code session the hook is wired via `.claude/settings.json` (matcher `Bash|mcp__.*`)
> and Claude Code itself supplies the stdin — see [`packages/hook/README.md`](../../packages/hook/README.md).
> Terminal C reproduces that stdin by hand so the recording does not depend on a live agent session.

## Decisions

- **CI relay is an in-process faithful double; the live relay is workerd.** Bridging node (SDK +
  approver) and workerd (relay) in one CI process is infeasible, so the CI e2e uses an in-process
  relay that mirrors the relay's observable contract and the zero-knowledge envelope-key allowlist,
  while `demo:e2e` runs the real `wrangler dev` relay and `@allw/relay`'s own suite proves
  zero-knowledge under workerd. This maximizes deterministic CI coverage without faking any crypto.
- **The approver auto-decision mode is additive.** It reuses the approver's exported `runWatch` with
  an auto-answering `Prompter` ([`src/lib/live-approver.ts`](./src/lib/live-approver.ts)); the
  interactive CLI is unchanged. The harness for the CI test likewise composes the approver's exported
  `prepareRequest` / `signDecision` — no approver behavior is modified.
- **`PAIRING_TTL_MS` moved out of the relay entrypoint.** `wrangler dev` (workerd) validates every
  named export of the worker entrypoint as a handler/DO class, so a bare numeric export made it
  refuse to boot. The constant moved to `packages/relay/src/constants.ts` (imported by the worker and
  its tests) — no relay behavior changed.

## What this is not

This is the v0 walking skeleton — the thinnest path that crosses every seam. It is **not** the full
product: push (polling only here), hardware key custody, the policy/T1 matcher, cross-device fan-out,
and actor-key attestation (the rendered actor line is explicitly `UNVERIFIED` in v0, [#16]) are all
deferred. See [epic #42](https://github.com/mike-north/allw/issues/42) for the full IN/OUT scope.

[#16]: https://github.com/mike-north/allw/issues/16
