# DX report: blind run of the README quickstart

**Status: complete.** Base: `origin/main` @ `2e3d0f2`. Run on 2026-11-03 (all times UTC) in a Linux cloud
container with Node 22.23.4, pnpm 10.32.1, and Claude Code 2.1.317.

**Method.** I acted as a first-time developer and used only `README.md`, `docs/quickstart.md`, the docs those two
link, `--help` output and error messages. I did not read `crates/` or `packages/*/src`. The packages are not on npm
yet, so I used the workspace build (`pnpm install && pnpm run build:wasm && pnpm -r build`) where the docs say
`npm install`. I ran the relay locally with `wrangler dev` and used the CLI approver as the second party.

## Headline

| Milestone                                                          | Time     | Elapsed |
| ------------------------------------------------------------------ | -------- | ------- |
| Start (read README + quickstart)                                   | 06:26:21 | 0:00    |
| Workspace build finished                                           | 06:30:35 | 4:14    |
| Relay up, device paired, `watch` connected                         | 06:31:00 | ~4:40   |
| **First verified approval** (hook fed PreToolUse JSON on stdin)    | 06:31:38 | 5:17    |
| **First verified approval through real Claude Code** (`claude -p`) | 06:32:45 | 6:24    |
| Deny path through Claude Code confirmed (command blocked)          | 06:33    | ~7:00   |
| Plain-script path (`packages/sdk/README.md` example) approved      | 06:35:20 | 9:00    |

About 2 of those minutes went to a sandbox-only proxy problem (binaryen download, see F-ENV). Without it, a
developer who already has Rust installed reaches a first approval in about 4–5 minutes. That is good. **The core
loop works as documented once the CLIs actually exist.** It rendered the exact command (WYSIWYS), the approve and
deny decisions round-tripped, and the hook returned `allow` only for a verified "yes".

The friction is almost all in **getting the CLIs installed**. One finding is a **blocker with security impact:**
the hook command the quickstart recommends fails open today.

## Severity summary

| ID  | Severity    | One-line                                                                                                                      |
| --- | ----------- | ----------------------------------------------------------------------------------------------------------------------------- |
| F1  | **Blocker** | Following the docs verbatim (`npm install` + `"command": "npx allw-hook"`) **fails open**: Claude Code runs the gated command |
| F2  | **Blocker** | `npm install @allw/hook @allw/approver` "succeeds" but installs empty name-reservation stubs; no docs path for source users   |
| F3  | Major       | The source path needs Rust 1.99.1 + `wasm32-unknown-unknown` + `wasm-pack`, but the docs say "No Rust toolchain needed"       |
| F4  | Major       | With a wrong-but-valid root key, the human sees and approves the request, then the hook reports `verdict: denied`             |
| F5  | Major       | Relay unreachable is reported as `verdict: expired`, instantly, with no mention of the relay                                  |
| F6  | Major       | Step 4's `ALLW_ACCOUNT_ID="my-account"` contradicts step 2 (the id is derived); the resulting error doesn't name the env var  |
| F7  | Major       | Troubleshooting row "`git status` runs without prompting" gives a wrong cause (`git status` _is_ Bash)                        |
| F8  | Minor       | Docs contradict each other on whether the web approver has shipped                                                            |
| F9  | Minor       | `pair` output isn't copy-pasteable and uses different names than the env vars; it shows internal issue refs                   |
| F10 | Minor       | "vendored wasm not found" troubleshooting fix is wrong for source/workspace users                                             |
| F11 | Minor       | Node ≥ 24 is stated as a hard requirement, but everything ran on Node 22 (engine warnings only)                               |
| F12 | Minor       | `allw-hook --help` prints a deny-decision JSON instead of help                                                                |
| F13 | Minor       | Invalid root key error names an internal field (`account_root_pubkey_b64`), not `ALLW_APPROVER_ROOT_KEY`                      |
| F14 | Minor       | The plain-script path isn't linked from README/quickstart, and with a workspace build it only runs inside a package dir       |
| F15 | Minor       | `pnpm install` on a fresh checkout prints a wall of "Failed to create bin" warnings                                           |

## Timeline (every step)

| Time     | Step                                                                                       | Result / notes                                                                                                                                                                            |
| -------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 06:26:21 | Read README → docs/quickstart.md                                                           | README defaults to the hosted relay; the brief says local, so I took quickstart §0 "Local relay"                                                                                          |
| 06:26:30 | Check prerequisites                                                                        | Node 22.23.4 on the box; docs require ≥ 24. I continued to see whether it matters (F11)                                                                                                   |
| 06:26:45 | `npm install @allw/hook @allw/approver` in a fresh dir (README step 1)                     | "added 2 packages", exit 0. These are `0.0.0-bootstrap.0` stubs (930 B, no `bin`). **F2**                                                                                                 |
| 06:26:45 | `npx allw-hook --version` (quickstart §1)                                                  | The stub has no bin, so npx downloads the **unscoped** `allw-hook` stub, which throws "use @allw/hook instead (npm install @allw/hook)". I had just done that. Circular. **F2**           |
| 06:26:58 | Fallback: `pnpm install` in the repo                                                       | OK in 9s. Engine warnings on every package, plus "Failed to create bin … dist/cli.js" warnings. **F11, F15**                                                                              |
| 06:27:22 | `pnpm run build:wasm`                                                                      | `sh: 1: wasm-pack: not found`. Nothing in README/quickstart mentions wasm-pack. **Guess:** `npm i -g wasm-pack`. **F3**                                                                   |
| 06:27:47 | Installed wasm-pack 0.15.1; rustup auto-installed the pinned 1.99.1 + wasm32 target        | rustup was already on the box; a dev without it is blocked here                                                                                                                           |
| 06:29:43 | `build:wasm` retry                                                                         | Failed downloading binaryen from GitHub releases. Sandbox proxy, not a doc defect (**F-ENV**). The error did say what to do (`wasm-opt = false`). I installed `wasm-opt` manually instead |
| 06:30:06 | `build:wasm`                                                                               | OK                                                                                                                                                                                        |
| 06:30:35 | `pnpm -r build`                                                                            | OK in 26s                                                                                                                                                                                 |
| 06:30:40 | `node packages/{hook,approver}/dist/cli.js --version`                                      | Both `0.1.0`. **Guess:** with no npm package, `npx allw-hook` isn't available outside the workspace, so I ran `dist/cli.js` directly. `allw-hook --help` printed a deny JSON (**F12**)    |
| 06:30:42 | `pnpm --filter @allw/relay dev` (quickstart §0)                                            | `Ready on http://localhost:8787` in about 5s. Smooth                                                                                                                                      |
| 06:30:51 | `allw-approver pair --relay http://127.0.0.1:8787 --label my-laptop` (§2)                  | Paired in 1s. Printed account id, root pubkey, device id, keyfile. **F9**                                                                                                                 |
| 06:31:00 | `allw-approver watch` (§3)                                                                 | "Connected. Waiting for approval requests". Smooth                                                                                                                                        |
| 06:31:23 | Hook with the doc's literal `ALLW_ACCOUNT_ID=my-account` (§4)                              | Deny: `approver account 'my-account' has no enrolled devices to encrypt to`. Fails closed (good), but gives no hint to use the id from `pair`. **F6**                                     |
| 06:31:34 | Hook with the real id; PreToolUse JSON for `git status` on stdin                           | Watch rendered the full request card: action, cwd, `UNVERIFIED` actor, expiry, request_hash                                                                                               |
| 06:31:38 | Pressed `a` in watch                                                                       | Hook emitted `permissionDecision: "allow"`. **First verified approval: 5:17**                                                                                                             |
| 06:31:49 | Real Claude Code, `.claude/settings.json` exactly as in §4 (`"command": "npx allw-hook"`)  | **The command ran with no approval** (canary file written). Debug log: `PreToolUse:Bash finished with status 1` (unscoped stub threw) → non-blocking error → tool ran. **F1**             |
| 06:32:38 | Real Claude Code, `"command": "node /home/user/allw/packages/hook/dist/cli.js"` + env vars | Request arrived in watch                                                                                                                                                                  |
| 06:32:45 | Pressed `a`                                                                                | Claude Code ran `git status` and reported "On branch master". **First verified approval via Claude Code: 6:24**                                                                           |
| 06:33:00 | Real Claude Code, `echo DENYME > canary.txt`, pressed `d`                                  | Claude Code: blocked, "not approved (verdict: denied)"; no canary file. Deny path works                                                                                                   |
| 06:33:19 | Negative checks (env unset, relay down, garbage key, wrong valid key)                      | Env unset: clear message. Relay down: **F5**. Garbage key: **F13**. Wrong valid key: **F4**                                                                                               |
| 06:35:09 | Plain script copied from `packages/sdk/README.md`                                          | From a scratch dir: `ERR_MODULE_NOT_FOUND` (expected with no npm package). Inside `examples/walking-skeleton/`: request rendered as `stripe refunds create --charge ch_1`                 |
| 06:35:20 | Pressed `a`                                                                                | `decision: approved`, exit 0. **F14**                                                                                                                                                     |

## Findings

### F1 — Blocker (security): the documented hook command fails open today

**What happened.** I wired `.claude/settings.json` exactly as quickstart §4 says (`"command": "npx allw-hook"`) in a
project where `npm install @allw/hook` had installed the stub. Claude Code then ran
`echo FAILOPEN-CANARY > canary.txt` and the file was written. Claude Code's debug log:

```
Hooks: PreToolUse:Bash [command hook] finished with status 1 (794ms)
Hook PreToolUse:Bash (PreToolUse) error: status code 1
stderr: … allw-hook is a name reservation, not an allw package. … use @allw/hook instead …
```

**Why.** `@allw/hook@0.0.0-bootstrap.0` has no `bin`, so `npx allw-hook` resolves the separate _unscoped_ npm package
`allw-hook`, a stub that throws. Exit 1 with no JSON is a **non-blocking error** in Claude Code, so the tool call
proceeds. `docs/claude-code-integration.md` already lists "hook never started / bad path" as a residual. But the
quickstart's own recommended command makes that residual the **default outcome** right now, with no warning. It
will happen again whenever a user's project lacks the package: wrong cwd, `PATH` doesn't include
`node_modules/.bin`, or a typo. Did the error tell me what to do? Only inside a debug log, and its advice
("install @allw/hook") was what I had already done.

**Proposed fix.**

1. **Docs, now:** change the recommended command to `npx --no-install allw-hook || exit 2`. (`--no-install` stops npx
   from fetching the unscoped package. `|| exit 2` makes "hook could not start or crashed" a _blocking_ exit, which
   Claude Code honors.) This is a wrapper in the user's config. It doesn't change the hook's own contract of
   "always deny-JSON on exit 0". Alternatively, recommend the absolute `node …/dist/cli.js` form first and add
   `|| exit 2` there as well. Apply the same treatment to `docs/codex-integration.md` if Codex has an equivalent.
2. Add a quickstart step "**verify the gate before trusting it**": run one command and **deny** it, and confirm it
   didn't run. That would have caught this immediately.
3. **Packaging:** make the unscoped `allw-hook` / `allw-approver` stubs exit 2 with the message on stderr, so even a
   mis-resolved `npx` blocks instead of failing open. Also consider giving the scoped `@allw/*` bootstrap stubs a
   `bin` that does the same.

### F2 — Blocker: `npm install` silently installs stubs, and the source path is undocumented

**What happened.** `npm install @allw/hook @allw/approver` exits 0 with no warning. `latest` points to
`0.0.0-bootstrap.0`, a 930-byte placeholder. The placeholder README says "Install a real release instead:
`npm install @allw/hook@latest`", which is the same stub. The `npx` failure then sends you round in a circle (see
timeline). README and quickstart never say the packages aren't published yet. The only source instructions are for
the _relay_ (§0, "the relay is not published to npm").

**Proposed fix.** Add a callout at the top of README "Quickstart" and quickstart §1: _"Pre-release: the `@allw/*`
packages are not on npm yet; build from source."_ Include a §1-alt with the exact commands:
`git clone … && pnpm install && pnpm run build:wasm && pnpm -r build`, then
`node <repo>/packages/approver/dist/cli.js …` and the absolute hook path. Remove the callout once a real release
ships. Fix the placeholder README text so it doesn't point at `@latest`, and make the stub fail loudly at install
(`preinstall` exit 1 with the message) rather than at run time.

### F3 — Major: source path needs Rust + wasm-pack, docs say no Rust needed

README and quickstart both say "**No Rust toolchain needed**". That is true for a future npm install, but false for
the only path that works today. `pnpm run build:wasm` failed with `sh: 1: wasm-pack: not found`. The error doesn't
say how to get it; I guessed `npm i -g wasm-pack`. The toolchain is pinned in `rust-toolchain.toml` (1.99.1 +
`wasm32-unknown-unknown`), so rustup handled that part automatically. A dev without rustup would be stuck.
wasm-pack then downloads binaryen from GitHub on first run.

**Fix.** In the source-path section (F2), list the prerequisites: rustup (the toolchain auto-installs from
`rust-toolchain.toml`), `wasm-pack` (`cargo install wasm-pack` or `npm i -g wasm-pack`), and network access to GitHub
releases for binaryen. Have `build:wasm` check for `wasm-pack` up front and print the install command.

### F4 — Major: wrong (valid) root key → human approves → hook says "denied"

With `ALLW_ACCOUNT_ID` correct and `ALLW_APPROVER_ROOT_KEY` set to a different valid 32-byte key, the request still
reached the device. The watch terminal showed it, I pressed `a`, the relay acked "resolved", and the hook emitted
`not approved (verdict: denied)`. Fail-closed held, which is correct. But:

- The message is **misleading**. The human approved; the real failure is that the verdict didn't chain to the
  configured trust anchor. A developer will debug the approver, not the env var.
- The account id is _derived from_ the root key (quickstart §2). So the hook could detect the mismatch **locally,
  before sending anything**: `ALLW_ACCOUNT_ID != derive(ALLW_APPROVER_ROOT_KEY)`.
- Question for maintainers (I can't check it blind): the request was encrypted and delivered to a device the hook
  couldn't anchor to its configured root. `docs/enrollment.md` describes the relay registry as the "online
  routing/encryption view", so this may be by design. Please confirm it matches `docs/threat-model.md`'s checklist
  item "Device keys chain to the configured account root before their verdicts/rules are trusted". That item covers
  _verdicts_, not recipients.

**Fix.** Add a pre-flight check in the core/SDK config path that the account id matches the root key, and fail
fast with "ALLW_ACCOUNT_ID does not match ALLW_APPROVER_ROOT_KEY (re-copy both from `allw-approver pair`)". Give
verification failures a distinct reason, such as `verdict could not be verified against ALLW_APPROVER_ROOT_KEY`,
instead of `denied`. Longer term, consider making `ALLW_ACCOUNT_ID` optional, since it can be derived.

### F5 — Major: relay unreachable is reported as "verdict: expired"

With `ALLW_RELAY_URL=http://127.0.0.1:9999` (nothing listening) the hook returned within the same second:
`allw: Run command: ls — not approved (verdict: expired)`. It fails closed, but "expired" sounds like a human
timeout. The troubleshooting row "Request times out immediately → check the relay" does exist, but only if you
think to map "expired" onto "times out".

**Fix.** Surface transport errors in the reason, e.g. `relay unreachable at http://127.0.0.1:9999 (ECONNREFUSED)`.
Update the troubleshooting row to quote the actual message text.

### F6 — Major: `ALLW_ACCOUNT_ID="my-account"` placeholder contradicts §2

§2 is emphatic that the account id is derived and you don't choose it. §4 then shows
`export ALLW_ACCOUNT_ID="my-account"`, which looks like a value you may choose. Pasting it gives
`approver account 'my-account' has no enrolled devices to encrypt to`. That doesn't mention `ALLW_ACCOUNT_ID` or
`pair`. A trailing slash on `ALLW_RELAY_URL` produced the same error, so the message also hides which input was
wrong.

**Fix.** Doc: use `"<ACCOUNT_ID_FROM_STEP_2>"`, matching the root-key placeholder. Error: append
`— check ALLW_ACCOUNT_ID matches the "account id" printed by allw-approver pair, and ALLW_RELAY_URL is the relay you paired against`.

### F7 — Major: troubleshooting row for "`git status` runs without prompting" gives the wrong cause

The row says "Only `Bash` and `mcp__*` are gated. Reads/edits/greps pass through by design." But `git status` _is_ a
Bash call, so per the docs it should prompt. The likely real causes are exactly the fail-open cases in F1: the hook
isn't registered, settings weren't loaded, or the hook process couldn't start or crashed (non-blocking error).

**Fix.** Rewrite the row: "Hook didn't run or couldn't start → Claude Code treats that as a non-blocking error and
**runs the command**. Run `claude --debug hooks` and look for `PreToolUse:Bash … status`. Use the `|| exit 2` wrapper
(F1)." Move the "reads/edits pass through" note to its own row ("`Read`/`Edit` don't prompt").

### F8 — Minor: does the web approver exist?

Quickstart §2 says "A hosted web approver is **live** at https://allw-web-approver.pages.dev". Three other places say
it hasn't shipped: the intro's "v0 stand-ins" ("The hosted web inbox is designed but not shipped"), the final
section "What's not in this quickstart (yet)" ("A phone/web approval surface … not shipped"), and the README
("CLI approver instead of a phone app"). I didn't try the URL, since the brief was the CLI approver.

**Fix.** Pick one story. If the web approver is live, update the stand-ins list and the closing section. If it's
an early preview, label it that way in §2.

### F9 — Minor: `pair` output vs. env var names

The output has two problems:

- **Labels don't match the env vars.** `pair` prints `account id:` and `account-root pubkey:`. The env vars are
  `ALLW_ACCOUNT_ID` and `ALLW_APPROVER_ROOT_KEY`. "Approver root key" and "account-root pubkey" read as two
  different things.
- **It's addressed to maintainers, not users.** The header reads "Configure integrators with (#12):", and the watch
  card shows "(#16)". Bare issue numbers mean nothing to a first-time user.

**Fix.** Have `pair` print ready-to-paste lines:

```
export ALLW_RELAY_URL="http://127.0.0.1:8787"
export ALLW_ACCOUNT_ID="1A_Z…"
export ALLW_APPROVER_ROOT_KEY="qI_v…"
```

Drop the bare `#NN` refs from user-facing output, or turn them into full URLs.

### F10 — Minor: "vendored wasm not found" fix is wrong for source users

The troubleshooting fix is "`npm install @allw/hook`". Today that installs a stub (F2). For a source checkout the
fix is `pnpm run build:wasm && pnpm -r build`. **Fix:** list both.

### F11 — Minor: Node ≥ 24 requirement vs. reality

Everything (pair, watch, hook, SDK script, relay) worked on Node 22.23.4. The only signs were `EBADENGINE` /
"Unsupported engine" warnings on every pnpm/npx command, which are noisy. Either Node 24 really is required for
some path I didn't hit, or the requirement is stricter than needed. **Fix:** say which feature needs 24, or relax
`engines` to the true minimum. If 24 is truly required, add a runtime check with a clear error instead of relying
on engine warnings.

### F12 — Minor: `allw-hook --help`

`allw-hook --version` works. `allw-hook --help` printed
`{"…permissionDecision":"deny","permissionDecisionReason":"allw: hook input was not valid JSON (fail-closed deny)"}`.
Fail-closed is correct for hook input, but a human typing `--help` deserves usage text. **Fix:** handle `--help`/`-h`
like `--version`: list the env vars, the stdin contract, and a link to the quickstart.

### F13 — Minor: invalid root key error leaks an internal name

`ALLW_APPROVER_ROOT_KEY=notakey` gave `account_root_pubkey_b64 is not valid base64url: Invalid last symbol 121, offset 6.`
**Fix:** name the env var: `ALLW_APPROVER_ROOT_KEY is not a valid base64url key (expected 43 chars from allw-approver pair)`.

### F14 — Minor: plain-script path is hidden and awkward from a workspace build

The brief allowed "a plain script or the Claude Code hook". Neither README nor quickstart mentions the script path.
I found it only in `packages/sdk/README.md` ("Gate a command from a script"). It's a good example: copy-pasteable,
fail-closed, and it worked first time. But with no npm package, `import "@allw/sdk"` resolves only from inside a
workspace package, so from a scratch dir you get `ERR_MODULE_NOT_FOUND`. I ran it from `examples/walking-skeleton/`.

**Fix.** Add a "Gate a command from your own script" step 5b to the quickstart that links the SDK README. In the F2
source-path section, say where to put the script (or how to `pnpm link` / use a `file:` dependency).

### F15 — Minor: `pnpm install` bin-link warnings on a fresh checkout

A fresh checkout prints repeated `WARN Failed to create bin at …/allw-hook. ENOENT … dist/cli.js` lines because
`dist/` isn't built yet. They're harmless but look like failures. **Fix:** say so in the source-path section ("bin
warnings before `pnpm -r build` are expected"), or add a `postinstall` note.

### F-ENV — not a doc defect

wasm-pack's binaryen download from GitHub failed through this sandbox's proxy, though `curl` to the same URL worked.
I worked around it by putting `wasm-opt` on `PATH`. A normal developer machine is unlikely to hit this. I mention it
only because it cost about 2 minutes of the elapsed time above.

## What worked well

- **The relay was trivial to run locally.** `pnpm --filter @allw/relay dev` → ready in ~5s, readable request log.
- **Pair and watch are fast and clear.** `allw-approver --help` is good: it covers commands, options and the
  software-keys caveat.
- **The approval card is excellent.** It shows the exact action, cwd, an `UNVERIFIED` actor badge, risk,
  reversibility, expiry and request_hash. WYSIWYS is visible to the human, not just claimed.
- **Fail-closed held on every hook-internal failure I tried:** env unset, wrong account, relay down, garbage key,
  wrong key, explicit deny. The only fail-open was outside the hook process (F1).
- **The SDK README script** is copy-pasteable and correct.

## Suggested order of fixes

1. F1: change the quickstart's hook command (`--no-install … || exit 2`) and add the "deny once to verify" step.
   Make the stubs exit 2.
2. F2/F3/F10/F15: add a "pre-release: build from source" section with the real prerequisites.
3. F4/F5/F6/F13: improve the error messages, and add the account-id ↔ root-key pre-flight check.
4. F7/F8: fix the doc contradictions.
5. F9/F11/F12/F14: polish.
