# @allw/approver

The **v0 stand-in approver** — the "second device" for the `allw` walking skeleton. A minimal Node
CLI that pairs with the relay, receives an encrypted `ApprovalContext` over the device presence
WebSocket, renders it **WYSIWYS**, and returns a correctly-signed `Verdict`.

All cryptography is delegated to the audited Rust core via WebAssembly — this package implements
**no** crypto or contract logic of its own (see [`docs/contract.md`](../../docs/contract.md),
[`docs/architecture.md`](../../docs/architecture.md)).

> ### ⚠ v0 stand-in: software-held keys
>
> This approver stores its signing/encryption **seeds in a local JSON keyfile** (software custody).
> That is a deliberate stand-in to unblock the first end-to-end proof. **Production custody is
> hardware-backed** — Secure Enclave / StrongBox with biometric-gated signing, where the key never
> serializes ([`docs/contract.md` §Identity & keys](../../docs/contract.md)). The hardware hero
> device is tracked by **[#23](https://github.com/mike-north/allw/issues/23)**. The wire protocol
> does **not** depend on key custody, so #23 swaps in later with **no protocol change**.

## Why WASM-under-node (a hard constraint, not a preference)

On-machine `allw` code runs as **WASM under `node`**, never a standalone native binary — so
enterprise binary-allowlisting (Google Santa) and MDM cannot block it
([`docs/architecture.md`](../../docs/architecture.md)). This package therefore avoids `napi`/native
deps; it loads the same vendored `--target web` `.wasm` the SDK does.

## Build

The approver runs the vendored WASM core, which must be built first from the repo root:

```sh
pnpm install
pnpm run build:wasm                 # builds packages/sdk/vendor/allw-wasm (the shared core)
pnpm --filter @allw/approver build  # compiles the CLI to dist/
```

## Usage

### 1. Pair with an account

```sh
allw-approver pair --relay https://relay.example.com --account <account-id> --label "my-laptop"
```

This generates a local keyfile (three software-held seeds + their public keys), obtains a pairing
code, registers the device **X25519** encryption key with the relay, mints a **device certificate**
(the account-root key signs the device signing key, so verifiers need only the account-root key),
and prints the **account-root public key** — the integrator's trust anchor
([#12](https://github.com/mike-north/allw/issues/12)).

> Pass `--code <code>` to redeem a code the account owner generated via `/pairing/start`. Omit it and
> the CLI drives both start + complete itself (fine for the v0 skeleton).

The keyfile defaults to `~/.allw/approver-keyfile.json` (override with `--keyfile <path>`) and is
written `0600` (owner read/write only).

### 2. Watch for requests and approve/deny

```sh
allw-approver watch          # alias: serve
```

For each incoming request the approver:

0. **refuses an expired request** before decrypting or prompting (device-side fail-closed expiry —
   see below),
1. **decrypts** the `context_ciphertext` with the device X25519 key (via the WASM core),
2. **recomputes** the WYSIWYS `request_hash` over the decrypted context + the envelope's
   `expires_at` — identical bytes to the integrator's pre-send hash,
3. **renders** the **complete** action substrate — the command/argv headline **plus** every other
   hash-bound field: a divergent reconstructed `argv` (when a benign `raw` would otherwise mask it),
   `flags`, `positionals`, `cwd`, `host`, `env_refs`, or MCP `params` when present — followed by the
   summary, actor, risk, reversibility, expiry, and `request_hash`,
4. prompts **Approve / Deny / Skip**,
5. **re-checks expiry** after the human decides and before signing (a prompt left open past the
   deadline emits nothing),
6. on a decision, **signs** the verdict (Ed25519, fresh ≥16-byte nonce, with the device cert) and
   sends `{ type: "verdict", request_id, verdict }` over the socket.

A `{ type: "retract" }` (another device resolved it) clears the pending prompt.

#### WYSIWYS render

The full meaning-changing substrate is shown — never elided behind a `raw` summary. The reconstructed
command (or MCP `server :: tool`) is the **`Action:` headline**; the remaining hash-bound fields —
`flags`, `positionals`, `cwd`, `host`, `env_refs`, MCP `server`/`tool`, and MCP `params` — each get
their own labeled line when present, so the headline alone is never the whole story. (`argv` is
normally the headline itself; it only also appears on a separate `Argv:` line when it **diverges**
from a `raw` headline — see below.)

```
────────────────────────────────────────────────────────────────────────
  APPROVAL REQUEST — review the EXACT action below before deciding
────────────────────────────────────────────────────────────────────────
  Request:    req-...
  Summary:    force push to main
  Action:     git push --force origin main
  Surface:    command
  Flags:      --force
  Positionals: origin main
  Cwd:        /home/me/project
  Env refs:   GIT_SSH_COMMAND
  Actor:      machine:laptop (claude-code)
              ✓ VERIFIED origin — claude-code · machine:laptop
  Risk:       high
  Reversible: no
  Expires:    2023-11-14T23:13:20.000Z
  request_hash (WYSIWYS): RfTZFQPM0Q8q6ve7iAhYWUYfNTPGof3GLDd104lyQto
────────────────────────────────────────────────────────────────────────
Approve / Deny / Skip? [a/d/s]
```

#### Anti-divergence: a benign `raw` can never hide a dangerous `argv`

`raw` is only **one** of the hash-bound substrate fields. A buggy or malicious integrator could send
a benign `raw` ("git status") alongside a divergent, dangerous `argv` (`git push --force …`) — both
covered by `request_hash`, but a `raw`-only headline would show the human only the benign string
while a downstream executor acts on `argv`. The device is the last line of defense against exactly
that field mismatch, so when the reconstructed `bin`/`argv` command **diverges** from `raw`, the
renderer surfaces the reconstructed form on a labeled `Argv:` line:

```
  Action:     git status
  Surface:    command
  Argv:       git push --force origin main      ← hash-bound argv, surfaced because it diverges from raw
```

The same hiding vector exists on the **MCP surface**: a benign `raw` ("echo hello") can co-exist with
a hash-bound `server`/`tool` (`fs :: delete_all_files`) and **no `params`**, so `server`/`tool` get
their own unconditional labeled line whenever present:

```
  Action:     echo hello
  Surface:    mcp_tool_call
  MCP:        fs :: delete_all_files            ← hash-bound server/tool, surfaced even behind a benign raw
```

This is **display-only** — it never changes the bytes bound into `request_hash`.

#### Verified request origin (Invariant #4)

The contract promises a **cryptographically-verified** requester origin (Invariant #4, actor-key
attestation — [#16](https://github.com/mike-north/allw/issues/16)). After decrypting and recomputing
`request_hash`, the approver verifies the `actor.attestation` carried in the `ApprovalContext`
against the actor's verifying key **resolved from root-signed account state**
(`docs/enrollment.md` §Account State) — **never** a relay-supplied `GET /:acct/actors` key. A
malicious or compromised relay can list its own key for an actor id, but it cannot author account
state, so it can never forge a verified origin. The attestation is an EdDSA compact JWS over
`(account_id, actor_id, actor_kind, request_id, request_hash)`, bound to **this exact request** (both
its id and WYSIWYS hash — not a reusable identity token).

- **Verified** → the attestation verified against the actor key that is `active` in the
  highest-sequence account-state document the configured account root signed. The actor line shows
  `✓ VERIFIED origin — {kind} · {id}`.
- **Stale account state** → `watch` persists the highest root-verified account-state sequence it
  has accepted in the keyfile and downgrades any later lower-sequence relay response to
  `⚠ UNVERIFIED`, even if the older document is still correctly root-signed.
- **Absent / not-root-anchored / revoked / wrong-key / spoofed / wrong-request / lifted** → the line
  is explicitly downgraded to `⚠ UNVERIFIED — <reason> (#16)`. A failed or absent attestation is
  **never** shown as verified (fail-closed display). When no root-signed account state is available
  (e.g. it has not yet been distributed to the device), the origin downgrades to unverified rather
  than aborting — the human still reviews the action, just without a trusted "who".

The integrator/hook side (the actor **signing** its attestation) and account-owner enrollment (which
authors the root-signed account state) are upstream of this package; this surface delivers the
device-side **verification + render**.

#### Device-side fail-closed expiry

The **device** (not just the relay) refuses a dead request: `prepareRequest` throws when
`expires_at <= now` before any decrypt/render, and the watch loop re-checks after the human decides
and before signing. A stale-but-signed approval can therefore never be produced, regardless of an
integrator's clock-skew window ([`docs/contract.md` §Invariants #6](../../docs/contract.md)).

## Fail-closed

The approver only ever emits a verdict the WASM core signed over the **real human decision**
([`docs/contract.md` §Invariants #6](../../docs/contract.md)):

- A request that fails to decrypt / parse is **skipped** — no verdict is sent, so the integrator's
  gate stays **closed** (deny-by-default). The human is not even prompted.
- A **Deny** or **Skip** never produces an "allow"; a denied verdict is a verified "no".
- A signing failure aborts that request rather than emitting a partial/forged verdict.

## Key custody (v0 stand-in)

| Seed                     | Curve   | Role                                                   |
| ------------------------ | ------- | ------------------------------------------------------ |
| `account_root_seed`      | Ed25519 | Account trust anchor; certifies device signing keys.   |
| `device_signing_seed`    | Ed25519 | Signs verdicts.                                        |
| `device_encryption_seed` | X25519  | Decrypts the `context_ciphertext` (JWE recipient key). |

All three are 32-byte seeds stored base64url in the keyfile — **software custody, v0 only**
(→ [#23](https://github.com/mike-north/allw/issues/23) for hardware custody).

## Tests

```sh
pnpm --filter @allw/approver test
```

Covers the full round-trip against the **real WASM core**: encrypt → decrypt → recompute matching
`request_hash` → sign → `verify_verdict` accepts (id + hash, no-swap); the `denied` path; and
fail-closed paths (malformed ciphertext, wrong-key ciphertext, missing cert). Relay pairing is
exercised against an in-Node HTTP stub of the relay's pairing surface.
