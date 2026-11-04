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
allw-approver pair --relay https://relay.example.com --label "my-laptop"
```

This generates a local keyfile (three software-held seeds + their public keys), derives the
**account id** from the account-root public key, obtains a pairing code with a root-signed
`pairing/start`, registers the device **X25519** encryption key with the relay, mints a **device
certificate** (the account-root key signs the device signing key, so verifiers need only the
account-root key), publishes a root-signed **account state** that names this device, and prints the
**account id** and **account-root public key** — what an integrator is configured with
([#12](https://github.com/mike-north/allw/issues/12)). Integrators encrypt requests only to devices
that account state lists (#243), so a device is unreachable until a state naming it is published.
The core composes that state (`next_account_state`, #379): it carries the existing devices forward at
the next sequence, keeps one entry per key pair (a re-pair replaces this keyfile's entry under its
old device id, #378), and refuses to publish when the relay's account states don't verify, disagree,
or are older than the keyfile has seen.

The account id is self-certifying (`docs/enrollment.md` §Self-Certifying Account Id): it is
`base64url(SHA-256("allw/account-id/v1" || 0x00 || account_root_pubkey))`, so only the root holder
can add devices to it. `--account <id>` is optional; when given it must equal the derived id or
`pair` fails before contacting the relay.

The relay URL must be `https://`. Plain `http://` is accepted only for a local relay on `localhost`
or `127.0.0.1` (not `[::1]`), and the URL may not carry a username, password, query or fragment.
Every relay request carries pairing material or the device's bearer token, so a plaintext or
malformed URL is refused before the keyfile or the relay is touched, with a non-zero exit
([#267](https://github.com/mike-north/allw/issues/267)). The rule is the SDK's and the web
approver's, and `watch` applies it too, to `--relay` or else the keyfile's stored `relay_url`. An
accepted URL is used and stored in canonical form (lower-case scheme and host, no default port, no
trailing `/`), so `pair --relay HTTPS://Relay.Example.COM/` stores `https://relay.example.com`.
Library callers of the exported request builders (`pairingStart`, `deviceConnectWsUrl`, …) apply
the exported `assertCliRelayUrl` first and use the URL it returns.

> Pass `--code <code>` to redeem a code the account owner (root holder) generated via a root-signed `/pairing/start`. Omit it and
> the CLI drives both start + complete itself (fine for the v0 skeleton).

The keyfile defaults to `~/.allw/approver-keyfile.json` (override with `--keyfile <path>`) and is
written `0600` (owner read/write only).

#### Upgrading an existing pairing

If you paired before root-vouched recipients shipped (#243), the relay holds no account state for
your account, so integrators deny every gated call with "the relay has no account state … run
allw-approver pair". Upgrade the pairing once:

1. Make sure your relay runs current `main`. A relay that answers `GET /<account>/account-states`
   with 401 is too old: integrators deny with "this relay is too old … redeploy it", and `pair` fails
   the same way. Redeploy it ([`relay-deploy.md`](../../docs/relay-deploy.md)).
2. Re-run `pair` with the **same keyfile** (and the same `--relay`):

   ```sh
   npx --no-install allw-approver pair --relay <RELAY_URL> --keyfile <your keyfile>
   ```

   It keeps your seeds and account, registers a new device id, mints a new device certificate and
   token, and publishes an account state naming that device ("Published account state —
   sequence N"). The account id and account-root public key are unchanged, so integrator config
   needs no edit. The state lists your keys once, under the new id: an entry with the same keys
   under an older id is dropped (#378), so the old device id can no longer read requests.

3. **Web approver:** open it, press **Use another device**, and paste the keyfile's values again.
   `device_id`, `device_cert` and `device_auth_token` changed. The seeds did not. This step is
   required: requests are encrypted to the device id the account state names, so a browser still
   holding the old device id cannot read them. Repeat it after every later re-pair. A running
   `allw-approver watch` picks the new values up from the keyfile on restart.

4. **iPhone approver, or a web approver with keys of its own** (not set up from this keyfile):
   re-pairing does not list it. Vouch for it once with the values it shows
   (`allw-approver vouch`, interim until #199; see [§Vouch for a device with its own keys](#vouch-for-a-device-with-its-own-keys)).
   Vouching lets it decrypt requests only: its approvals are denied until it holds a device
   certificate from this account root, which `vouch` does not issue (#199). Never vouch for a web
   approver set up from this keyfile; paste the new values into it (step 3).

#### Vouch for a device with its own keys

> **Interim until [#199](https://github.com/mike-north/allw/issues/199)**, the cross-device
> enrollment ceremony, which replaces this command.

Integrators encrypt each request only to devices the root-signed account state lists. `pair` lists
this keyfile's own device. A device with **keys of its own** (the iPhone approver, or a web
approver whose seeds did not come from this keyfile) has to be vouched for by the account-root
holder, from the paired keyfile:

```sh
allw-approver vouch --device-id <id> --encryption-pubkey <b64url> --signing-pubkey <b64url>
```

Copy the three values from the device's own screen (the web approver's "This device's keys"
panel). A web approver set up by pasting this keyfile's values is this keyfile's device and needs
no vouch.

`vouch` refuses, with a non-zero exit and nothing signed, when:

- stdin and stdout are not both a terminal (there is no `--yes`: a device is never vouched for
  unseen);
- the id or a key is malformed: not canonical base64url of 32 bytes, a small-order X25519 key, or an
  Ed25519 key that is not a valid point;
- the relay has no device with that id for this account, or registered it with a different
  encryption key;
- the relay's account states don't verify, disagree, or are older than the keyfile has seen, or the
  id is revoked or already listed with other keys (a key change is a rotation, #199's job);
- the device carries **this keyfile's own keys**, so the new state would replace this keyfile's
  device (a web approver set up from the keyfile, still on a device id from before a re-pair). Use
  `pair` for this device and paste the keyfile's current values into that browser;
- you don't answer `y`.

Before asking, it prints the device id, the relay's label for it, and a fingerprint of each key:
eight groups of four hex digits, the same ones the device shows. It also prints what the signed
state will do: its sequence, every device id it **replaces** (an entry with the same keys under
another id, which then stops receiving requests, #378), and the full list of recipients after it. **Compare the device id and all
eight groups of both fingerprints.** That comparison is the only check on the signing key (the
relay stores only the encryption key). A wrong signing key fails closed: the device's verdicts don't
verify, so they deny. On `y`, it root-signs and publishes the next account state, and records its
sequence in the keyfile.

`vouch` grants **decrypt only**: it does not issue a device certificate, by decision. Once
vouched, the device can read requests, but its approvals don't verify (integrators treat them as
deny) until it holds a certificate from this account root for its signing key. That certificate
comes from the cross-device enrollment ceremony (#199), not from `vouch`. Before `vouch` existed it
was the same: only `pair` issued certificates, for its own keyfile's key.

Library callers: `runVouch` takes the confirmation as an injected `Confirmer`, so a program can
answer yes without a terminal. That grants nothing new: the caller already holds the keyfile, and
with it the account root.

See `docs/enrollment.md` §Interim vouching and `docs/threat-model.md` R9.

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
pnpm run build:wasm                         # once, from the repo root
pnpm --filter "@allw/approver..." build     # this package and its workspace deps
pnpm --filter @allw/approver test
```

Covers the full round-trip against the **real WASM core**: encrypt → decrypt → recompute matching
`request_hash` → sign → `verify_verdict` accepts (id + hash, no-swap); the `denied` path; and
fail-closed paths (malformed ciphertext, wrong-key ciphertext, missing cert). Relay pairing is
exercised against an in-Node HTTP stub of the relay's pairing surface.
