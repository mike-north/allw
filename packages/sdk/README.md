# @allw/sdk

The call site for asking a human to approve an action. `requestApproval` sends an end-to-end-encrypted
request to the human's devices through the zero-knowledge relay, waits for their signed decision, and
**verifies it before returning** (`docs/contract.md`). All crypto runs in the audited Rust core, which
ships with this package as WASM.

Waiting ends on the first fully verified verdict, including a verified denial or abort. Unverifiable
WebSocket frames and polled verdicts are ignored until `expires_at`; without a verified verdict the
result is `expired`. Verification reuses the account-state set loaded once for the request. Polling
keeps its cadence after a rejected verdict, even if the relay has already resolved and cannot deliver
a replacement. Transport failures still fail closed. When the caller aborts a pending request,
the SDK attempts retraction: confirmation rejects with `RequestRetractedError`; a refusal or failure
ends the local wait `expired` once that attempt settles, without waiting for `expires_at`. The
original deadline still bounds a hung retract. This applies even if the relay has already resolved
on an SDK-unverifiable verdict; it does not imply that the server-side request was retracted.

The SDK never returns "allow". It returns a verified human decision. Your code decides whether to
proceed, and it must fail closed: anything other than `decision === "approved"` means stop.

## Gate a command from a script

A script about to run a command uses the `command` surface, the same one the agent hooks use.
`commandRequest` builds the full request in one call. The script below is the one
`examples/walking-skeleton/test/plain-script.test.mjs` runs verbatim:

```js
// Gate a command on a human approval from a plain script (issue #231). Usage: node gate-refund.mjs <charge-id>
import {
  createClient,
  commandRequest,
  fileSequenceFloorStore,
  relayAccountStateSource,
} from "@allw/sdk";

const {
  ALLW_RELAY_URL: relayUrl,
  ALLW_ACCOUNT_ID: accountId,
  ALLW_APPROVER_ROOT_KEY: approverRootKey,
} = process.env;
const timeoutMs = Number(process.env.ALLW_TIMEOUT_MS ?? 300_000);
const argv = ["stripe", "refunds", "create", "--charge", process.argv[2]];
// Encrypt only to the devices the root-signed account state vouches for; refuse a rollback.
const floorStore = fileSequenceFloorStore({ accountId });
const accountStates = relayAccountStateSource({ relayUrl, accountId, floorStore });
const client = createClient({ relayUrl, accountId, approverRootKey, accountStates });
const verdict = await client.requestApproval(
  await commandRequest({ argv, summary: `Refund charge ${process.argv[2]}`, timeoutMs }),
);
console.log(`decision: ${verdict.decision}`);
if (verdict.decision !== "approved") process.exit(1); // fail-closed: only a verified approval proceeds
// ... now run argv, e.g. execFileSync(argv[0], argv.slice(1), { stdio: "inherit" })
```

`commandRequest({ argv | commandLine, summary, ... })` fills in the request like this:

| Field        | Value                                                                                                                                        |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `action`     | Built by the core from `argv` (exact tokens) or `commandLine` (tokenized by the core).                                                       |
| `risk`       | Taken from the core-built `action.risk`. You never state it twice.                                                                           |
| `actor`      | Default `{ id: "machine:<os.hostname()>", kind: "script" }`.                                                                                 |
| `reversible` | Default `false`. The human is told the action can't be undone unless you say otherwise.                                                      |
| `cwd`        | Default `process.cwd()`, where `execFile` / `spawn` run the command. If you run it elsewhere, pass that directory. `null` leaves it unbound. |
| others       | `timeoutMs`, `signal`, `constraints` and `chain` are passed through when given.                                                              |

Prefer `argv`, and run exactly that `argv` with `execFile` or `spawn` (no shell). Re-tokenizing text
could bind different tokens than the ones that execute.

`commandLine` is only split into words. Shell operators (`&&`, `;`, `|`, redirections), substitutions
(`$(…)`, backticks) and newlines are not parsed, and the record describes only the first program:
`ls && rm -rf /` is recorded as `ls`. **Never run a `commandLine` through a shell** (`sh -c`,
`execSync`), because the shell would run more than the human approved.

For just the `ActionRecord`, use `commandAction(argv, { cwd?, raw? })` or
`commandActionFromLine(line, { cwd? })`. Both return exactly the record the core builds, and neither
binds a `cwd` unless you pass one. The SDK does no tokenizing or risk classification of its own.
`raw` is for an upstream gate that already holds the command's display text. It must be the exact text
of `argv`, because some approvers show `raw` in place of `argv`. `commandRequest` does not take it.

All three reject with a `CommandActionError` (with a machine-readable `reason`) when the input is
malformed, so nothing is submitted. That covers an empty `argv`, a non-string element, a blank or
unparseable command line (for example an unmatched quote), an empty program, a blank `summary` or
`cwd`, a malformed `actor`, a non-positive or non-integer `timeoutMs`, or `raw` passed to
`commandRequest`.

A command that runs no program is refused too, because there is nothing to show the human. The core
refuses it, so every allw surface agrees: a command line that is only variable assignments or shell
operators (`FOO=1`, `&&`) rejects with `reason: "command_line_no_program"`, and an `argv` of only
assignments (`["FOO=1"]`) with `reason: "argv_no_program"`. A blank or comment-only line is
`command_line_empty`, and an empty program word is `argv_program_empty`.

## Who can read a request: account state

`createClient` requires `accountStates`. A request is encrypted only to the devices that root-signed
account state vouches for (`docs/enrollment.md` §Model). The relay's own device list is never used
for keys, so a relay cannot add a reader. Verdicts from devices that account state revokes are
rejected.

`expectedAccountId` defaults to the client's configured `accountId` when omitted or empty.
A device certificate issued by the same root for a different account cannot answer the request.
This defense complements account-state binding and remains in force when `Verdict.verify()` is
called with `accountStates: []` or `accountStates: undefined` to omit revocation context.
Standalone verification exports have no client default; pass `expectedAccountId` explicitly.

- **`relayAccountStateSource({ relayUrl, accountId, floorStore })`** is what the hooks use. It fetches
  `GET /{account}/account-states` for each request; the documents are verified in the core against
  `approverRootKey`, so the fetch needs no credentials.
- **`fileSequenceFloorStore({ accountId })`** keeps the highest sequence used so far in
  `~/.allw/state/<account_id>.floor.json`. A later state below it is refused, which stops a relay
  from rolling back to a state that still lists a revoked device. Only a missing file means "no
  floor yet". A file that is corrupt, unreadable, not a regular file (a symlink included), owned by
  another user, or writable by others makes the request fail closed, as does a state directory that
  is not a real directory, is owned by another user, or is group- or world-writable. Pass `dir` to
  keep the floor somewhere else.
- A fixed array of compact account-state documents also works. The caller then owns rollback
  protection.
- You can write your own `AccountStateSource`. `load()` is called once per request, and that set is
  used for both encryption and verdict checks. After sealing, the SDK awaits
  `accepted(sequence)` **before** sending; if it throws, nothing is sent.

When account state can't be loaded, doesn't verify, is below the floor, or names no active device,
`requestApproval` rejects with a `RecipientSelectionError` (`stage`: `"load"`, `"seal"` or
`"accept"`) and nothing is sent. Treat that like a denial. If you call
`relayAccountStateSource(...).load()` yourself, a fetch that hangs past `fetchTimeoutMs` rejects with
`RelayTimeoutError`, exported from `@allw/sdk` so you can check it with `instanceof`. Until the account's root holder runs
`allw-approver pair`, there is no account state, and every request is refused.

## Request size limit

The relay refuses a request whose encrypted context (`context_ciphertext`) is over **64 KiB**, counted
in UTF-8 bytes, with HTTP 413 (`docs/relay-api.md` §3). The ciphertext is larger than the plaintext
context it encrypts, so keep the summary and action detail well under that. An over-size request
fails closed: nothing is stored or shown to the human, and `requestApproval` rejects with a
`RelayError` whose `status` is 413. Treat that rejection, like any other, as deny; never retry it
into an approval.

`RelayError` is exported, so you can narrow on it. `requestApproval` rejects with it only when
the submit gets a non-2xx reply, or a 2xx whose body is malformed. A failed account-state fetch
rejects earlier, with a `RecipientSelectionError` (stage `"load"`) whose `cause` is the
`RelayError` or `RelayTimeoutError` (see above). Once the request is submitted, a non-2xx or
malformed poll reply (for example 401 or 403) resolves to an `expired` verdict instead, and a failed
retract is ignored. So does a relay that hangs or can't be reached after that point. The error's
message never quotes the relay's body.

```ts
import { RelayError } from "@allw/sdk";

try {
  const verdict = await client.requestApproval(request);
  // ...compute allow from the verified verdict
} catch (err) {
  if (err instanceof RelayError && err.status === 413) {
    log("allw: the encrypted context is over 64 KiB; shrink the summary or action detail");
  }
  return deny(); // every rejection is a deny
}
```
