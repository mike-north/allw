# @allw/sdk

The call site for asking a human to approve an action. `requestApproval` sends an end-to-end-encrypted
request to the human's devices through the zero-knowledge relay, waits for their signed decision, and
**verifies it before returning** (`docs/contract.md`). All crypto runs in the audited Rust core, which
ships with this package as WASM.

The SDK never returns "allow". It returns a verified human decision. Your code decides whether to
proceed, and it must fail closed: anything other than `decision === "approved"` means stop.

## Gate a command from a script

A script about to run a command uses the `command` surface, the same one the agent hooks use.
`commandRequest` builds the full request in one call. The script below is the one
`examples/walking-skeleton/test/plain-script.test.mjs` runs verbatim:

```js
// Gate a command on a human approval from a plain script (issue #231). Usage: node gate-refund.mjs <charge-id>
import { createClient, commandRequest } from "@allw/sdk";

const {
  ALLW_RELAY_URL: relayUrl,
  ALLW_ACCOUNT_ID: accountId,
  ALLW_APPROVER_ROOT_KEY: approverRootKey,
} = process.env;
const timeoutMs = Number(process.env.ALLW_TIMEOUT_MS ?? 300_000);
const argv = ["stripe", "refunds", "create", "--charge", process.argv[2]];
const client = createClient({ relayUrl, accountId, approverRootKey });
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

## Request size limit

The relay refuses a request whose encrypted context (`context_ciphertext`) is over **64 KiB**, counted
in UTF-8 bytes, with HTTP 413 (`docs/relay-api.md` §3). The ciphertext is larger than the plaintext
context it encrypts, so keep the summary and action detail well under that. An over-size request
fails closed: nothing is stored or shown to the human, and `requestApproval` rejects with an
error whose `name` is `"RelayError"` and whose `status` is 413. Treat that rejection, like any other, as deny; never retry it
into an approval.
