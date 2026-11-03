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

| Field        | Value                                                                                   |
| ------------ | --------------------------------------------------------------------------------------- |
| `action`     | Built by the core from `argv` (exact tokens) or `commandLine` (tokenized by the core).  |
| `risk`       | Taken from the core-built `action.risk`. You never state it twice.                      |
| `actor`      | Default `{ id: "machine:<os.hostname()>", kind: "script" }`.                            |
| `reversible` | Default `false`. The human is told the action can't be undone unless you say otherwise. |
| `cwd`, `raw` | Optional. Bound into `action.syntactic` so the human sees them.                         |
| others       | `timeoutMs`, `signal`, `constraints` and `chain` are passed through when given.         |

Pass `argv` when you hold the exact tokens that will run. Re-tokenizing text could bind different
tokens than the ones that execute.

For just the `ActionRecord`, use `commandAction(argv, { cwd?, raw? })` or
`commandActionFromLine(line, { cwd? })`. Both return exactly the record the core builds. The SDK does
no tokenizing or risk classification of its own.

All three reject with a `CommandActionError` (with a machine-readable `reason`) when the input is
malformed, so nothing is submitted. That covers an empty `argv`, a non-string element, a blank or
unparseable command line (for example an unmatched quote), or a blank `summary`.
