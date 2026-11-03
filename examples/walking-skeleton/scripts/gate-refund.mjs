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
