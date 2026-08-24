#!/usr/bin/env bash
# Human-run OpenClaw UAT setup for issue #182.
#
# This helper intentionally NEVER starts the OpenClaw gateway, and never requires
# one to be installed. It prepares the local allw relay, a paired software
# approver, a throwaway OpenClaw config with the operator prerequisites from
# docs/openclaw-integration.md §3, and a wrapper that launches the bridge —
# then prints the exact commands for the human operator to run.
#
# Automating a live agent runtime has already proven unreliable (a macOS
# malware-detection false positive on the Codex binary), so the operator drives
# OpenClaw; repository automation only prepares the environment.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UAT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/allw-openclaw-uat.XXXXXX")"
STATE_DIR="$UAT_DIR/state"
KEYFILE="$UAT_DIR/approver-keyfile.json"
RELAY_LOG="$UAT_DIR/relay.log"
ACCOUNT_ID="acct_openclaw_uat_$(date +%s)_$$"
RELAY_PORT="${ALLW_UAT_RELAY_PORT:-8787}"
RELAY_URL="http://127.0.0.1:$RELAY_PORT"
GATEWAY_URL="${ALLW_OPENCLAW_GATEWAY_URL:-ws://127.0.0.1:18789}"
GATEWAY_ID="${ALLW_OPENCLAW_GATEWAY_ID:-uat-gateway}"
RELAY_PID=""

cleanup() {
  local status=$?

  if [[ -n "$RELAY_PID" ]] && kill -0 "$RELAY_PID" 2>/dev/null; then
    kill "$RELAY_PID" 2>/dev/null || true
    wait "$RELAY_PID" 2>/dev/null || true
  fi

  rm -rf "$UAT_DIR"
  exit "$status"
}
trap cleanup EXIT INT TERM

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'error: required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

wait_for_relay() {
  local deadline=$((SECONDS + 45))

  while ((SECONDS < deadline)); do
    # Any HTTP response proves wrangler is listening; the pairing call below is
    # the protocol-level readiness check.
    if [[ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 1 "$RELAY_URL/$ACCOUNT_ID/pairing/start" || true)" != "000" ]]; then
      return 0
    fi
    sleep 1
  done

  printf 'error: relay did not start at %s within 45s\n' "$RELAY_URL" >&2
  printf 'relay log: %s\n' "$RELAY_LOG" >&2
  sed -n '1,160p' "$RELAY_LOG" >&2 || true
  exit 1
}

require_command curl
require_command node
require_command pnpm

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

printf '==> Building local WASM and workspace packages\n'
(
  cd "$ROOT_DIR"
  pnpm run build:wasm
  pnpm -r build
)

printf '==> Starting local relay at %s\n' "$RELAY_URL"
(
  cd "$ROOT_DIR"
  pnpm --filter @allw/relay dev -- --ip 127.0.0.1 --port "$RELAY_PORT"
) >"$RELAY_LOG" 2>&1 &
RELAY_PID=$!
wait_for_relay

printf '==> Pairing temporary approver account %s\n' "$ACCOUNT_ID"
(
  cd "$ROOT_DIR"
  # Invoke the built CLI directly: pnpm does not link a package's OWN bin into
  # its own node_modules/.bin, so the filtered exec form fails on a fresh
  # checkout.
  node "$ROOT_DIR/packages/approver/dist/cli.js" pair \
    --relay "$RELAY_URL" \
    --account "$ACCOUNT_ID" \
    --label "openclaw-uat-$(hostname -s 2>/dev/null || hostname)" \
    --keyfile "$KEYFILE"
)

ACCOUNT_ROOT_KEY="$(
  node -e 'const fs = require("node:fs"); const keyfile = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(keyfile.account_root_pubkey);' "$KEYFILE"
)"
BRIDGE_CLI="$ROOT_DIR/packages/openclaw-bridge/dist/cli.js"
BRIDGE_WRAPPER="$UAT_DIR/allw-openclaw-bridge.sh"
OPENCLAW_CONFIG="$UAT_DIR/openclaw.json"

# The bridge reads its whole configuration from the environment, and the device
# key + paired device token live under ALLW_OPENCLAW_STATE_DIR at 0600 — never
# in this file.
cat >"$BRIDGE_WRAPPER" <<WRAPPER
#!/usr/bin/env bash
export ALLW_RELAY_URL=$(printf '%q' "$RELAY_URL")
export ALLW_ACCOUNT_ID=$(printf '%q' "$ACCOUNT_ID")
export ALLW_APPROVER_ROOT_KEY=$(printf '%q' "$ACCOUNT_ROOT_KEY")
export ALLW_OPENCLAW_GATEWAY_URL=$(printf '%q' "$GATEWAY_URL")
export ALLW_OPENCLAW_GATEWAY_ID=$(printf '%q' "$GATEWAY_ID")
export ALLW_OPENCLAW_STATE_DIR=$(printf '%q' "$STATE_DIR")
# Uncomment for the timeout case (step 3): a short cap makes the bridge's own
# deny land well before the gateway's expiresAtMs.
# export ALLW_OPENCLAW_MAX_TIMEOUT_MS=20000
exec node $(printf '%q' "$BRIDGE_CLI") "\$@"
WRAPPER
chmod +x "$BRIDGE_WRAPPER"

# The operator prerequisites from docs/openclaw-integration.md §3. Without these
# the gateway either never prompts or resolves approvals without a human, and
# the UAT would pass for the wrong reason.
cat >"$OPENCLAW_CONFIG" <<'JSON'
{
  "tools": {
    "exec": {
      "mode": "ask",
      "strictInlineEval": true
    }
  },
  "hostApprovals": {
    "ask": "always",
    "askFallback": "deny"
  },
  "autoAllowSkills": false,
  "approvals": {
    "exec": { "enabled": false },
    "plugin": { "enabled": false }
  }
}
JSON

cat <<EOF

==> OpenClaw UAT environment is ready

Relay:
  $RELAY_URL
  log: $RELAY_LOG

Bridge:
  wrapper:     $BRIDGE_WRAPPER
  gateway url: $GATEWAY_URL
  gateway id:  $GATEWAY_ID   (inbox actor: openclaw:$GATEWAY_ID)
  state dir:   $STATE_DIR    (device key + paired device token, 0600)

Throwaway OpenClaw config carrying the §3 operator prerequisites:
  $OPENCLAW_CONFIG

This script does not start or install OpenClaw. Merge that config into your own
gateway config (or point the gateway at it) and start the gateway yourself.

Step 1 - start the bridge in a second terminal:
  bash $(printf '%q' "$BRIDGE_WRAPPER")

  On the first run the gateway will refuse the connection with PAIRING_REQUIRED
  and the bridge logs the request id. Approve it on the gateway host:
    openclaw devices approve <requestId>
  Then re-run the wrapper; the paired device token is persisted automatically.

Step 2 - leave this terminal running allw-approver watch and drive OpenClaw
from a third terminal.

Checks to run (docs/openclaw-integration.md §11):
  1. Approve (exec)      - ask the agent to run a harmless gated command, approve
                           on the second device; the gateway must record
                           allow-once with terminal_reason: user.
  2. Deny (exec)         - ask for another gated command, deny on the device.
  3. Timeout             - uncomment ALLW_OPENCLAW_MAX_TIMEOUT_MS in the wrapper,
                           leave the approval unanswered, and confirm the bridge
                           denies BEFORE the gateway's own expiresAtMs.
  4. Actor identity      - the inbox must show openclaw:$GATEWAY_ID, distinct
                           from any codex:<hostname> request on this machine.
  5. Plan divergence     - after approving, mutate the command/cwd before the
                           forwarded system.run; the GATEWAY must reject it as an
                           approval mismatch (the two bindings compose).

Deferred to a later slice (do not test here): plugin permission requests, the
allow-once-unavailable path on a plugin request, and the plugin surface race.

Paste this UAT result template back onto #182:

  Approve (exec): PASS/FAIL - command ran only after approval
  Deny (exec): PASS/FAIL - command was blocked after denial
  Timeout: PASS/FAIL - bridge denied before the gateway deadline
  Actor identity: PASS/FAIL - inbox showed openclaw:$GATEWAY_ID
  Plan divergence: PASS/FAIL - gateway rejected the mutated run
  Notes:

Press Ctrl-C in this terminal when UAT is complete; cleanup will stop the relay
and remove the temporary state directory, keyfile, and config.

==> Starting foreground approver watch

EOF

cd "$ROOT_DIR"
# Direct bin invocation for the same reason as the pair call above.
node "$ROOT_DIR/packages/approver/dist/cli.js" watch --relay "$RELAY_URL" --keyfile "$KEYFILE"
