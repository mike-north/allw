#!/usr/bin/env bash
# Human-run Codex UAT setup for issue #126.
#
# This helper intentionally NEVER starts Codex. It prepares the local allw relay,
# a paired software approver, and a temporary project-scoped Codex hook config,
# then prints the exact Codex commands for the human operator to run.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UAT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/allw-codex-uat.XXXXXX")"
PROJECT_DIR="$UAT_DIR/project"
KEYFILE="$UAT_DIR/approver-keyfile.json"
RELAY_LOG="$UAT_DIR/relay.log"
ACCOUNT_ID="acct_codex_uat_$(date +%s)_$$"
RELAY_PORT="${ALLW_UAT_RELAY_PORT:-8787}"
RELAY_URL="http://127.0.0.1:$RELAY_PORT"
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

  while (( SECONDS < deadline )); do
    # Any HTTP response proves wrangler is listening; the actual pairing call below is the
    # protocol-level readiness check.
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

json_string() {
  node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$1"
}

require_command curl
require_command node
require_command pnpm

mkdir -p "$PROJECT_DIR/.codex"

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
  pnpm --filter @allw/approver exec allw-approver pair \
    --relay "$RELAY_URL" \
    --account "$ACCOUNT_ID" \
    --label "codex-uat-$(hostname -s 2>/dev/null || hostname)" \
    --keyfile "$KEYFILE"
)

ACCOUNT_ROOT_KEY="$(
  node -e 'const fs = require("node:fs"); const keyfile = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); process.stdout.write(keyfile.account_root_pubkey);' "$KEYFILE"
)"
HOOK_CLI="$ROOT_DIR/packages/codex-hook/dist/cli.js"
HOOK_COMMAND="node $HOOK_CLI"

cat >"$PROJECT_DIR/.codex/hooks.json" <<JSON
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|apply_patch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": $(json_string "$HOOK_COMMAND"),
            "timeout": 480,
            "statusMessage": "Requesting allw approval",
            "env": {
              "ALLW_RELAY_URL": $(json_string "$RELAY_URL"),
              "ALLW_ACCOUNT_ID": $(json_string "$ACCOUNT_ID"),
              "ALLW_APPROVER_ROOT_KEY": $(json_string "$ACCOUNT_ROOT_KEY")
            }
          }
        ]
      }
    ]
  }
}
JSON

cat >"$PROJECT_DIR/README.md" <<EOF
# allw Codex UAT scratch project

This temporary project contains only project-scoped Codex hook config:

- .codex/hooks.json
- relay: $RELAY_URL
- account: $ACCOUNT_ID

It is deleted when scripts/uat-codex.sh exits.
EOF

cat <<EOF

==> Codex UAT environment is ready

Relay:
  $RELAY_URL
  log: $RELAY_LOG

Temporary Codex project:
  $PROJECT_DIR
  project hook config: $PROJECT_DIR/.codex/hooks.json

This script will now run allw-approver watch in the foreground so you can
approve, deny, skip, or let requests time out. Leave this terminal open.

Open a second terminal and run the Codex command yourself. The setup script
does not invoke codex.

Approve case:
  cd $(printf '%q' "$PROJECT_DIR")
  codex exec "run: echo allw-uat-approve"

Deny case:
  cd $(printf '%q' "$PROJECT_DIR")
  codex exec "run: echo allw-uat-deny"

Timeout case:
  node -e 'const fs = require("node:fs"); const p = process.argv[1]; const c = JSON.parse(fs.readFileSync(p, "utf8")); c.hooks.PreToolUse[0].hooks[0].env.ALLW_TIMEOUT_MS = "5000"; fs.writeFileSync(p, JSON.stringify(c, null, 2) + "\n");' "$PROJECT_DIR/.codex/hooks.json"
  Then run:
    cd $(printf '%q' "$PROJECT_DIR")
    codex exec "run: echo allw-uat-timeout"

Actor identity check:
  The approval inbox must show actor.id as codex:<hostname>.

File-edit case:
  cd $(printf '%q' "$PROJECT_DIR")
  codex exec "edit README.md and add a line that says allw-uat-file-edit"

Paste this UAT result template back onto #97:

  Approve: PASS/FAIL - command ran only after approval
  Deny: PASS/FAIL - command was blocked after denial
  Timeout: PASS/FAIL - command failed closed after ALLW_TIMEOUT_MS
  Actor identity: PASS/FAIL - inbox showed codex:<hostname>
  File edit: PASS/FAIL - apply_patch was gated with path, summary, and diff hash
  Notes:

Press Ctrl-C in this terminal when UAT is complete; cleanup will stop the
relay and remove the temporary project/keyfile.

==> Starting foreground approver watch

EOF

cd "$ROOT_DIR"
pnpm --filter @allw/approver exec allw-approver watch --relay "$RELAY_URL" --keyfile "$KEYFILE"
