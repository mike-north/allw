import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const SCRIPT_URL = new URL("./uat-codex.sh", import.meta.url);

async function readScript() {
  return await readFile(SCRIPT_URL, "utf8");
}

function stripHereDocs(source) {
  const lines = source.split("\n");
  const kept = [];
  let terminator = null;

  for (const line of lines) {
    if (terminator !== null) {
      if (line.trim() === terminator) terminator = null;
      continue;
    }

    kept.push(line);
    const match = /<<-?\s*'?([A-Za-z0-9_]+)'?/.exec(line);
    if (match) terminator = match[1];
  }

  return kept.join("\n");
}

test("Codex UAT helper prepares the gate without invoking Codex", async () => {
  const script = await readScript();
  const activeShell = stripHereDocs(script);

  assert.match(script, /pnpm run build:wasm/);
  assert.match(script, /pnpm -r build/);
  assert.match(script, /pnpm --filter @allw\/relay dev/);
  assert.match(script, /allw-approver pair/);
  assert.match(script, /allw-approver watch/);
  assert.match(script, /\.codex\/hooks\.json/);
  assert.doesNotMatch(script, /~\/\.codex/);
  assert.match(script, /Bash\|apply_patch\|mcp__\.\*/);
  assert.match(script, /ALLW_RELAY_URL/);
  assert.match(script, /ALLW_ACCOUNT_ID/);
  assert.match(script, /ALLW_APPROVER_ROOT_KEY/);
  assert.match(script, /codex exec/);
  assert.match(script, /codex:<hostname>/);

  assert.doesNotMatch(
    activeShell,
    /^\s*(?:command\s+|exec\s+|env\s+[^#\n]*\s+)?codex(?:\s|$)/m,
    "the helper must never run codex itself",
  );
  assert.doesNotMatch(activeShell, /\$\(\s*codex(?:\s|\))/);
  assert.doesNotMatch(activeShell, /`\s*codex(?:\s|`)/);
});
