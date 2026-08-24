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

/**
 * Extract the body of the heredoc that writes hooks.json (the JSON here-doc
 * between <<JSON and the closing JSON terminator).
 */
function extractJsonHeredoc(source) {
  const match = /<<JSON\n([\s\S]*?)\nJSON\b/m.exec(source);
  return match ? match[1] : "";
}

test("Codex UAT helper prepares the gate without invoking Codex", async () => {
  const script = await readScript();
  const activeShell = stripHereDocs(script);

  assert.match(script, /pnpm run build:wasm/);
  assert.match(script, /pnpm -r build/);
  assert.match(script, /pnpm --filter @allw\/relay dev/);
  // The helper invokes the built approver CLI directly (#189): pnpm does not link a package's own
  // bin into its own node_modules/.bin, so the filtered exec form breaks on a fresh checkout.
  assert.match(script, /approver\/dist\/cli\.js" pair/);
  assert.match(script, /approver\/dist\/cli\.js" watch/);
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

test("Generated hooks.json uses self-contained wrapper approach, not unsupported env map", async () => {
  const script = await readScript();
  const jsonHeredoc = extractJsonHeredoc(script);

  // The hooks.json template must not contain an "env" key — Codex's command hook
  // schema has no per-handler env field; adding one would silently be ignored and
  // the hook would launch without ALLW_RELAY_URL / ALLW_ACCOUNT_ID / ALLW_APPROVER_ROOT_KEY.
  assert.doesNotMatch(
    jsonHeredoc,
    /"env"\s*:/,
    'hooks.json template must not emit an unsupported "env" key',
  );

  // The three ALLW_* values must appear in the active shell (the wrapper script
  // section), not be omitted — they must be baked into the generated wrapper.
  assert.match(script, /export ALLW_RELAY_URL/, "wrapper must export ALLW_RELAY_URL");
  assert.match(script, /export ALLW_ACCOUNT_ID/, "wrapper must export ALLW_ACCOUNT_ID");
  assert.match(
    script,
    /export ALLW_APPROVER_ROOT_KEY/,
    "wrapper must export ALLW_APPROVER_ROOT_KEY",
  );

  // The wrapper script file must be referenced so Codex invokes it.
  assert.match(script, /allw-hook\.sh/, "script must write a named wrapper (allw-hook.sh)");

  // The hooks.json "command" entry must reference the wrapper, not bare node cli.
  assert.match(
    jsonHeredoc,
    /bash.*HOOK_WRAPPER|HOOK_WRAPPER.*bash/,
    'hooks.json "command" must invoke the wrapper via bash',
  );
});
