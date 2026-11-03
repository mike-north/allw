/**
 * Static checks on the human-run Codex UAT helper, which must never run Codex itself.
 *
 * @see https://learn.chatgpt.com/docs/config-file/config-reference (approval_policy, approvals_reviewer)
 * @see https://toml.io/en/v1.0.0
 * @see ../docs/codex-integration.md
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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

  assert.deepEqual(codexInvocations(activeShell), [], "the helper must never run codex itself");
});

/**
 * Patterns that would run Codex from shell code. Each is applied per line, after heredoc bodies and comments are
 * removed. `codex` may still appear inside a path or name (`.codex/`, `codex-hook`, `allw-codex-uat`).
 */
const CODEX_INVOCATION_PATTERNS = [
  // `codex` as a word of its own: a direct call, `command`/`exec`/`env`/`xargs`/`eval codex`, `$(codex)`,
  // backticks, `bash -c "codex …"`, or a variable assigned the name (`cmd=codex`).
  /(?<![\w./-])codex(?![\w./-])/i,
  // Variable indirection: a variable named for Codex (`$CODEX`, `${CODEX_BIN}`) whose value comes from elsewhere.
  /\$\{?[A-Za-z_]*codex/i,
  // Indirect execution of a computed string, which no static check can see through.
  /(?:^|[;&|(\s])eval(?:\s|$)/,
  /(?:^|[;&|(\s])(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*-\w*c\b/,
  /(?:^|[;&|(\s])xargs(?:\s|$)/,
];

/** The lines of `activeShell` (heredocs already removed) that match a Codex invocation pattern. */
function codexInvocations(activeShell) {
  return activeShell
    .split("\n")
    .map((line) => line.replace(/(?:^|\s)#.*$/, ""))
    .filter((code) => CODEX_INVOCATION_PATTERNS.some((pattern) => pattern.test(code)));
}

test("The never-run-codex guard catches direct and indirect invocations", () => {
  const forbidden = [
    "codex exec 'hi'",
    "  command codex",
    "exec codex",
    "env FOO=1 codex exec x",
    'out="$(codex exec x)"',
    "out=`codex exec x`",
    'eval "$cmd"',
    "bash -c 'codex exec x'",
    'sh -c "echo hi"',
    "zsh -ec 'true'",
    "echo x | xargs codex exec",
    "printf '%s' x | xargs -0 echo",
    'CODEX=codex; "$CODEX" exec x',
    'cmd="codex"',
    '"${CODEX_BIN}" exec x',
    "$codex_path exec x",
  ];
  for (const line of forbidden) {
    assert.equal(codexInvocations(line).length, 1, `the guard must flag: ${line}`);
  }

  const allowed = [
    'mkdir -p "$PROJECT_DIR/.codex/rules"',
    'HOOK_CLI="$ROOT_DIR/packages/codex-hook/dist/cli.js"',
    'UAT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/allw-codex-uat.XXXXXX")"',
    '    --label "codex-uat-$(hostname -s 2>/dev/null || hostname)" \\',
    "# The operator runs codex exec by hand.",
    "require_command git # not codex",
  ];
  assert.deepEqual(codexInvocations(allowed.join("\n")), []);
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

/** The body of the quoted `<<'TOML'` heredoc that writes the project's `.codex/config.toml`. */
function extractTomlHeredoc(source) {
  const match = /cat >"\$PROJECT_DIR\/\.codex\/config\.toml" <<'TOML'\n([\s\S]*?)\nTOML\n/.exec(
    source,
  );
  assert.ok(match, "the script must write .codex/config.toml from a quoted TOML heredoc");
  return match[1];
}

/**
 * Python source that parses TOML from stdin with the standard-library `tomllib` (Python >= 3.11) and prints JSON.
 * An older Python exits with a message naming `tomllib` instead of a bare `ModuleNotFoundError`.
 */
const PARSE_TOML_PY = [
  "import json, sys",
  "if sys.version_info < (3, 11):",
  "    sys.exit('tomllib needs Python >= 3.11; python3 is ' + sys.version.split()[0])",
  "import tomllib",
  "print(json.dumps(tomllib.loads(sys.stdin.read())))",
].join("\n");

/**
 * Parses TOML with Python's standard-library `tomllib` (TOML 1.0), so no parser dependency is added.
 * A missing or too-old `python3` fails with a message that says so, rather than as a TOML error.
 */
function parseToml(text) {
  const result = spawnSync("python3", ["-I", "-c", PARSE_TOML_PY], {
    input: text,
    encoding: "utf8",
  });
  if (result.error) {
    assert.fail(
      `this test needs python3 >= 3.11 on PATH to parse config.toml with tomllib: ${result.error.message}`,
    );
  }
  if (result.status !== 0 && result.stderr.includes("tomllib needs Python >= 3.11")) {
    assert.fail(`this test parses config.toml with tomllib: ${result.stderr.trim()}`);
  }
  assert.equal(result.status, 0, `config.toml must parse as TOML: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

test("Generated .codex/config.toml parses and sets the fail-closed granular approval policy (#192)", async () => {
  const script = await readScript();
  const config = parseToml(extractTomlHeredoc(script));

  // docs/codex-integration.md §Granular approval_policy: each granular key means "this category may
  // surface"; false auto-rejects. The three categories the PreToolUse hook can't see are false; the
  // two that only add a Codex-side gate after allw stay true. A human reviews Codex's own prompts.
  assert.deepEqual(config, {
    approvals_reviewer: "user",
    approval_policy: {
      granular: {
        sandbox_approval: true,
        rules: true,
        mcp_elicitations: false,
        request_permissions: false,
        skill_approval: false,
      },
    },
  });
});

test("UAT project is a git repo with one .rules rule per decision and a printed trust step (#192)", async () => {
  const script = await readScript();
  const activeShell = stripHereDocs(script);

  // `codex exec` exits outside a git repository (codex-rs/exec/src/lib.rs), so the project is one.
  assert.match(activeShell, /^git init -q "\$PROJECT_DIR"$/m);

  // docs/codex-integration.md §execpolicy `.rules`: one prefix_rule per decision, each on its own
  // command, so each UAT case exercises exactly one rule.
  const rules = /<<'RULES'\n([\s\S]*?)\nRULES\n/.exec(script)?.[1] ?? "";
  for (const decision of ["allow", "prompt", "forbidden"]) {
    assert.match(
      rules,
      new RegExp(
        `pattern = \\["echo", "allw-uat-rules-${decision}"\\],\\n\\s+decision = "${decision}",`,
      ),
      `uat.rules must have a ${decision} rule on its own command`,
    );
  }
  assert.match(script, /\.codex\/rules\/uat\.rules/);

  // Codex silently skips an untrusted hook (#348), so the printed instructions must include the
  // one-time trust step before any case, and a PASS/FAIL line for each new case.
  assert.match(script, /One-time trust step \(required\)/);
  for (const line of [
    ".rules allow: PASS/FAIL",
    ".rules prompt: PASS/FAIL",
    ".rules forbidden: PASS/FAIL",
    "Granular auto-reject: PASS/FAIL",
    "Permission mode: PASS/FAIL",
  ]) {
    assert.ok(script.includes(line), `the #97 template must include "${line}"`);
  }
});
