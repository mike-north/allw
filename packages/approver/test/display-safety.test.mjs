/**
 * Display-safety tests for the CLI approver (#246, review finding S7).
 *
 * The CLI must never let a request's own bytes repaint the terminal. These tests drive the real
 * WASM core end to end and assert on the **actual rendered output**:
 *
 * - the #246 ESC/CR line-erase spoof (`rm -rf ~/x; : ESC[2K CR git status`) reaches stdout as visible
 *   escapes, with no raw 0x1b / 0x0d byte, and a hidden-character warning above the prompt;
 * - bidi overrides and zero-width characters in other fields (cwd, actor, summary) are escaped too;
 * - relay-supplied log text (request ids, relay error strings) is escaped before it is printed;
 * - escaping is display-only: the request hash still binds the raw bytes.
 *
 * The final test is a UAT: it runs `runWatch` in a child process with the real readline prompter
 * and the default console logger, and inspects the child's stdout/stderr bytes.
 *
 * Expected escaped strings are written by hand from the notation in
 * `crates/allw-core/src/display.rs` (`\x1b`, `\r`, `⟨U+202E⟩`), not captured from program output.
 *
 * @see ../../../docs/contract.md §Invariants #3 (WYSIWYS)
 * @see ../../../docs/threat-model.md R3 (WYSIWYS completeness)
 * @see https://www.unicode.org/reports/tr9/ §2 (explicit bidi formatting characters)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadWasm } from "../dist/index.js";
import { generateKeyfile } from "../dist/lib/keyfile.js";
import { prepareRequest } from "../dist/lib/approver-core.js";
import { HIDDEN_CHARS_WARNING, renderRequest } from "../dist/lib/render.js";
import { runWatch } from "../dist/commands/watch.js";
import { writeKeyfile } from "../dist/lib/keyfile.js";

const here = dirname(fileURLToPath(import.meta.url));

const ACCOUNT_ID = "acct-display-test";
const DEVICE_ID = "dev-display-test";
const REQUEST_ID = "req-display-1";
const ISSUED_AT = 1700000000000;
const EXPIRES_AT = 1700003600000;
const NOW_MS = 1700001500000;

const ESC = "\u001b";
const CR = "\r";
/** The #246 spoof: erase the current line, return the cursor, repaint a benign command. */
const SPOOF = `rm -rf ~/x; : ${ESC}[2K${CR}git status`;
/** The same spoof as the core displays it (hand-written from the documented notation). */
const SPOOF_ESCAPED = "rm -rf ~/x; : \\x1b[2K\\rgit status";

function context(overrides = {}) {
  return {
    action: {
      record_schema_version: 1,
      surface: "command",
      syntactic: { raw: SPOOF },
      risk: "critical",
    },
    summary: "check git status",
    actor: { id: "machine:ci", kind: "claude-code" },
    risk: "critical",
    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
    ...overrides,
  };
}

function paired(wasm) {
  const fresh = generateKeyfile(wasm);
  const cert = wasm.issue_device_cert(
    fresh.account_root_seed,
    ACCOUNT_ID,
    DEVICE_ID,
    fresh.device_signing_pubkey,
    ISSUED_AT,
  );
  return {
    ...fresh,
    relay_url: "https://relay.allw.test",
    account_id: ACCOUNT_ID,
    device_id: DEVICE_ID,
    device_cert: cert,
  };
}

function envelopeFor(wasm, keyfile, ctx, id = REQUEST_ID) {
  const jwe = wasm.encrypt_context(
    JSON.stringify(ctx),
    JSON.stringify([{ device_id: DEVICE_ID, public_key_b64: keyfile.device_encryption_pubkey }]),
  );
  return {
    v: 1,
    id,
    created_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    approver: ACCOUNT_ID,
    context_ciphertext: jwe,
  };
}

async function render(ctx, id) {
  const wasm = await loadWasm();
  const keyfile = paired(wasm);
  const prepared = prepareRequest(wasm, keyfile, envelopeFor(wasm, keyfile, ctx, id), NOW_MS);
  return { wasm, prepared, rendered: renderRequest(prepared) };
}

/** Every C0 control except LF (the block's own line separator), plus DEL and C1. */
// eslint-disable-next-line no-control-regex
const RAW_CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/;
const RAW_BIDI_OR_INVISIBLE = /[؜​-‏‪-‮⁠⁦-⁩﻿]/;

test("ESC/CR line-erase spoof renders escaped, with no raw control byte (#246)", async () => {
  const { rendered } = await render(context());
  assert.ok(!rendered.includes(ESC), "no raw ESC (0x1b) may reach the terminal");
  assert.ok(!rendered.includes(CR), "no raw CR (0x0d) may reach the terminal");
  assert.doesNotMatch(rendered, RAW_CONTROL);
  assert.match(rendered.split("\n").find((l) => l.startsWith("  Action:")) ?? "", /x1b/);
  assert.ok(rendered.includes(`  Action:     ${SPOOF_ESCAPED}`), "the real bytes are visible");
});

test("hidden-character warning appears above the action when the core flags the request", async () => {
  const { rendered } = await render(context());
  const lines = rendered.split("\n");
  const warningAt = lines.indexOf(HIDDEN_CHARS_WARNING);
  assert.ok(warningAt > 0, "warning line is present");
  assert.ok(
    warningAt < lines.findIndex((l) => l.startsWith("  Action:")),
    "warning precedes the action",
  );
});

test("a clean request shows no hidden-character warning", async () => {
  const clean = context();
  clean.action = { ...clean.action, syntactic: { raw: "git status" } };
  const { rendered } = await render(clean);
  assert.ok(!rendered.includes(HIDDEN_CHARS_WARNING));
  assert.match(rendered, /Action:\s+git status$/m);
});

test("bidi override in cwd and zero-width space in actor id are escaped", async () => {
  const ctx = context();
  ctx.action = {
    ...ctx.action,
    syntactic: { raw: "ls", cwd: "/home/dev/‮ppa" },
  };
  ctx.actor = { id: "machine:ci​", kind: "claude-code" };
  const { rendered } = await render(ctx);
  assert.doesNotMatch(rendered, RAW_BIDI_OR_INVISIBLE);
  assert.match(rendered, /Cwd:\s+\/home\/dev\/⟨U\+202E⟩ppa/);
  assert.match(rendered, /Actor:\s+machine:ci⟨U\+200B⟩ \(claude-code\)/);
  assert.ok(rendered.includes(HIDDEN_CHARS_WARNING));
});

test("summary, argv, flags, chain and MCP params are escaped", async () => {
  const ctx = context({
    summary: `safe${CR}overwritten`,
    chain: [`gate${ESC}`],
  });
  ctx.action = {
    ...ctx.action,
    surface: "mcp_tool_call",
    syntactic: {
      server: "fs",
      tool: "write⁦",
      params: { path: "/tmp/‮txt.exe" },
      argv: ["echo", `a${ESC}b`],
      flags: [`--x${CR}`],
    },
  };
  const { rendered } = await render(ctx);
  assert.doesNotMatch(rendered, RAW_CONTROL);
  assert.doesNotMatch(rendered, RAW_BIDI_OR_INVISIBLE);
  assert.match(rendered, /Summary:\s+safe\\roverwritten/);
  assert.match(rendered, /Chain:\s+gate\\x1b/);
  assert.match(rendered, /MCP:\s+fs :: write⟨U\+2066⟩/);
  assert.ok(rendered.includes(`Params:     {"path":"/tmp/⟨U+202E⟩txt.exe"}`));
  assert.ok(rendered.includes("Flags:      '--x\\r'"), "escaped token is quoted at its boundary");
});

test("the relay-supplied request id is escaped", async () => {
  const { rendered } = await render(context(), `req${ESC}[2K`);
  assert.ok(rendered.includes("Request:    req\\x1b[2K"));
  assert.ok(!rendered.includes(ESC));
});

test("divergence is decided on raw bytes: literal '\\x1b' text never masks a real ESC argv", async () => {
  // `raw` holds the four printable characters `\x1b`; argv holds a real ESC byte. Both display as
  // `\x1b`, but they are different commands, so the Argv divergence line must still be shown.
  const ctx = context();
  ctx.action = {
    ...ctx.action,
    syntactic: { raw: "echo \\x1b", argv: ["echo", ESC] },
  };
  const { rendered } = await render(ctx);
  assert.match(rendered, /^ {2}Argv:/m, "divergent argv is surfaced");
  assert.ok(rendered.includes(HIDDEN_CHARS_WARNING), "the real ESC raises the warning");
});

test("file-edit content keeps one line per LF and marks a CRLF ending without warning", async () => {
  const ctx = context();
  ctx.action = {
    ...ctx.action,
    surface: "file_edit",
    syntactic: {
      operation: "patch",
      paths: ["src/a.ts"],
      raw: `-old${CR}\n+new`,
    },
  };
  const { rendered } = await render(ctx);
  const lines = rendered.split("\n");
  const at = lines.indexOf("  File edit content:");
  assert.ok(at > 0);
  assert.equal(lines[at + 1], "    -old␍");
  assert.equal(lines[at + 2], "    +new");
  assert.ok(!rendered.includes(CR));
  assert.ok(!rendered.includes(HIDDEN_CHARS_WARNING), "a CRLF line ending is structure");
});

test("a Go file edit (TABs, CRLF) renders its indentation visibly and does not warn", async () => {
  const ctx = context();
  ctx.action = {
    ...ctx.action,
    surface: "file_edit",
    syntactic: {
      operation: "write",
      paths: ["main.go"],
      raw: 'func main() {\n\tfmt.Println("hi")\n}',
    },
  };
  const { rendered } = await render(ctx);
  const lines = rendered.split("\n");
  const at = lines.indexOf("  File edit content:");
  assert.equal(lines[at + 2], '    →   fmt.Println("hi")');
  assert.doesNotMatch(rendered, RAW_CONTROL);
  assert.ok(!rendered.includes(HIDDEN_CHARS_WARNING));
});

test("a heredoc commit command prints as continuation lines and does not warn", async () => {
  const ctx = context({ summary: "commit the fix" });
  ctx.action = {
    ...ctx.action,
    syntactic: { raw: "git commit -m \"$(cat <<'EOF'\nfix: a thing\n\n\tdetail\nEOF\n)\"" },
  };
  const { rendered } = await render(ctx);
  const lines = rendered.split("\n");
  const at = lines.findIndex((l) => l.startsWith("  Action:"));
  assert.deepEqual(lines.slice(at, at + 6), [
    "  Action:     git commit -m \"$(cat <<'EOF'",
    "            │ fix: a thing",
    "            │ ",
    "            │ →   detail",
    "            │ EOF",
    '            │ )"',
  ]);
  assert.ok(!rendered.includes(HIDDEN_CHARS_WARNING));
});

test("an ESC/CR spoof on a later line of a multi-line command still warns", async () => {
  const ctx = context();
  ctx.action = { ...ctx.action, syntactic: { raw: `echo ok\n${SPOOF}` } };
  const { rendered } = await render(ctx);
  assert.ok(rendered.includes(`            │ ${SPOOF_ESCAPED}`));
  assert.doesNotMatch(rendered, RAW_CONTROL);
  assert.ok(rendered.includes(HIDDEN_CHARS_WARNING));
});

test("the escaped headline and the warning are the last lines before the prompt", async () => {
  const ctx = context();
  // A long multi-line command: the header warning and the Action line scroll far above.
  const filler = Array.from({ length: 120 }, (_, i) => `echo line ${String(i)}`).join("\n");
  ctx.action = { ...ctx.action, syntactic: { raw: `${SPOOF}\n${filler}` } };
  const { rendered } = await render(ctx);
  const lines = rendered.split("\n");
  assert.equal(lines.at(-1), HIDDEN_CHARS_WARNING);
  assert.ok(lines.at(-2)?.startsWith(`  Deciding on: ${SPOOF_ESCAPED}\\necho line 0`));
});

test("a variation selector after ASCII cannot make a divergent argv look identical", async () => {
  // `main` + VS-16 renders like `main`; the Argv divergence line must show the difference.
  const ctx = context();
  ctx.action = {
    ...ctx.action,
    syntactic: { raw: "git push origin main", argv: ["git", "push", "origin", "main\uFE0F"] },
  };
  const { rendered } = await render(ctx);
  assert.match(rendered, /^ {2}Argv:\s+git push origin main⟨U\+FE0F⟩$/m);
  assert.ok(rendered.includes(HIDDEN_CHARS_WARNING));
});

test("emoji, keycaps and CJK variation sequences render as-is without warning", async () => {
  const ctx = context({ summary: "ship it ⚠\uFE0F 1\uFE0F\u20E3 \u845B\u{E0100}" });
  ctx.action = { ...ctx.action, syntactic: { raw: "git status" } };
  const { rendered } = await render(ctx);
  assert.ok(rendered.includes("Summary:    ship it ⚠\uFE0F 1\uFE0F\u20E3 \u845B\u{E0100}"));
  assert.ok(!rendered.includes(HIDDEN_CHARS_WARNING));
});

test("display escaping never changes the request hash (display-only)", async () => {
  const ctx = context();
  const { wasm, prepared } = await render(ctx);
  assert.equal(prepared.requestHash, wasm.compute_request_hash(JSON.stringify(ctx), EXPIRES_AT));
  // The model is a rendering of the raw bytes; swapping it in is a different request.
  const displayed = { ...ctx, action: { ...ctx.action, syntactic: { raw: SPOOF_ESCAPED } } };
  assert.notEqual(
    prepared.requestHash,
    wasm.compute_request_hash(JSON.stringify(displayed), EXPIRES_AT),
  );
});

test("runWatch escapes relay-supplied text in log lines (malicious relay error)", async () => {
  const wasm = await loadWasm();
  const keyfile = paired(wasm);
  const dir = mkdtempSync(join(tmpdir(), "allw-display-"));
  const info = [];
  const warn = [];
  try {
    const keyfilePath = join(dir, "keyfile.json");
    writeKeyfile(keyfilePath, { ...keyfile, device_auth_token: "tok" });
    const listeners = { open: [], message: [], error: [], close: [] };
    const emit = (type, ev = {}) => listeners[type].forEach((l) => l(ev));
    queueMicrotask(() => {
      emit("open");
      emit("message", { data: JSON.stringify({ type: "error", error: `x${ESC}[2A${CR}y` }) });
      emit("message", { data: JSON.stringify({ type: "retract", request_id: `r${ESC}` }) });
      emit("close");
    });
    await runWatch(
      wasm,
      { keyfilePath },
      {
        connect: () => ({
          addEventListener: (type, l) => listeners[type].push(l),
          send() {},
          close() {},
        }),
        prompter: { decide: () => Promise.resolve(null) },
        log: { info: (l) => info.push(l), warn: (l) => warn.push(l) },
        now: () => NOW_MS,
      },
    );
    const all = [...info, ...warn].join("\n");
    assert.ok(!all.includes(ESC) && !all.includes(CR), "no raw control bytes in log output");
    assert.ok(warn.includes("Relay error: x\\x1b[2A\\ry"));
    assert.ok(info.includes("Request r\\x1b was retracted (resolved elsewhere)."));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("UAT: `watch` stdout/stderr bytes carry no raw ESC/CR for the #246 spoof", async () => {
  const driver = join(here, "fixtures", "watch-spoof-driver.mjs");
  const dir = mkdtempSync(join(tmpdir(), "allw-display-uat-"));
  try {
    const child = spawnSync(process.execPath, [driver, dir], {
      input: "d\n",
      timeout: 60_000,
    });
    assert.equal(child.status, 0, `driver failed: ${child.stderr.toString("utf8")}`);
    const stdout = child.stdout;
    const stderr = child.stderr;
    assert.equal(stdout.indexOf(0x1b), -1, "stdout contains no raw ESC (0x1b)");
    assert.equal(stdout.indexOf(0x0d), -1, "stdout contains no raw CR (0x0d)");
    assert.equal(stderr.indexOf(0x1b), -1, "stderr contains no raw ESC (0x1b)");
    assert.equal(stderr.indexOf(0x0d), -1, "stderr contains no raw CR (0x0d)");
    const text = stdout.toString("utf8");
    assert.ok(text.includes(SPOOF_ESCAPED), "the escaped real command is printed");
    const warningAt = text.lastIndexOf(HIDDEN_CHARS_WARNING);
    const promptAt = text.indexOf("Approve / Deny / Skip?");
    assert.ok(warningAt >= 0, "the hidden-character warning is printed");
    assert.ok(promptAt > warningAt, "the warning is printed above the prompt");
    // The request is 100+ lines long, so the header copy of the warning has scrolled away by the
    // time the human answers. A copy sits on the line directly above the prompt, after the
    // one-line headline.
    const beforePrompt = text.slice(0, promptAt).split("\n");
    assert.equal(beforePrompt.at(-2), HIDDEN_CHARS_WARNING, "warning is the line above the prompt");
    assert.ok(beforePrompt.at(-3)?.startsWith(`  Deciding on: ${SPOOF_ESCAPED}`));
    assert.match(text, /Sent denied verdict for req-display-uat\./);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * A hostile relay for the pairing UAT: `pairing/start` returns a code carrying a clear-screen
 * sequence, and `pairing/complete` fails with an error body that does the same.
 */
function startHostileRelay() {
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      if (req.url?.endsWith("/pairing/start")) {
        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            code: `ABC${ESC}[2J`,
            expires_at: EXPIRES_AT,
            pairing_auth_token: "pairing-token",
          }),
        );
        return;
      }
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: `boom${ESC}[2J${CR}all good \u202Eevil` }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${String(port)}`, close: () => server.close() });
    });
  });
}

/** Run the real CLI binary as a subprocess (async, so the in-process relay can answer). */
function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(here, "..", "dist", "cli.js"), ...args]);
    const out = [];
    const err = [];
    child.stdout.on("data", (chunk) => out.push(chunk));
    child.stderr.on("data", (chunk) => err.push(chunk));
    child.on("close", (status) => {
      resolve({ status, stdout: Buffer.concat(out), stderr: Buffer.concat(err) });
    });
  });
}

test("UAT: `pair` output and the fatal error line escape relay-supplied text", async () => {
  const relay = await startHostileRelay();
  const dir = mkdtempSync(join(tmpdir(), "allw-display-pair-"));
  try {
    const result = await runCli([
      "pair",
      "--keyfile",
      join(dir, "keyfile.json"),
      "--relay",
      relay.url,
      "--account",
      ACCOUNT_ID,
    ]);
    assert.equal(result.status, 1, "pairing fails on the relay error");
    for (const [name, bytes] of [
      ["stdout", result.stdout],
      ["stderr", result.stderr],
    ]) {
      assert.equal(bytes.indexOf(0x1b), -1, `${name} contains no raw ESC`);
      assert.equal(bytes.indexOf(0x0d), -1, `${name} contains no raw CR`);
      assert.doesNotMatch(bytes.toString("utf8"), RAW_BIDI_OR_INVISIBLE, `${name} has no raw bidi`);
    }
    assert.match(result.stdout.toString("utf8"), /code ABC\\x1b\[2J/);
    assert.match(
      result.stderr.toString("utf8"),
      /^allw-approver: .*boom\\x1b\[2J\\rall good ⟨U\+202E⟩evil$/m,
    );
  } finally {
    relay.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
