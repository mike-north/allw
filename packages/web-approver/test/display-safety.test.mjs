/**
 * Display-safety tests for the web approver (#246).
 *
 * The web approver writes request text with `textContent`, so HTML injection is already impossible —
 * but bidi overrides (U+202E, Trojan Source / CVE-2021-42574) and zero-width characters can still
 * reorder or hide what the human reads. These tests run the **real** path end to end: the context
 * is encrypted to the device, `createWasmRuntime` decrypts it and builds the view from the core's
 * `display_model`, and `mountWebApprover` renders it into a jsdom DOM. They assert that the escaped
 * form (not the raw control character) is what reaches the DOM, and that the warning badge shows.
 *
 * Expected escaped strings are written by hand from the notation in
 * `crates/allw-core/src/display.rs` (`⟨U+202E⟩`, `\x1b`), not captured from program output.
 *
 * @see https://www.unicode.org/reports/tr9/ §2 (explicit bidi formatting characters)
 * @see ../../../docs/threat-model.md R3 (WYSIWYS completeness)
 * @see ../../../docs/contract.md §Invariants #3 (WYSIWYS)
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { JSDOM } from "jsdom";

import { mountWebApprover } from "../dist/browser.js";
import { createWasmRuntime } from "../dist/index.js";
import { loadTestWasm } from "./wasm-helper.mjs";
import {
  ACCOUNT_ID,
  DEVICE_ID,
  NOW_MS,
  envelope,
  mountWith,
  pairedIdentity,
} from "./support/real-runtime.mjs";

const RLO = "\u202e";
const ZWSP = "\u200b";
// eslint-disable-next-line no-control-regex
const RAW_HIDDEN =
  /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/;

function context(syntactic, overrides = {}) {
  return {
    action: { record_schema_version: 3, surface: "command", syntactic, risk: "high" },
    summary: "open the invoice",
    actor: { id: "machine:laptop", kind: "claude-code" },

    reversible: false,
    constraints: { allowed_decisions: ["approved", "denied"], challenge_required: false },
    ...overrides,
  };
}

test("a U+202E bidi override renders escaped in the DOM with the warning badge (#246)", async () => {
  // Trojan-Source-style filename: displayed raw, `invoice\u202efdp.exe` reads as `invoiceexe.pdf`.
  const root = await mountWith([
    context({ argv: ["open", `invoice${RLO}fdp.exe`], raw: `open invoice${RLO}fdp.exe` }),
  ]);
  const text = root.textContent ?? "";
  assert.doesNotMatch(text, RAW_HIDDEN, "no raw bidi/control character reaches the DOM");
  assert.ok(text.includes("open invoice⟨U+202E⟩fdp.exe"), "the escaped form is in the DOM");
  const badge = root.querySelector(".hidden-chars-warning");
  assert.ok(badge, "the hidden-character warning badge is present");
  assert.match(badge.textContent ?? "", /hidden\/control characters/);
  assert.equal(badge.getAttribute("role"), "alert");
});

test("zero-width characters in the actor and cwd are escaped in the DOM", async () => {
  const root = await mountWith([
    context(
      { argv: ["ls"], raw: "ls", cwd: `/srv/${ZWSP}app` },
      {
        summary: `list files\u001b[2K`,
        actor: { id: `machine:${ZWSP}laptop`, kind: "claude-code" },
      },
    ),
  ]);
  const text = root.textContent ?? "";
  assert.doesNotMatch(text, RAW_HIDDEN);
  assert.ok(text.includes("cwd: /srv/⟨U+200B⟩app"));
  assert.ok(text.includes("machine:⟨U+200B⟩laptop (claude-code)"));
  assert.ok(root.querySelector(".hidden-chars-warning"));
});

test("MCP params with a bidi override are escaped in the DOM", async () => {
  const root = await mountWith([
    {
      ...context({}),
      action: {
        record_schema_version: 3,
        surface: "mcp_tool_call",
        syntactic: { server: "fs", tool: "write", params: { path: `/tmp/${RLO}txt.exe` } },
      },
    },
  ]);
  const text = root.textContent ?? "";
  assert.doesNotMatch(text, RAW_HIDDEN);
  assert.ok(text.includes(`"path": "/tmp/⟨U+202E⟩txt.exe"`));
  assert.ok(root.querySelector(".hidden-chars-warning"));
});

test("a clean request renders without the warning badge", async () => {
  const root = await mountWith([
    context({ argv: ["git", "status"], raw: "git status", cwd: "/repo" }),
  ]);
  assert.ok((root.textContent ?? "").includes("git status"));
  assert.equal(root.querySelector(".hidden-chars-warning"), null);
});

/** Run `fn` with jsdom globals installed for its whole (async) duration. */
async function withDom(fn) {
  const dom = new JSDOM('<div id="app"></div>', { url: "https://approver.local/" });
  const saved = {
    document: globalThis.document,
    window: globalThis.window,
    HTMLButtonElement: globalThis.HTMLButtonElement,
  };
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  globalThis.HTMLButtonElement = dom.window.HTMLButtonElement;
  try {
    return await fn(dom.window.document.getElementById("app"));
  } finally {
    globalThis.document = saved.document;
    globalThis.window = saved.window;
    globalThis.HTMLButtonElement = saved.HTMLButtonElement;
  }
}

const ESC = "\u001b";

test("a multi-line (heredoc) command shows its lines behind a continuation marker, no badge", async () => {
  const raw = "git commit -m \"$(cat <<'EOF'\nfix: a thing\n\n\tdetail\nEOF\n)\"";
  const root = await mountWith([context({ argv: ["git", "commit"], raw })]);
  const pre = root.querySelector("pre");
  assert.ok(pre);
  assert.ok(
    (pre.textContent ?? "").includes(
      "raw: git commit -m \"$(cat <<'EOF'\n   │ fix: a thing\n   │ \n   │ →   detail\n   │ EOF\n   │ )\"",
    ),
  );
  assert.equal(root.querySelector(".hidden-chars-warning"), null);
});

test("a relay-supplied envelope id in the verification-failed banner is escaped (#246)", async () => {
  // Already expired: the runtime refuses it with an error that names the (relay-supplied) id.
  const wasm = await loadTestWasm();
  const { identity, encryptTo } = pairedIdentity(wasm);
  const id = `req-${RLO}evil${ESC}[2J`;
  const stale = { ...envelope(id, encryptTo(context({ argv: ["ls"], raw: "ls" }))) };
  const expired = { ...stale, expires_at: NOW_MS - 1 };
  const text = await withDom(async (root) => {
    await mountWebApprover({
      root,
      nowMs: () => NOW_MS,
      fetchInbox: async () => [expired],
      runtime: createWasmRuntime({ wasm, identity, nowMs: () => NOW_MS }),
    });
    return root.textContent ?? "";
  });
  assert.doesNotMatch(text, RAW_HIDDEN, "no raw bidi/control character reaches the DOM");
  assert.ok(text.includes("Verification failed:"), "the card shows why it is unverified");
  assert.ok(text.includes("req-⟨U+202E⟩evil\\x1b[2J"), "the id is shown escaped");
});

test("the relay-outage banner escapes the relay error text (#246)", async () => {
  const wasm = await loadTestWasm();
  const { identity } = pairedIdentity(wasm);
  const text = await withDom(async (root) => {
    const mounted = await mountWebApprover({
      root,
      nowMs: () => NOW_MS,
      runtime: createWasmRuntime({ wasm, identity, nowMs: () => NOW_MS }),
      relay: {
        relayUrl: "https://relay.allw.test",
        accountId: ACCOUNT_ID,
        deviceId: DEVICE_ID,
        deviceAuthToken: "relay-bearer-test-token",
        fetchImpl: async () => {
          throw new Error(`relay down${ESC}[2J${RLO}evil`);
        },
      },
    });
    // Let the immediate first poll tick settle and re-render.
    for (let i = 0; i < 5; i += 1) await new Promise((r) => setTimeout(r, 0));
    mounted.stop();
    return root.querySelector(".relay-outage-banner")?.textContent ?? "";
  });
  assert.ok(text.includes("Relay unavailable"), "the outage banner is shown");
  assert.doesNotMatch(text, RAW_HIDDEN);
  assert.ok(text.includes("relay down\\x1b[2J⟨U+202E⟩evil"));
});

test("a tool call shows server :: tool, so a dotted server or tool name stays unambiguous", async () => {
  const call = (server, tool) => ({
    ...context({}),
    action: {
      record_schema_version: 3,
      surface: "mcp_tool_call",
      syntactic: { server, tool },
    },
  });
  const root = await mountWith([call("fs.delete", "x")]);
  const text = root.textContent ?? "";
  assert.ok(text.includes("mcp: fs.delete :: x"));
  assert.ok(!text.includes("fs :: delete.x"));
});
