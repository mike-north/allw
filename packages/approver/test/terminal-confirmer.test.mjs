/**
 * The `vouch` confirmation prompt (#381): only an explicit `y` / `yes` submitted with Enter
 * confirms, and every way the question ends without one is "not confirmed", which `runVouch`
 * turns into a non-zero exit with nothing signed.
 *
 * Regression for review-387 F2: typing `y` with no Enter and then closing the terminal left the
 * question pending forever, so Node exited 0 with nothing published and a wrapper read success.
 *
 * The streams are in-memory; the confirmer runs readline in terminal mode, as it does on the TTY
 * `vouch` requires, so a line counts only when Enter submits it.
 *
 * @see https://nodejs.org/api/readline.html#rlquestionquery-options
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";

import { createTerminalConfirmer } from "../dist/lib/terminal-confirmer.js";

/** A question that never settles is the bug under test: fail fast instead of hanging. */
const SETTLES = { timeout: 5_000 };

function terminal() {
  const input = new PassThrough();
  const output = new PassThrough();
  output.resume(); // discard the prompt and echo
  const confirmer = createTerminalConfirmer({ input, output, interactive: true });
  return { input, confirmer };
}

/** Ask, then feed `typed` and optionally end the input; resolve with the answer. */
async function ask(typed, { end = false } = {}) {
  const { input, confirmer } = terminal();
  const answer = confirmer.confirm("vouch? [y/N] ");
  input.write(typed);
  if (end) input.end();
  try {
    return await answer;
  } finally {
    confirmer.close();
  }
}

test("y or yes submitted with Enter confirms", async () => {
  assert.equal(await ask("y\r"), true);
  assert.equal(await ask("  YES \r"), true);
});

test("anything else submitted with Enter does not confirm", async () => {
  assert.equal(await ask("\r"), false);
  assert.equal(await ask("n\r"), false);
  assert.equal(await ask("yep\r"), false);
});

test(
  "y typed without Enter, then the terminal closes: not confirmed (review-387 F2)",
  SETTLES,
  async () => {
    assert.equal(await ask("y", { end: true }), false);
  },
);

test("the terminal closes with nothing typed: not confirmed", SETTLES, async () => {
  assert.equal(await ask("", { end: true }), false);
});

test("a question asked after the confirmer closed is not confirmed", async () => {
  const { confirmer } = terminal();
  confirmer.close();
  assert.equal(await confirmer.confirm("vouch? [y/N] "), false);
});

test("interactive reports what the caller decided", () => {
  const confirmer = createTerminalConfirmer({
    input: new PassThrough(),
    output: new PassThrough(),
    interactive: false,
  });
  assert.equal(confirmer.interactive, false);
});
