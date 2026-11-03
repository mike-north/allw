/**
 * Unit tests for `writeAllSync`, the full-write loop behind the hook's deny-only output.
 *
 * `fs.writeSync` may write fewer bytes than asked, or throw `EAGAIN` on a full non-blocking pipe. A
 * truncated decision line is invalid JSON, which Claude Code and Codex treat as a non-blocking error
 * (the tool call goes ahead), so a deny must go out in full.
 *
 * @see https://nodejs.org/api/fs.html#fswritesyncfd-buffer-offset-length-position
 * @see https://code.claude.com/docs/en/hooks#exit-code-output
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { writeAllSync } from "../dist/lib/decision-output.js";

/** A fake `writeSync` that writes at most `chunk` bytes per call and can throw scripted errors. */
function fakeWriter({ chunk, errors = [] }) {
  const written = [];
  let calls = 0;
  const write = (_fd, buffer, offset, length) => {
    const scripted = errors[calls++];
    if (scripted !== undefined) throw Object.assign(new Error(scripted), { code: scripted });
    const n = Math.min(chunk, length);
    written.push(...buffer.subarray(offset, offset + n));
    return n;
  };
  return { write, written: () => Buffer.from(written).toString("utf8") };
}

test("short writes: every byte is written, in order", () => {
  const { write, written } = fakeWriter({ chunk: 3 });
  writeAllSync(1, Buffer.from('{"deny":true}\n'), write);
  assert.equal(written(), '{"deny":true}\n');
});

test("EAGAIN: the write is retried until it goes through", () => {
  const { write, written } = fakeWriter({ chunk: 4, errors: ["EAGAIN", undefined, "EAGAIN"] });
  writeAllSync(1, Buffer.from("abcdefghij"), write);
  assert.equal(written(), "abcdefghij");
});

test("any other error (e.g. EPIPE) is thrown, not retried", () => {
  const { write } = fakeWriter({ chunk: 4, errors: ["EPIPE"] });
  assert.throws(() => writeAllSync(1, Buffer.from("abc"), write), { code: "EPIPE" });
});
