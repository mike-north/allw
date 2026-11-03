/**
 * Tests for the shared user-owned-file reader's error text. Paths come from the environment
 * (`HOME`, `ALLW_CONFIG`), and a `UserFileError` message can reach the agent through a hook's deny
 * reason, so a control character in the path is shown escaped (#358). The error's `path` keeps the
 * raw value for callers that need it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { readUserOwnedFile, UserFileError } from "../dist/user-file.js";

test(
  "a UserFileError for a path with a newline or ESC shows the path escaped, keeps it raw on .path",
  { skip: process.platform === "win32" },
  () => {
    const path = join(mkdtempSync(join(tmpdir(), "allw-user-file-")), "a\nb\u001b[31m");
    mkdirSync(path); // a directory: refused as not a regular file
    assert.throws(
      () => readUserOwnedFile(path, 1024),
      (err) => {
        assert.ok(err instanceof UserFileError, String(err));
        assert.equal(err.problem.kind, "not_regular");
        assert.doesNotMatch(err.message, /[\u0000-\u001f\u007f]/, "no raw control characters");
        assert.match(err.message, /a\\u000ab\\u001b\[31m/, "shown escaped");
        assert.equal(err.path, path);
        return true;
      },
    );
  },
);
