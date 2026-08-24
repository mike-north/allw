/**
 * The reported version must come from `package.json`, never a hardcoded literal — a literal
 * silently drifts on every publish and makes "which build is the operator running?" unanswerable.
 */

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { getVersion } from "../dist/index.js";

test("getVersion reports this package's package.json version", () => {
  const pkg = JSON.parse(
    readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"),
  );
  assert.equal(getVersion(), pkg.version);
});

test("the reported version is not a placeholder literal", () => {
  assert.notEqual(getVersion(), "0.0.0");
  assert.match(getVersion(), /^\d+\.\d+\.\d+/);
});
