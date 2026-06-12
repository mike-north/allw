import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

async function read(name) {
  return readFile(join(here, name), "utf8");
}

test("onboarding prototype wires the shared design tokens and React canvas", async () => {
  const html = await read("Allw Approver Onboarding.html");

  assert.match(html, /..\/inbox\/tokens\.css/, "prototype must reuse the inbox token source");
  assert.match(html, /app\.css/, "prototype must load its local app styling");
  assert.match(html, /app\.jsx/, "prototype must load the interactive onboarding canvas");
  assert.match(html, /id="root"/, "prototype must have a React mount point");
});

test("onboarding prototype covers the required first-run and returning-device flows", async () => {
  const app = await read("app.jsx");

  for (const requiredCopy of [
    "user-owned account root",
    "Recovery kit",
    "Pairing code",
    "Already paired",
    "copy hook config",
  ]) {
    assert.match(app, new RegExp(requiredCopy, "i"), `missing onboarding copy: ${requiredCopy}`);
  }

  for (const stateName of ["create", "pair", "returning", "empty"]) {
    assert.match(app, new RegExp(`id: "${stateName}"`), `missing flow state: ${stateName}`);
  }
});

test("empty state copy controls share a resilient copied-state handler", async () => {
  const app = await read("app.jsx");

  assert.match(app, /async function copyConfig\(\)/, "empty state must centralize copy behavior");
  assert.match(app, /setCopyStatus\("copied"\)/, "copy action must expose successful feedback");
  assert.equal(
    app.match(/onClick=\{copyConfig\}/g)?.length,
    2,
    "primary and snippet copy controls must call the same handler",
  );
});

test("flow notes document security intent and route-level behavior", async () => {
  const notes = await read("flow-notes.md");

  for (const heading of [
    "First-run account creation",
    "Device pairing ceremony",
    "Returning device login",
    "Paired empty state",
  ]) {
    assert.match(notes, new RegExp(`## ${heading}`), `missing flow note section: ${heading}`);
  }

  assert.match(notes, /trust ceremony/i, "notes must frame pairing as a trust ceremony");
  assert.match(notes, /E2EE|end-to-end encrypted/i, "notes must call out the E2EE story");
  assert.match(notes, /user-owned keys/i, "notes must explain user-owned keys");
});
