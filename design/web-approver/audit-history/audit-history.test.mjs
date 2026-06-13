import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

async function read(name) {
  return readFile(join(here, name), "utf8");
}

test("audit history prototype wires shared tokens and React canvas", async () => {
  const html = await read("Allw Approver Audit History.html");

  assert.match(html, /..\/inbox\/tokens\.css/, "prototype must reuse the inbox token source");
  assert.match(html, /app\.css/, "prototype must load local audit styling");
  assert.match(html, /app\.jsx/, "prototype must load the interactive audit canvas");
  assert.match(html, /id="root"/, "prototype must expose a React mount point");
});

test("audit history prototype covers required issue #95 surfaces", async () => {
  const app = await read("app.jsx");

  for (const requiredCopy of [
    "Timeline of decisions",
    "Decision detail",
    "Audit chain verified",
    "Broken chain",
    "Export slice",
    "WYSIWYS render",
  ]) {
    assert.match(app, new RegExp(requiredCopy, "i"), `missing audit copy: ${requiredCopy}`);
  }

  for (const filter of ["actor", "surface", "decision", "date"]) {
    assert.match(app, new RegExp(`${filter}: \\[`), `missing filter: ${filter}`);
  }
});

test("audit history prototype models verified and unverifiable entries distinctly", async () => {
  const app = await read("app.jsx");

  assert.match(app, /chainStatus:\s*"verified"/, "must include a verified chain state");
  assert.match(app, /chainStatus:\s*"broken"/, "must include a broken chain state");
  assert.match(app, /origin:\s*"verified"/, "must include verified origin evidence");
  assert.match(app, /origin:\s*"unverifiable"/, "must include unverifiable origin evidence");
  assert.match(
    app,
    /unapprovable|fail-closed/i,
    "unverifiable history must use fail-closed language",
  );
});

test("flow notes document audit trust behavior and export scope", async () => {
  const notes = await read("flow-notes.md");

  for (const heading of [
    "Timeline of decisions",
    "Decision detail",
    "Chain integrity cue",
    "Export affordance",
  ]) {
    assert.match(notes, new RegExp(`## ${heading}`), `missing flow note section: ${heading}`);
  }

  assert.match(notes, /read-only/i, "notes must keep audit history read-only");
  assert.match(notes, /tamper-evident/i, "notes must describe the audit-chain trust model");
  assert.match(notes, /WYSIWYS/i, "notes must tie detail back to the request render");
});
