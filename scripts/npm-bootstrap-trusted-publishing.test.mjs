/**
 * Tests for the npm trusted-publishing bootstrap, driven through a fake `npm` so no registry, login,
 * or network is involved. The central guarantees: `--dry-run` never writes, every write is gated on
 * a confirmation, re-runs are no-ops once configured, and unreadable state fails closed.
 *
 * @see ../docs/releasing.md
 * @see https://docs.npmjs.com/trusted-publishers
 * @see https://docs.npmjs.com/cli/v11/commands/npm-trust (`--file`, `--repo`, `--env`,
 *      `--allow-stage-publish`, `--yes`, `--dry-run`; one trust config per package; package must
 *      exist)
 * @see https://docs.npmjs.com/staged-publishing (stage-only trust: CI stages, a maintainer approves)
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  PLACEHOLDER_TAG,
  PLACEHOLDER_VERSION,
  bootstrap,
  isExpectedTrust,
  parseTrustList,
  parseMaintainers,
  trustGithubArgs,
  versionAtLeast,
  writePlaceholder,
} from "./npm-bootstrap-trusted-publishing.mjs";
import {
  CLAIM_ONLY_NAMES,
  PUBLISHED_PACKAGES,
  RELEASE_ENVIRONMENT,
  RELEASE_WORKFLOW_FILE,
  TRUSTED_REPOSITORY,
} from "./release-packages.mjs";

const NAMES = PUBLISHED_PACKAGES.map((p) => p.name);
const CLAIMS = CLAIM_ONLY_NAMES.map((c) => c.name);

/** The trust config the release workflow needs, as `npm trust list --json` prints it. */
const EXPECTED_TRUST = {
  id: "trust-1",
  type: "github",
  file: RELEASE_WORKFLOW_FILE,
  repository: TRUSTED_REPOSITORY,
  environment: RELEASE_ENVIRONMENT,
  // Stage-only: the workflow may `npm stage publish`, never `npm publish` (npm's "createPackage").
  permissions: ["createStagedPackage"],
};

/**
 * A fake npm CLI over an in-memory registry. Records every call; `writes()` returns only the
 * mutating ones (publish / trust create / trust revoke, excluding npm's own --dry-run).
 */
function fakeNpm({
  npmVersion = "11.18.0",
  user = "mike-north",
  org = { "mike-north": "owner" },
  registry = {},
  failTrustCreate = false,
  viewError = null,
  maintainersError = false,
} = {}) {
  const calls = [];
  const placeholders = [];
  const ok = (stdout = "") => ({ status: 0, stdout, stderr: "" });
  const err = (stderr) => ({ status: 1, stdout: "", stderr });

  function npm(args, opts = {}) {
    calls.push({ args, interactive: Boolean(opts.interactive) });
    const [cmd, sub, name] = args;
    if (cmd === "--version") return ok(`${npmVersion}\n`);
    if (cmd === "whoami") return user ? ok(`${user}\n`) : err("npm error code ENEEDAUTH");
    if (cmd === "org") {
      return org === "404"
        ? err("npm error code E404\nnpm error 404 Not Found - Scope not found")
        : ok(JSON.stringify(org));
    }
    if (cmd === "profile")
      return ok(JSON.stringify({ tfa: { mode: "auth-and-writes", pending: false } }));
    if (cmd === "view") {
      if (viewError) return err(viewError);
      const pkg = registry[sub];
      if (!pkg) return err("npm error code E404\n404 Not Found");
      if (args[2] === "maintainers") {
        return maintainersError
          ? err("npm error code ECONNRESET")
          : ok(JSON.stringify(pkg.maintainers ?? [`${user} <${user}@example.test>`]));
      }
      return ok(JSON.stringify(pkg.versions));
    }
    if (cmd === "publish") {
      const manifest = JSON.parse(readFileSync(join(sub, "package.json"), "utf8"));
      placeholders.push({ manifest, args, hasIndex: existsSync(join(sub, "index.js")) });
      registry[manifest.name] = { versions: [manifest.version], trust: [] };
      return ok();
    }
    if (cmd === "trust" && sub === "list") {
      return ok((registry[name]?.trust ?? []).map((c) => JSON.stringify(c, null, 2)).join("\n"));
    }
    if (cmd === "trust" && sub === "github") {
      if (args.includes("--dry-run")) return ok();
      if (failTrustCreate) return err("npm error code E500");
      registry[name].trust = [{ ...EXPECTED_TRUST, id: `new-${name}` }];
      return ok();
    }
    if (cmd === "trust" && sub === "revoke") {
      const id = args.find((a) => a.startsWith("--id=")).slice(5);
      registry[name].trust = registry[name].trust.filter((c) => c.id !== id);
      return ok();
    }
    throw new Error(`unexpected npm call: ${args.join(" ")}`);
  }

  const writes = () =>
    calls.filter(
      ({ args }) =>
        (args[0] === "publish" ||
          (args[0] === "trust" && (args[1] === "github" || args[1] === "revoke"))) &&
        !args.includes("--dry-run"),
    );
  return { npm, calls, writes, placeholders, registry };
}

/** Run the bootstrap with captured log, a scripted confirm, and no real sleeping. */
async function run(fake, { dryRun = false, refreshTrust = false, answer = true } = {}) {
  const lines = [];
  const questions = [];
  const sleeps = [];
  const result = await bootstrap({
    dryRun,
    refreshTrust,
    npm: fake.npm,
    log: (line) => lines.push(line),
    confirm: async (q) => {
      questions.push(q);
      return typeof answer === "function" ? answer(q) : answer;
    },
    sleep: async (ms) => {
      sleeps.push(ms);
    },
  });
  return { ...result, out: lines.join("\n"), questions, sleeps };
}

/** A registry where every release package is trusted and every claim-only name is ours. */
const configuredRegistry = () => ({
  ...Object.fromEntries(
    NAMES.map((n) => [n, { versions: ["0.1.0"], trust: [{ ...EXPECTED_TRUST }] }]),
  ),
  ...Object.fromEntries(CLAIMS.map((n) => [n, { versions: [PLACEHOLDER_VERSION], trust: [] }])),
});

/** The names a run passed to `npm trust` (any subcommand that changes state). */
const trustTargets = (fake) =>
  fake.calls
    .filter(({ args }) => args[0] === "trust" && args[1] !== "list")
    .map(({ args }) => args[2]);

test("not logged in → fails with the `npm login` fix and writes nothing", async () => {
  const fake = fakeNpm({ user: null });
  const { exitCode, out } = await run(fake);
  assert.equal(exitCode, 1);
  assert.match(out, /run `npm login`/);
  assert.deepEqual(fake.writes(), []);
});

test("missing @allw scope → fails with the org-creation fix and writes nothing", async () => {
  const fake = fakeNpm({ org: "404" });
  const { exitCode, out } = await run(fake);
  assert.equal(exitCode, 1);
  assert.match(out, /scope @allw does not exist/);
  assert.match(out, /https:\/\/www\.npmjs\.com\/org\/create/);
  assert.deepEqual(fake.writes(), []);
});

test("logged-in user who is not an org member → fails before any write", async () => {
  const fake = fakeNpm({ org: { someone: "owner" } });
  const { exitCode, out } = await run(fake);
  assert.equal(exitCode, 1);
  assert.match(out, /is not a member/);
  assert.deepEqual(fake.writes(), []);
});

test("npm older than 11.15.0 (no `npm trust`) → fails with the upgrade command", async () => {
  const fake = fakeNpm({ npmVersion: "11.5.1" });
  const { exitCode, out } = await run(fake);
  assert.equal(exitCode, 1);
  assert.match(out, /npm install -g npm@\^11\.15\.0/);
  assert.deepEqual(fake.writes(), []);
});

test("registry outage → fails closed rather than treating packages as missing", async () => {
  const fake = fakeNpm({ viewError: "npm error code ECONNRESET" });
  const { exitCode } = await run(fake);
  assert.equal(exitCode, 1);
  assert.deepEqual(fake.writes(), []);
});

test("--dry-run on a fresh registry reports the plan and writes nothing, without prompting", async () => {
  const fake = fakeNpm();
  const { exitCode, out, questions } = await run(fake, { dryRun: true });
  assert.equal(exitCode, 0);
  assert.deepEqual(fake.writes(), []);
  assert.deepEqual(questions, []);
  for (const name of [...NAMES, ...CLAIMS]) {
    assert.match(out, new RegExp(`\\[dry-run\\] npm publish <placeholder for ${name}>`));
  }
  assert.match(out, /Re-run without --dry-run/);
  // The release is on hold: expiry is explained, and no tag push is demanded.
  assert.match(out, /No release is needed now/);
  assert.match(out, /--refresh-trust/);
  assert.doesNotMatch(out, /Cut the first real release/);
});

test("fresh registry: placeholders then trusted publishers, in release order, after confirmation", async () => {
  const fake = fakeNpm();
  const { exitCode, questions, sleeps, out } = await run(fake);
  assert.equal(exitCode, 0);
  assert.equal(questions.length, 3, "one confirmation each: placeholders, trust, unscoped claims");

  const writes = fake.writes();
  const publishes = writes.filter(({ args }) => args[0] === "publish");
  const trusts = writes.filter(({ args }) => args[1] === "github");
  assert.deepEqual(
    fake.placeholders.map((p) => p.manifest.name),
    [...NAMES, ...CLAIMS],
    "release placeholders in dependency order, then the unscoped claims",
  );
  for (const p of fake.placeholders) {
    const claimOnly = CLAIMS.includes(p.manifest.name);
    assert.equal(p.manifest.version, PLACEHOLDER_VERSION);
    assert.deepEqual(p.args.slice(2), ["--access", "public", "--tag", PLACEHOLDER_TAG]);
    // A placeholder carries no package code, only a stub that points at the real package. A
    // claim-only name also gets a same-named bin, so `npx <name>` hits the stub too.
    assert.deepEqual(p.manifest.bin, claimOnly ? { [p.manifest.name]: "index.js" } : undefined);
    assert.equal(p.manifest.dependencies, undefined);
    assert.equal(p.manifest.scripts, undefined);
    assert.equal(p.hasIndex, true);
  }
  for (const claim of CLAIMS) {
    assert.ok(!trustTargets(fake).includes(claim), `${claim} must not get a trusted publisher`);
  }
  assert.ok(
    publishes.every((c) => c.interactive),
    "publishes run attached to the terminal (2FA)",
  );

  assert.deepEqual(
    trusts.map(({ args }) => args),
    NAMES.map((n) => trustGithubArgs(n)),
  );
  assert.deepEqual(trustGithubArgs("@allw/sdk"), [
    "trust",
    "github",
    "@allw/sdk",
    "--file",
    "release.yml",
    "--repo",
    "mike-north/allw",
    "--env",
    "npm-publish",
    "--allow-stage-publish",
    "--yes",
  ]);
  assert.equal(sleeps.length, NAMES.length - 1, "trust calls are paced");
  assert.match(out, /npm deprecate "@allw\/sdk@0\.0\.0-bootstrap\.0"/);
});

test("re-run when everything is configured is a no-op: no writes, no prompts", async () => {
  const fake = fakeNpm({ registry: configuredRegistry() });
  const { exitCode, questions } = await run(fake);
  assert.equal(exitCode, 0);
  assert.deepEqual(fake.writes(), []);
  assert.deepEqual(questions, []);
});

test("a mismatched trust config is revoked and replaced, only after confirmation", async () => {
  const registry = configuredRegistry();
  registry["@allw/hook"].trust = [{ ...EXPECTED_TRUST, id: "old", environment: "production" }];
  const fake = fakeNpm({ registry });
  const { exitCode } = await run(fake);
  assert.equal(exitCode, 0);
  assert.deepEqual(
    fake.writes().map(({ args }) => args.slice(0, 4)),
    [
      ["trust", "revoke", "@allw/hook", "--id=old"],
      ["trust", "github", "@allw/hook", "--file"],
    ],
  );
});

// Regression: the first bootstrap created direct-publish (`--allow-publish`) configs, which let the
// tag workflow make a version public with no human approval. A re-run must replace them.
test("a direct-publish trust config is revoked and replaced with a stage-only one", async () => {
  const registry = configuredRegistry();
  for (const name of NAMES) {
    registry[name].trust = [
      { ...EXPECTED_TRUST, id: `direct-${name}`, permissions: ["createPackage"] },
    ];
  }
  const fake = fakeNpm({ registry });
  const { exitCode } = await run(fake);
  assert.equal(exitCode, 0);
  const writes = fake.writes().map(({ args }) => args);
  for (const name of NAMES) {
    assert.ok(
      writes.some((a) => a.join(" ") === `trust revoke ${name} --id=direct-${name}`),
      `revokes the direct-publish config on ${name}`,
    );
    const create = writes.find((a) => a[0] === "trust" && a[1] === "github" && a[2] === name);
    assert.ok(create?.includes("--allow-stage-publish"), `recreates ${name} stage-only`);
    assert.ok(!create.includes("--allow-publish"));
  }
});

test("declining the confirmations writes nothing", async () => {
  const fake = fakeNpm();
  const { out } = await run(fake, { answer: false });
  assert.deepEqual(fake.writes(), []);
  assert.match(out, /skipped \(declined\)/);
});

test("a failed `npm trust` falls back to exact npmjs.com instructions and exits non-zero", async () => {
  const registry = configuredRegistry();
  registry["@allw/sdk"].trust = [];
  const fake = fakeNpm({ registry, failTrustCreate: true });
  const { exitCode, out } = await run(fake);
  assert.equal(exitCode, 1);
  assert.match(out, /https:\/\/www\.npmjs\.com\/package\/@allw\/sdk\/access/);
  assert.match(out, /Workflow filename: {4}release\.yml/);
  assert.match(out, /Environment name: {5}npm-publish/);
});

test("parseTrustList handles npm's empty, single and concatenated --json output", () => {
  assert.deepEqual(parseTrustList(""), []);
  assert.deepEqual(parseTrustList(JSON.stringify(EXPECTED_TRUST, null, 2)), [EXPECTED_TRUST]);
  const two = [EXPECTED_TRUST, { ...EXPECTED_TRUST, id: "b" }];
  assert.deepEqual(parseTrustList(two.map((c) => JSON.stringify(c, null, 2)).join("\n")), two);
  assert.deepEqual(parseTrustList(JSON.stringify(two)), two);
});

test("isExpectedTrust rejects any identity or permission that differs from the release workflow", () => {
  assert.equal(isExpectedTrust(EXPECTED_TRUST), true);
  for (const change of [
    { type: "gitlab" },
    { repository: "someone/fork" },
    { file: "ci.yml" },
    { environment: undefined },
    { environment: "production" },
    // Anything that can publish directly is wrong, even alongside staging.
    { permissions: ["createPackage"] },
    { permissions: ["createPackage", "createStagedPackage"] },
    { permissions: [] },
    { permissions: undefined },
  ]) {
    assert.equal(isExpectedTrust({ ...EXPECTED_TRUST, ...change }), false, JSON.stringify(change));
  }
});

test("versionAtLeast compares numerically, not lexically", () => {
  assert.equal(versionAtLeast("11.15.0", "11.15.0"), true);
  assert.equal(versionAtLeast("11.18.0", "11.15.0"), true);
  assert.equal(versionAtLeast("12.0.0", "11.15.0"), true);
  assert.equal(versionAtLeast("11.5.1", "11.15.0"), false);
  assert.equal(versionAtLeast("11.9.9", "11.15.0"), false);
});

test("--dry-run also previews the unscoped claims, and never attaches trust to them", async () => {
  const fake = fakeNpm();
  await run(fake, { dryRun: true });
  for (const claim of CLAIMS) {
    assert.ok(!trustTargets(fake).includes(claim), `${claim} must not get a trusted publisher`);
  }
  assert.deepEqual(fake.writes(), []);
});

test("an unscoped name someone else owns is reported, not published over", async () => {
  const registry = configuredRegistry();
  registry["allw-hook"] = {
    versions: ["9.9.9"],
    trust: [],
    maintainers: ["mallory <m@example.test>"],
  };
  const fake = fakeNpm({ registry });
  const { exitCode, out, claimRows } = await run(fake);
  assert.equal(exitCode, 0);
  assert.deepEqual(fake.writes(), []);
  assert.equal(claimRows.find((r) => r.name === "allw-hook").placeholder, "TAKEN by mallory");
  assert.match(out, /belong to someone else[\s\S]*allw-hook \(mallory\)/);
});

test("declining only the claim prompt still reserves the release packages", async () => {
  const fake = fakeNpm();
  const { claimRows } = await run(fake, { answer: (q) => !/unscoped/.test(q) });
  assert.deepEqual(
    fake.placeholders.map((p) => p.manifest.name),
    NAMES,
  );
  assert.ok(claimRows.every((r) => r.placeholder === "skipped (declined)"));
});

test("unreadable claim-name maintainers → fails closed and claims nothing", async () => {
  const registry = configuredRegistry();
  delete registry.allw;
  const fake = fakeNpm({ registry, maintainersError: true });
  const { exitCode } = await run(fake);
  assert.equal(exitCode, 1);
  assert.deepEqual(fake.writes(), []);
});

test("--refresh-trust revokes and recreates every trust config, after one confirmation", async () => {
  const fake = fakeNpm({ registry: configuredRegistry() });
  const { exitCode, questions, out } = await run(fake, { refreshTrust: true });
  assert.equal(exitCode, 0);
  assert.equal(questions.length, 1);
  assert.deepEqual(
    fake.writes().map(({ args }) => args.slice(0, 3)),
    NAMES.flatMap((n) => [
      ["trust", "revoke", n],
      ["trust", "github", n],
    ]),
  );
  assert.match(out, /Push the release tag within 48 hours/);
  assert.doesNotMatch(out, /No release is needed now/);
});

test("claim-only placeholder: importing it and running its bin both throw a pointer to @allw", () => {
  const dir = writePlaceholder({ name: "allw-hook", pointsTo: "@allw/hook" });
  try {
    const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    assert.deepEqual(manifest.bin, { "allw-hook": "index.js" });
    assert.equal(manifest.publishConfig, undefined, "unscoped packages are public by default");
    const res = spawnSync(process.execPath, [join(dir, "index.js")], { encoding: "utf8" });
    assert.notEqual(res.status, 0);
    assert.match(res.stderr, /not an allw package[\s\S]*use @allw\/hook instead/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("release-package placeholder: no bin, scoped public access, import throws", () => {
  const dir = writePlaceholder({ name: "@allw/sdk", dir: "packages/sdk" });
  try {
    const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    assert.equal(manifest.bin, undefined);
    assert.deepEqual(manifest.publishConfig, { access: "public" });
    assert.equal(manifest.repository.directory, "packages/sdk");
    const res = spawnSync(process.execPath, [join(dir, "index.js")], { encoding: "utf8" });
    assert.notEqual(res.status, 0);
    assert.match(res.stderr, /empty name-reservation placeholder/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("parseMaintainers reads both shapes npm prints", () => {
  assert.deepEqual(parseMaintainers('["mike-north <m@example.test>", "other <o@example.test>"]'), [
    "mike-north",
    "other",
  ]);
  assert.deepEqual(parseMaintainers('[{"name":"mike-north","email":"m@example.test"}]'), [
    "mike-north",
  ]);
  assert.deepEqual(parseMaintainers('"solo <s@example.test>"'), ["solo"]);
});
