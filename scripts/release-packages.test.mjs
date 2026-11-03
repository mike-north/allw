/**
 * Tests for the npm release set and the release workflow's trusted-publishing shape.
 *
 * @see ../docs/releasing.md
 * @see https://docs.npmjs.com/trusted-publishers (OIDC needs `id-token: write`; the publisher is
 *      identified by repo + workflow filename + optional environment; `repository.url` must match)
 * @see https://docs.npmjs.com/staged-publishing (`npm stage publish`; maintainer approves with 2FA)
 * @see https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  CLAIM_ONLY_NAMES,
  PUBLISHED_PACKAGES,
  RELEASE_ENVIRONMENT,
  RELEASE_WORKFLOW_FILE,
  REPO_ROOT,
  TRUSTED_REPOSITORY,
  compareVersions,
  githubRepoOf,
  parseStageId,
  planEntry,
  publishAll,
  readManifest,
  releaseProblems,
  setVersion,
  stageArgs,
  tarballIntegrity,
  versionFromTag,
} from "./release-packages.mjs";

/** Every non-private workspace package (packages/* and examples/*, per pnpm-workspace.yaml). */
function publicWorkspacePackages() {
  const names = [];
  for (const group of ["packages", "examples"]) {
    for (const entry of readdirSync(join(REPO_ROOT, group), { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      let manifest;
      try {
        manifest = readManifest(join(group, entry.name));
      } catch {
        continue;
      }
      if (manifest.private !== true) names.push(manifest.name);
    }
  }
  return names.sort();
}

/** A throwaway repo root holding the given manifests (keyed by repo-relative dir). */
function fixtureRoot(manifests) {
  const root = mkdtempSync(join(tmpdir(), "allw-release-test-"));
  for (const [dir, manifest] of Object.entries(manifests)) {
    mkdirSync(join(root, dir), { recursive: true });
    writeFileSync(join(root, dir, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  }
  return root;
}

const goodManifest = (name, deps = {}) => ({
  name,
  version: "1.2.3",
  dependencies: deps,
  repository: { type: "git", url: "git+https://github.com/mike-north/allw.git" },
  publishConfig: { access: "public" },
});

test("the release set is exactly the non-private workspace packages", () => {
  assert.deepEqual(PUBLISHED_PACKAGES.map((p) => p.name).sort(), publicWorkspacePackages());
});

// `npx <bin>` outside a project resolves a registry package named after the bin, so every bin a
// published package declares must be claimed (and point back at the package that declares it).
test("claim-only names cover every published bin, and are never released", () => {
  const claims = new Map(CLAIM_ONLY_NAMES.map((c) => [c.name, c.pointsTo]));
  const published = new Set(PUBLISHED_PACKAGES.map((p) => p.name));
  // npm refuses bare `allw` as too similar to existing names, which blocks squatters equally, so
  // claiming it would fail on every run.
  assert.ok(!claims.has("allw"));
  for (const pkg of PUBLISHED_PACKAGES) {
    const bin = readManifest(pkg.dir).bin;
    const bins = typeof bin === "string" ? [pkg.name.split("/")[1]] : Object.keys(bin ?? {});
    for (const name of bins) {
      assert.equal(claims.get(name), pkg.name, `bin ${name} of ${pkg.name} must be claimed`);
    }
  }
  for (const { name, pointsTo } of CLAIM_ONLY_NAMES) {
    assert.ok(!published.has(name), `${name} is claim-only, so it must not be in the release set`);
    assert.ok(!name.startsWith("@"), `${name}: claims are for unscoped names`);
    assert.ok(published.has(pointsTo), `${name} points at ${pointsTo}, which is not released`);
  }
});

test("the real release set is releasable at its current lockstep version", () => {
  const version = readManifest(PUBLISHED_PACKAGES[0].dir).version;
  assert.deepEqual(releaseProblems(version), []);
});

test("releaseProblems rejects a dependency published after its dependent", () => {
  const packages = [
    { name: "@allw/hook", dir: "a" },
    { name: "@allw/sdk", dir: "b" },
  ];
  const root = fixtureRoot({
    a: goodManifest("@allw/hook", { "@allw/sdk": "workspace:*" }),
    b: goodManifest("@allw/sdk"),
  });
  try {
    const problems = releaseProblems("1.2.3", { root, packages });
    assert.equal(problems.length, 1);
    assert.match(problems[0], /depends on @allw\/sdk, which is published after it/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("releaseProblems rejects version drift, private, non-public access, foreign repo, unknown @allw dep", () => {
  const packages = [{ name: "@allw/sdk", dir: "a" }];
  const cases = [
    [{ ...goodManifest("@allw/sdk"), version: "1.2.4" }, /expected 1\.2\.3 \(lockstep\)/],
    [{ ...goodManifest("@allw/sdk"), private: true }, /is private/],
    [{ ...goodManifest("@allw/sdk"), publishConfig: {} }, /publishConfig\.access/],
    [
      {
        ...goodManifest("@allw/sdk"),
        repository: { url: "git+https://github.com/someone/fork.git" },
      },
      /repository\.url must point at github\.com\/mike-north\/allw/,
    ],
    [{ ...goodManifest("@allw/sdk"), name: "@allw/other" }, /expected @allw\/sdk/],
    [goodManifest("@allw/sdk", { "@allw/relay": "workspace:*" }), /not in the published set/],
  ];
  for (const [manifest, expected] of cases) {
    const root = fixtureRoot({ a: manifest });
    try {
      const problems = releaseProblems("1.2.3", { root, packages });
      assert.equal(problems.length, 1, `expected one problem, got ${JSON.stringify(problems)}`);
      assert.match(problems[0], expected);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

test("versionFromTag accepts v<x.y.z> and rejects prereleases and anything else", () => {
  assert.equal(versionFromTag("v0.1.0"), "0.1.0");
  // Prereleases need a non-latest dist-tag (npm refuses one without --tag); this workflow only
  // ever moves `latest` forward, so it refuses them up front.
  for (const bad of [
    "v1.2.3-rc.1",
    "0.1.0",
    "v0.1",
    "v1.2.3+build.5",
    "release-1.2.3",
    "",
    "v1.2.3\n",
  ]) {
    assert.throws(
      () => versionFromTag(bad),
      /not of the form/,
      `should reject ${JSON.stringify(bad)}`,
    );
  }
});

test("githubRepoOf extracts owner/repo from the forms npm accepts", () => {
  assert.equal(
    githubRepoOf({ url: "git+https://github.com/mike-north/allw.git" }),
    TRUSTED_REPOSITORY,
  );
  assert.equal(githubRepoOf("https://github.com/mike-north/allw"), TRUSTED_REPOSITORY);
  assert.equal(githubRepoOf({ url: "git@github.com:mike-north/allw.git" }), TRUSTED_REPOSITORY);
  assert.equal(githubRepoOf({ url: "https://gitlab.com/mike-north/allw.git" }), null);
  assert.equal(githubRepoOf(undefined), null);
});

test("setVersion bumps every published manifest in place and rejects non-semver", () => {
  const packages = [
    { name: "@allw/sdk", dir: "a" },
    { name: "@allw/hook", dir: "b" },
  ];
  const root = fixtureRoot({
    a: goodManifest("@allw/sdk"),
    b: goodManifest("@allw/hook", { "@allw/sdk": "workspace:*" }),
  });
  try {
    setVersion("2.0.0", { root, packages });
    for (const dir of ["a", "b"]) {
      const manifest = JSON.parse(readFileSync(join(root, dir, "package.json"), "utf8"));
      assert.equal(manifest.version, "2.0.0");
    }
    // workspace:* ranges are left for pnpm pack to rewrite.
    assert.equal(readManifest("b", root).dependencies["@allw/sdk"], "workspace:*");
    assert.throws(() => setVersion("2.0", { root, packages }), /not a plain semver/);
    assert.throws(() => setVersion("2.0.0-rc.1", { root, packages }), /not a plain semver/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("compareVersions orders releases above their prereleases", () => {
  assert.ok(compareVersions("0.1.0", "0.0.0-bootstrap.0") > 0);
  assert.ok(compareVersions("0.0.0-stage", "0.1.0") < 0);
  assert.ok(compareVersions("0.10.0", "0.9.9") > 0);
  assert.equal(compareVersions("1.2.3", "1.2.3"), 0);
  assert.ok(compareVersions("1.2.3", "1.2.3-rc.1") > 0);
});

/**
 * A packed release dir with one tarball of the given bytes, and a manifest recording `integrity`
 * (by default, those bytes' real sha512, as `packAll` writes it).
 */
function releaseDir(bytes = "tarball-bytes", { integrity } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "allw-release-dir-"));
  writeFileSync(join(dir, "allw-sdk-0.2.0.tgz"), bytes);
  const entries = [
    {
      name: "@allw/sdk",
      version: "0.2.0",
      file: "allw-sdk-0.2.0.tgz",
      integrity: integrity ?? `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
    },
  ];
  writeFileSync(join(dir, "release-manifest.json"), JSON.stringify(entries));
  return { dir, entry: entries[0] };
}

/**
 * A fake `npm view` over a registry of `{ versions, integrity }` per package (integrity keyed by
 * version). Unknown packages 404; `failWith` simulates an outage.
 */
function fakeView(registry, { failWith = null } = {}) {
  return (args) => {
    if (failWith) return { status: 1, stdout: "", stderr: failWith };
    const [, spec, field] = args;
    const at = spec.lastIndexOf("@");
    const name = at > 0 ? spec.slice(0, at) : spec;
    const version = at > 0 ? spec.slice(at + 1) : null;
    const pkg = registry[name];
    if (!pkg || (version && !pkg.versions.includes(version))) {
      return { status: 1, stdout: '{"error":{"code":"E404"}}', stderr: "npm error code E404" };
    }
    if (field === "versions") return { status: 0, stdout: JSON.stringify(pkg.versions) };
    if (field === "dist.integrity")
      return { status: 0, stdout: JSON.stringify(pkg.integrity[version]) };
    throw new Error(`unexpected npm view ${args.join(" ")}`);
  };
}

test("tarballIntegrity is the SRI sha512 of the file's exact bytes", () => {
  const { dir, entry } = releaseDir("abc");
  try {
    const expected = `sha512-${createHash("sha512").update("abc").digest("base64")}`;
    assert.equal(tarballIntegrity(join(dir, entry.file)), expected);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("planEntry stages a new highest version, and skips only an identical published tarball", () => {
  const { dir, entry } = releaseDir();
  try {
    const local = tarballIntegrity(join(dir, entry.file));
    const fresh = fakeView({
      "@allw/sdk": { versions: ["0.0.0-bootstrap.0", "0.1.0"], integrity: {} },
    });
    assert.equal(planEntry(entry, { dir, runNpm: fresh }), "stage");
    assert.equal(planEntry(entry, { dir, runNpm: fakeView({}) }), "stage", "brand-new package");
    const same = fakeView({ "@allw/sdk": { versions: ["0.2.0"], integrity: { "0.2.0": local } } });
    assert.equal(planEntry(entry, { dir, runNpm: same }), "skip");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Regression: the registry already holding `name@version` used to count as success whatever its
// contents, so a hostile or mismatched upload passed as a completed release.
test("planEntry fails hard when the published version has different contents", () => {
  const { dir, entry } = releaseDir();
  try {
    const other = fakeView({
      "@allw/sdk": { versions: ["0.2.0"], integrity: { "0.2.0": "sha512-c29tZXRoaW5nIGVsc2U=" } },
    });
    assert.throws(() => planEntry(entry, { dir, runNpm: other }), /DIFFERENT contents/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("planEntry refuses a backport, and fails closed on an unreadable registry", () => {
  const { dir, entry } = releaseDir();
  try {
    const newer = fakeView({ "@allw/sdk": { versions: ["0.3.0"], integrity: {} } });
    assert.throws(() => planEntry(entry, { dir, runNpm: newer }), /backports are not supported/);
    const down = fakeView({}, { failWith: "npm error code ECONNRESET" });
    assert.throws(() => planEntry(entry, { dir, runNpm: down }), /could not query the registry/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("stageArgs stages publicly under latest, with provenance (or as a dry run)", () => {
  assert.deepEqual(stageArgs("/t/a.tgz"), [
    "stage",
    "publish",
    "/t/a.tgz",
    "--access",
    "public",
    "--tag",
    "latest",
    "--provenance",
  ]);
  assert.equal(stageArgs("/t/a.tgz", { dryRun: true }).at(-1), "--dry-run");
});

test("parseStageId reads the id npm prints after staging", () => {
  const id = "0b9c3a52-8f1e-4c2d-9a7b-3e5f6a7b8c9d";
  assert.equal(parseStageId(`+ @allw/sdk@0.2.0 (staged with id ${id})\n`), id);
  assert.equal(parseStageId("+ @allw/sdk@0.2.0 (staged)\n"), null);
});

test("publishAll stages, records the approval commands, and never calls plain `npm publish`", () => {
  const { dir } = releaseDir();
  const summary = join(dir, "summary.md");
  const id = "0b9c3a52-8f1e-4c2d-9a7b-3e5f6a7b8c9d";
  const stageCalls = [];
  try {
    const staged = publishAll(dir, {
      runNpm: fakeView({}),
      runStage: (args) => {
        stageCalls.push(args);
        return { status: 0, stdout: `+ @allw/sdk@0.2.0 (staged with id ${id})\n` };
      },
      summaryFile: summary,
    });
    assert.equal(stageCalls.length, 1);
    assert.deepEqual(stageCalls[0].slice(0, 2), ["stage", "publish"]);
    assert.equal(staged[0].stageId, id);
    const text = readFileSync(summary, "utf8");
    assert.match(text, new RegExp(`npm stage approve ${id}`));
    // The summary is not evidence: it records the integrity and sends the maintainer to the
    // independent check before any approval.
    assert.ok(text.includes(staged[0].integrity), "summary lists the tarball's sha512");
    assert.match(text, /node scripts\/verify-staged-release\.mjs 0\.2\.0 --run /);
    assert.ok(
      text.indexOf("verify-staged-release") < text.indexOf("npm stage approve"),
      "verify comes before approve",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("publishAll plans everything before staging anything, so one mismatch stages nothing", () => {
  const { dir } = releaseDir();
  const stageCalls = [];
  try {
    const mismatch = fakeView({
      "@allw/sdk": { versions: ["0.2.0"], integrity: { "0.2.0": "sha512-b3RoZXI=" } },
    });
    assert.throws(
      () => publishAll(dir, { runNpm: mismatch, runStage: (a) => stageCalls.push(a) }),
      /DIFFERENT contents/,
    );
    assert.deepEqual(stageCalls, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("publishAll refuses a tarball whose bytes differ from release-manifest.json", () => {
  for (const integrity of ["sha512-b3RoZXI=", null]) {
    const { dir } = releaseDir("tarball-bytes", { integrity: integrity ?? undefined });
    const stageCalls = [];
    try {
      if (integrity === null) {
        const manifest = join(dir, "release-manifest.json");
        const entries = JSON.parse(readFileSync(manifest, "utf8"));
        delete entries[0].integrity;
        writeFileSync(manifest, JSON.stringify(entries));
      }
      assert.throws(
        () => publishAll(dir, { runNpm: fakeView({}), runStage: (a) => stageCalls.push(a) }),
        integrity ? /does not match release-manifest\.json/ : /no sha512 integrity/,
      );
      assert.deepEqual(stageCalls, []);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("publishAll fails if npm reports no stage id", () => {
  const { dir } = releaseDir();
  try {
    assert.throws(
      () =>
        publishAll(dir, {
          runNpm: fakeView({}),
          runStage: () => ({ status: 0, stdout: "+ @allw/sdk@0.2.0\n" }),
          summaryFile: join(dir, "s.md"),
        }),
      /did not report a stage id/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("release.yml only stages, via OIDC from the trusted identity, with no token", () => {
  // Assert on the YAML itself, not its explanatory comments.
  const workflow = readFileSync(
    join(REPO_ROOT, ".github", "workflows", RELEASE_WORKFLOW_FILE),
    "utf8",
  )
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");
  const [buildJob, stageJob] = workflow.split(/^ {2}stage:$/m);
  assert.ok(stageJob, "release.yml must have a `stage` job");

  // Deliberate triggers only: a v* tag push or a manual dispatch. Never PR / comment events, which
  // npm refuses for trusted publishing and which would let untrusted input reach the stage job.
  assert.match(workflow, /^ {4}tags: \["v\*"\]$/m);
  assert.match(workflow, /^ {2}workflow_dispatch:/m);
  assert.doesNotMatch(workflow, /pull_request|issue_comment|pull_request_target/);

  // Default token is read-only; only the stage job can mint an OIDC token.
  assert.match(buildJob, /^permissions:\n {2}contents: read$/m);
  assert.doesNotMatch(buildJob, /id-token/);
  assert.match(stageJob, /^ {6}id-token: write$/m);

  // The environment npm is told to trust is the one the job runs in.
  assert.match(stageJob, new RegExp(`^ {4}environment: ${RELEASE_ENVIRONMENT}$`, "m"));
  assert.match(stageJob, /^ {4}if: startsWith\(github\.ref, 'refs\/tags\/v'\)$/m);

  // No long-lived npm credential, and no direct `npm publish` anywhere: CI only stages.
  assert.doesNotMatch(workflow, /NPM_TOKEN|NODE_AUTH_TOKEN|_authToken|secrets\./);
  assert.doesNotMatch(workflow, /npm publish/);

  // `npm stage` needs npm >= 11.15.0, and the token-holding job pins an exact version.
  const pinned = /npm install -g npm@(\d+)\.(\d+)\.(\d+)$/m.exec(stageJob);
  assert.ok(pinned, "the stage job installs an exactly pinned npm");
  assert.ok(Number(pinned[1]) > 11 || (Number(pinned[1]) === 11 && Number(pinned[2]) >= 15));
  assert.match(stageJob, /release-packages\.mjs publish dist-release$/m);

  // The smoke test runs on exactly the tarballs that are staged: pack first, then smoke them.
  const pack = buildJob.indexOf("release-packages.mjs pack dist-release");
  const smoke = buildJob.indexOf("smoke-packaged-install.mjs --tarballs dist-release");
  assert.ok(pack >= 0 && smoke > pack, "pack, then smoke the packed tarballs");
});
