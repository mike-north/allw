/**
 * Tests for the npm release set and the release workflow's trusted-publishing shape.
 *
 * @see ../docs/releasing.md
 * @see https://docs.npmjs.com/trusted-publishers (OIDC needs `id-token: write`; the publisher is
 *      identified by repo + workflow filename + optional environment; `repository.url` must match)
 * @see https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
 */

import assert from "node:assert/strict";
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
  githubRepoOf,
  isPublished,
  readManifest,
  releaseProblems,
  setVersion,
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
test("claim-only names cover `allw` and every published bin, and are never released", () => {
  const claims = new Map(CLAIM_ONLY_NAMES.map((c) => [c.name, c.pointsTo]));
  const published = new Set(PUBLISHED_PACKAGES.map((p) => p.name));
  assert.equal(claims.get("allw"), "@allw/sdk");
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

test("versionFromTag accepts v<semver> and rejects anything else", () => {
  assert.equal(versionFromTag("v0.1.0"), "0.1.0");
  assert.equal(versionFromTag("v1.2.3-rc.1"), "1.2.3-rc.1");
  for (const bad of ["0.1.0", "v0.1", "v1.2.3+build.5", "release-1.2.3", "", "v1.2.3\n"]) {
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
    assert.throws(() => setVersion("2.0", { root, packages }), /not a semver/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("isPublished: version present → true, registry 404 → false, any other failure throws", () => {
  const reply =
    (status, stdout, stderr = "") =>
    () => ({ status, stdout, stderr });
  assert.equal(isPublished("@allw/sdk", "0.1.0", reply(0, '"0.1.0"\n')), true);
  // Package exists, but this version does not: npm prints nothing and exits 0.
  assert.equal(isPublished("@allw/sdk", "0.1.0", reply(0, "")), false);
  assert.equal(isPublished("@allw/sdk", "0.1.0", reply(1, '{"error":{"code":"E404"}}')), false);
  assert.throws(
    () => isPublished("@allw/sdk", "0.1.0", reply(1, "", "npm error code ECONNRESET")),
    /could not query the registry/,
  );
});

test("release.yml publishes via OIDC from the trusted identity, with no token", () => {
  // Assert on the YAML itself, not its explanatory comments.
  const workflow = readFileSync(
    join(REPO_ROOT, ".github", "workflows", RELEASE_WORKFLOW_FILE),
    "utf8",
  )
    .split("\n")
    .filter((line) => !/^\s*#/.test(line))
    .join("\n");
  const [buildJob, publishJob] = workflow.split(/^ {2}publish:$/m);
  assert.ok(publishJob, "release.yml must have a `publish` job");

  // Deliberate triggers only: a v* tag push or a manual dispatch. Never PR / comment events, which
  // npm refuses for trusted publishing and which would let untrusted input reach a publish job.
  assert.match(workflow, /^ {4}tags: \["v\*"\]$/m);
  assert.match(workflow, /^ {2}workflow_dispatch:/m);
  assert.doesNotMatch(workflow, /pull_request|issue_comment|pull_request_target/);

  // Default token is read-only; only the publish job can mint an OIDC token.
  assert.match(buildJob, /^permissions:\n {2}contents: read$/m);
  assert.doesNotMatch(buildJob, /id-token/);
  assert.match(publishJob, /^ {6}id-token: write$/m);

  // The environment npm is told to trust is the one the job runs in.
  assert.match(publishJob, new RegExp(`^ {4}environment: ${RELEASE_ENVIRONMENT}$`, "m"));
  assert.match(publishJob, /^ {4}if: startsWith\(github\.ref, 'refs\/tags\/v'\)$/m);

  // No long-lived npm credential anywhere.
  assert.doesNotMatch(workflow, /NPM_TOKEN|NODE_AUTH_TOKEN|_authToken|secrets\./);

  // npm >= 11.5.1 is required for OIDC publish.
  assert.match(publishJob, /npm install -g npm@\^11\.5\.1/);
  assert.match(publishJob, /release-packages\.mjs publish dist-release$/m);
});
