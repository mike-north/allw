/**
 * The npm release set and the release workflow's pack/stage steps.
 *
 * This module is the single source of truth for *which* `@allw/*` packages are released to npm,
 * *in what order*, and *under which trusted-publisher identity* (repo + workflow file + GitHub
 * environment). It also lists the unscoped names held only as anti-squatting claims and never
 * released (`CLAIM_ONLY_NAMES`). The CI release workflow (`.github/workflows/release.yml`), the
 * packaged-install smoke test, and the one-shot operator bootstrap
 * (`scripts/npm-bootstrap-trusted-publishing.mjs`) all import it, so the identity npm is told to trust
 * and the identity that actually publishes can never drift apart.
 *
 * **CI never publishes directly; it stages.** The trusted publisher is configured stage-only, so the
 * release workflow can only `npm stage publish`. A staged version stays private until a maintainer
 * approves it with npm 2FA (`npm stage approve <stage-id>`). That approval is the release gate: the
 * repo/workflow/environment binding alone is not, because anyone who can push to the repo can push a
 * tag or edit `release.yml`.
 *
 * Versioning is **lockstep** and **forward-only**: every released package carries the same plain
 * `x.y.z` version, higher than anything already on the registry, and a release is cut by pushing a
 * `v<version>` tag that must equal it. Prereleases and backports are refused, because npm needs an
 * explicit non-`latest` dist-tag for them and this workflow only ever moves `latest` forward.
 *
 * CLI (used by the release workflow; each command fails non-zero with a reason on any doubt):
 *
 *   node scripts/release-packages.mjs verify <tag>          check every manifest is releasable at <tag>
 *   node scripts/release-packages.mjs set-version <x.y.z>   bump every released manifest (lockstep)
 *   node scripts/release-packages.mjs pack <out-dir>        pnpm pack each package, in release order
 *   node scripts/release-packages.mjs publish <out-dir> [--dry-run]
 *                                                           npm stage publish each packed tarball, in
 *                                                           order, after checking the registry
 *
 * @see ../docs/releasing.md (the release process this implements)
 * @see https://docs.npmjs.com/trusted-publishers
 * @see https://docs.npmjs.com/staged-publishing
 */

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The GitHub repository npm trusts to stage releases (`owner/repo`); must match each `repository.url`. */
export const TRUSTED_REPOSITORY = "mike-north/allw";

/**
 * The workflow file (basename only, as npm's trusted-publisher config wants it) that stages releases.
 * npm validates the OIDC token's `workflow_ref` against this name.
 */
export const RELEASE_WORKFLOW_FILE = "release.yml";

/**
 * The GitHub Actions environment the staging job runs in. The trusted publisher is bound to it, so
 * only jobs in that environment can get a stage-capable OIDC token. Environment protection rules add
 * defense in depth, but the release gate is the maintainer's npm 2FA approval of each staged version.
 */
export const RELEASE_ENVIRONMENT = "npm-publish";

/** The npm scope every released package lives under. */
export const NPM_SCOPE = "@allw";

/** The only dist-tag this workflow applies. */
export const RELEASE_DIST_TAG = "latest";

/** Release tags: `v` + a plain `x.y.z` version (no prerelease, no build metadata). */
const TAG_PATTERN = /^v(\d+\.\d+\.\d+)$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;

/**
 * The released packages, **in dependency order** (every package appears after the workspace
 * packages it depends on). Staging in this order means the maintainer approves them in this order,
 * so a consumer never sees a released package whose `@allw/*` dependency at that exact version is
 * not yet public. Private packages (`@allw/relay`, `@allw/web-approver`, the examples) are deployed
 * or run from source and are never published.
 */
export const PUBLISHED_PACKAGES = Object.freeze([
  { name: "@allw/sdk", dir: "packages/sdk" },
  { name: "@allw/hook", dir: "packages/hook" },
  { name: "@allw/approver", dir: "packages/approver" },
  { name: "@allw/codex-hook", dir: "packages/codex-hook" },
  { name: "@allw/openclaw-bridge", dir: "packages/openclaw-bridge" },
]);

/**
 * Unscoped names we **claim but never release** ("claim-only"), so nobody else can squat them.
 *
 * Every bin of a released package is here, because `npx <bin>` run outside a project that has the
 * scoped package installed resolves a *registry package* of that bare name. A squatter publishing
 * `allw-hook` would get code execution from anyone who types `npx allw-hook`. Each claim holds an
 * inert placeholder whose import and bin throw an error naming `pointsTo`, the real scoped package.
 * No trusted publisher is attached: the release workflow never publishes these names.
 *
 * Bare `allw` is deliberately absent: npm refuses it as too similar to existing packages, which
 * blocks a squatter just as well.
 */
export const CLAIM_ONLY_NAMES = Object.freeze([
  { name: "allw-hook", pointsTo: "@allw/hook" },
  { name: "allw-approver", pointsTo: "@allw/approver" },
  { name: "allw-codex-hook", pointsTo: "@allw/codex-hook" },
  { name: "allw-openclaw-bridge", pointsTo: "@allw/openclaw-bridge" },
]);

/** Read a package's manifest (`dir` is repo-relative). */
export function readManifest(dir, root = REPO_ROOT) {
  return JSON.parse(readFileSync(join(root, dir, "package.json"), "utf8"));
}

/** Parse a release tag (`v1.2.3`) into its version, or throw. */
export function versionFromTag(tag) {
  const match = TAG_PATTERN.exec(tag);
  if (!match) {
    throw new Error(
      `release tag ${JSON.stringify(tag)} is not of the form v<major>.<minor>.<patch> ` +
        `(prerelease and build-metadata tags are not supported)`,
    );
  }
  return match[1];
}

/**
 * Compare two semver versions: negative if `a < b`, 0 if equal, positive if `a > b`. Handles the
 * registry's prerelease versions (e.g. `0.0.0-bootstrap.0`), which sort below their release.
 */
export function compareVersions(a, b) {
  const split = (v) => {
    const [core, ...pre] = String(v).split("-");
    return { nums: core.split(".").map((n) => Number.parseInt(n, 10) || 0), pre: pre.join("-") };
  };
  const x = split(a);
  const y = split(b);
  for (let i = 0; i < 3; i++) {
    if ((x.nums[i] ?? 0) !== (y.nums[i] ?? 0)) return (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
  }
  if (x.pre === y.pre) return 0;
  if (x.pre === "") return 1;
  if (y.pre === "") return -1;
  return x.pre < y.pre ? -1 : 1;
}

/** `owner/repo` from a package.json `repository` field, or `null` if it is not a GitHub URL. */
export function githubRepoOf(repository) {
  const url = typeof repository === "string" ? repository : repository?.url;
  if (typeof url !== "string") return null;
  const match = /github\.com[/:]([^/]+\/[^/.]+?)(?:\.git)?\/?$/.exec(url);
  return match ? match[1] : null;
}

/**
 * Every reason the release set cannot be released as `version`. Empty ⇔ releasable.
 *
 * Checks the properties npm's trusted publishing and our consumers depend on: each package is public,
 * named as listed, at the lockstep version, and points `repository.url` at the trusted repo (npm
 * rejects provenance when it differs); and the list is in dependency order.
 */
export function releaseProblems(version, { root = REPO_ROOT, packages = PUBLISHED_PACKAGES } = {}) {
  const problems = [];
  const positions = new Map(packages.map((p, i) => [p.name, i]));
  for (const [index, pkg] of packages.entries()) {
    const manifest = readManifest(pkg.dir, root);
    const where = `${pkg.dir}/package.json`;
    if (manifest.name !== pkg.name) {
      problems.push(`${where}: name is ${manifest.name}, expected ${pkg.name}`);
    }
    if (manifest.private === true) {
      problems.push(`${where}: is private and cannot be published`);
    }
    if (manifest.version !== version) {
      problems.push(`${where}: version is ${manifest.version}, expected ${version} (lockstep)`);
    }
    if (manifest.publishConfig?.access !== "public") {
      problems.push(`${where}: publishConfig.access must be "public" for a scoped package`);
    }
    const repo = githubRepoOf(manifest.repository);
    if (repo !== TRUSTED_REPOSITORY) {
      problems.push(
        `${where}: repository.url must point at github.com/${TRUSTED_REPOSITORY} (npm provenance requires it), got ${String(repo)}`,
      );
    }
    for (const dep of Object.keys(manifest.dependencies ?? {})) {
      if (!dep.startsWith(`${NPM_SCOPE}/`)) continue;
      const depIndex = positions.get(dep);
      if (depIndex === undefined) {
        problems.push(`${where}: depends on ${dep}, which is not in the published set`);
      } else if (depIndex > index) {
        problems.push(`${where}: depends on ${dep}, which is published after it`);
      }
    }
  }
  return problems;
}

/** Rewrite the `version` of every released manifest (lockstep bump), preserving formatting. */
export function setVersion(version, { root = REPO_ROOT, packages = PUBLISHED_PACKAGES } = {}) {
  if (!VERSION_PATTERN.test(version)) {
    throw new Error(`version ${JSON.stringify(version)} is not a plain semver x.y.z`);
  }
  for (const pkg of packages) {
    const file = join(root, pkg.dir, "package.json");
    const source = readFileSync(file, "utf8");
    // Rewrite in place (rather than re-serialising) so key order and formatting survive the bump.
    const updated = source.replace(/("version"\s*:\s*)"[^"]*"/, `$1"${version}"`);
    if (JSON.parse(updated).version !== version) {
      throw new Error(`${pkg.dir}/package.json: could not locate its top-level version field`);
    }
    writeFileSync(file, updated);
  }
}

/** Run a command, inheriting stderr; throw with context on a non-zero exit. */
function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
    ...opts,
  });
  if (res.status !== 0) {
    throw new Error(`command failed (exit ${String(res.status)}): ${cmd} ${args.join(" ")}`);
  }
  return res.stdout ?? "";
}

/**
 * `pnpm pack` every released package into `outDir`, in release order, and write
 * `outDir/release-manifest.json` (`[{ name, version, file }]`) for the smoke test and the stage step.
 * `pnpm pack` is what rewrites `workspace:*` dependencies to the exact sibling version.
 */
export function packAll(outDir, { root = REPO_ROOT, packages = PUBLISHED_PACKAGES } = {}) {
  const dest = resolve(outDir);
  mkdirSync(dest, { recursive: true });
  const entries = [];
  for (const pkg of packages) {
    const before = new Set(readdirSync(dest));
    run("pnpm", ["pack", "--pack-destination", dest], { cwd: join(root, pkg.dir) });
    const produced = readdirSync(dest).filter((f) => f.endsWith(".tgz") && !before.has(f));
    if (produced.length !== 1) {
      throw new Error(`expected exactly one tarball for ${pkg.name}, got ${produced.length}`);
    }
    entries.push({
      name: pkg.name,
      version: readManifest(pkg.dir, root).version,
      file: produced[0],
    });
    console.log(`packed ${pkg.name} → ${produced[0]}`);
  }
  writeFileSync(join(dest, "release-manifest.json"), `${JSON.stringify(entries, null, 2)}\n`);
  return entries;
}

/** Read `outDir/release-manifest.json`, the tarballs `packAll` produced, in release order. */
export function readReleaseManifest(outDir) {
  return JSON.parse(readFileSync(join(resolve(outDir), "release-manifest.json"), "utf8"));
}

/** The npm `dist.integrity` (SRI sha512) of a tarball's exact bytes. */
export function tarballIntegrity(file) {
  return `sha512-${createHash("sha512").update(readFileSync(file)).digest("base64")}`;
}

const is404 = (res) => /E404/.test(`${res.stdout}\n${res.stderr}`);

/** Every version of `name` on the registry (`[]` if the package does not exist); throws otherwise. */
export function registryVersions(name, runNpm = defaultNpm) {
  const res = runNpm(["view", name, "versions", "--json"]);
  if (res.status === 0) {
    const parsed = JSON.parse(res.stdout || "[]");
    return Array.isArray(parsed) ? parsed : [parsed];
  }
  if (is404(res)) return [];
  throw new Error(`could not query the registry for ${name}:\n${res.stderr}`);
}

/** The registry's `dist.integrity` for `name@version`; throws if it cannot be read. */
export function publishedIntegrity(name, version, runNpm = defaultNpm) {
  const res = runNpm(["view", `${name}@${version}`, "dist.integrity", "--json"]);
  const integrity = res.status === 0 ? JSON.parse(res.stdout || "null") : null;
  if (typeof integrity !== "string" || integrity === "") {
    throw new Error(`could not read the registry integrity of ${name}@${version}:\n${res.stderr}`);
  }
  return integrity;
}

/**
 * Decide what to do with one packed tarball, against the registry. Returns `"skip"` when exactly
 * this tarball is already published, `"stage"` when it should be staged under `latest`, and throws
 * (fail closed) when the registry holds *different* bytes at that version, or when the version
 * would not be the highest on the registry (a backport, which would move `latest` backwards).
 */
export function planEntry({ name, version, file }, { dir, runNpm = defaultNpm }) {
  const versions = registryVersions(name, runNpm);
  if (versions.includes(version)) {
    const remote = publishedIntegrity(name, version, runNpm);
    const local = tarballIntegrity(join(dir, file));
    if (remote !== local) {
      throw new Error(
        `${name}@${version} is already on the registry with DIFFERENT contents ` +
          `(registry ${remote}, local ${local}). Refusing to treat the release as done.`,
      );
    }
    return "skip";
  }
  const higher = versions.filter((v) => compareVersions(v, version) > 0);
  if (higher.length > 0) {
    throw new Error(
      `${name}@${version} is lower than ${higher.join(", ")} on the registry; backports are not ` +
        `supported (they would need a non-latest dist-tag).`,
    );
  }
  return "stage";
}

function defaultNpm(args) {
  return spawnSync("npm", args, { encoding: "utf8" });
}

/** Run `npm` with stdout captured (and echoed) so the stage id can be read back. */
function defaultStageNpm(args) {
  const res = spawnSync("npm", args, { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
  process.stdout.write(res.stdout ?? "");
  return { status: res.status ?? 1, stdout: res.stdout ?? "" };
}

/** The `npm stage publish` arguments for one tarball. */
export function stageArgs(tarball, { dryRun = false } = {}) {
  const args = ["stage", "publish", tarball, "--access", "public", "--tag", RELEASE_DIST_TAG];
  // Provenance is requested explicitly so a missing attestation fails the stage rather than
  // shipping silently; a dry run has no OIDC token to attest with.
  args.push(dryRun ? "--dry-run" : "--provenance");
  return args;
}

/** The stage id npm prints (`+ name@1.2.3 (staged with id <uuid>)`), or `null`. */
export function parseStageId(stdout) {
  return /staged with id ([0-9a-fA-F-]{36})/.exec(stdout)?.[1] ?? null;
}

/**
 * Stage every tarball listed in `outDir/release-manifest.json`, in order. Every entry is planned
 * against the registry **before** anything is staged, so a mismatch or backport anywhere stops the
 * whole release. Exact re-uploads are skipped, so re-running a partly failed release finishes it.
 * Auth is npm trusted publishing (GitHub OIDC); there is no token. Returns the staged entries with
 * their stage ids, and writes the approval commands to the GitHub job summary when there is one.
 */
export function publishAll(
  outDir,
  { dryRun = false, runNpm = defaultNpm, runStage = defaultStageNpm, summaryFile } = {},
) {
  const dir = resolve(outDir);
  const entries = readReleaseManifest(dir);
  const plan = entries.map((entry) => ({ ...entry, action: planEntry(entry, { dir, runNpm }) }));
  const staged = [];
  for (const entry of plan) {
    if (entry.action === "skip") {
      console.log(`skip ${entry.name}@${entry.version}: this exact tarball is already published`);
      continue;
    }
    const args = stageArgs(join(dir, entry.file), { dryRun });
    console.log(`${dryRun ? "[dry-run] " : ""}npm ${args.join(" ")}`);
    const res = runStage(args);
    if (res.status !== 0) {
      throw new Error(`npm stage publish failed for ${entry.name}@${entry.version}`);
    }
    const stageId = dryRun ? null : parseStageId(res.stdout);
    if (!dryRun && !stageId) {
      throw new Error(`npm did not report a stage id for ${entry.name}@${entry.version}`);
    }
    staged.push({ ...entry, stageId });
  }
  if (!dryRun && staged.length > 0) {
    const text = approvalInstructions(staged);
    console.log(`\n${text}`);
    const file = summaryFile ?? process.env.GITHUB_STEP_SUMMARY;
    if (file) appendFileSync(file, `\n${text}\n`);
  }
  return staged;
}

/** The maintainer's approval steps for a set of staged releases, in dependency order. */
export function approvalInstructions(staged) {
  return [
    "## Staged on npm: waiting for maintainer approval",
    "",
    "Nothing is public yet. Inspect, then approve **in this order** (each asks for npm 2FA):",
    "",
    "```sh",
    ...staged.flatMap(({ name, version, stageId }) => [
      `npm stage view ${stageId}       # ${name}@${version}`,
      `npm stage approve ${stageId}`,
    ]),
    "```",
    "",
    "To abandon a release instead: `npm stage reject <stage-id>` for each.",
  ].join("\n");
}

function cli(argv) {
  const [command, arg, ...rest] = argv;
  switch (command) {
    case "verify": {
      const version = versionFromTag(arg ?? "");
      const problems = releaseProblems(version);
      if (problems.length > 0) {
        throw new Error(`not releasable as ${version}:\n  - ${problems.join("\n  - ")}`);
      }
      console.log(
        `releasable: ${PUBLISHED_PACKAGES.map((p) => `${p.name}@${version}`).join(", ")}`,
      );
      return;
    }
    case "set-version":
      setVersion(arg ?? "");
      console.log(`set ${PUBLISHED_PACKAGES.length} released packages to ${arg}`);
      return;
    case "pack":
      if (!arg) throw new Error("usage: pack <out-dir>");
      packAll(arg);
      return;
    case "publish":
      if (!arg) throw new Error("usage: publish <out-dir> [--dry-run]");
      publishAll(arg, { dryRun: rest.includes("--dry-run") });
      return;
    default:
      throw new Error("usage: release-packages.mjs verify|set-version|pack|publish …");
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    cli(process.argv.slice(2));
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
