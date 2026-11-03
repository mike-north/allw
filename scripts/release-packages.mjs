/**
 * The npm release set and the release workflow's pack/publish steps.
 *
 * This module is the single source of truth for *which* `@allw/*` packages are published to npm,
 * *in what order*, and *under which trusted-publisher identity* (repo + workflow file + GitHub
 * environment). Both the CI release workflow (`.github/workflows/release.yml`) and the one-shot
 * operator bootstrap (`scripts/npm-bootstrap-trusted-publishing.mjs`) import it, so the identity npm
 * is told to trust and the identity that actually publishes can never drift apart.
 *
 * Versioning is **lockstep**: every published package carries the same version, and a release is cut
 * by pushing a `v<version>` tag that must equal it. (The packages are versioned together because they
 * share one WASM core and pin each other via `workspace:*`, which `pnpm pack` rewrites to the exact
 * sibling version.)
 *
 * CLI (used by the release workflow; each command fails non-zero with a reason on any doubt):
 *
 *   node scripts/release-packages.mjs verify <tag>          check every manifest is releasable at <tag>
 *   node scripts/release-packages.mjs set-version <x.y.z>   bump every published manifest (lockstep)
 *   node scripts/release-packages.mjs pack <out-dir>        pnpm pack each package, in publish order
 *   node scripts/release-packages.mjs publish <out-dir> [--dry-run]
 *                                                           npm publish each packed tarball, in order,
 *                                                           skipping versions already on the registry
 *
 * @see ../docs/releasing.md (the release process this implements)
 * @see https://docs.npmjs.com/trusted-publishers
 */

import { spawnSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The GitHub repository npm trusts to publish (`owner/repo`); must match each `repository.url`. */
export const TRUSTED_REPOSITORY = "mike-north/allw";

/**
 * The workflow file (basename only, as npm's trusted-publisher config wants it) that publishes.
 * npm validates the OIDC token's `workflow_ref` against this name at publish time.
 */
export const RELEASE_WORKFLOW_FILE = "release.yml";

/**
 * The GitHub Actions environment the publish job runs in. Binding the trusted publisher to an
 * environment means only jobs in that environment can mint a publish-capable OIDC token, and lets the
 * repo owner add environment protection rules (required reviewers, tag-only deployment) as a human
 * gate in front of every release.
 */
export const RELEASE_ENVIRONMENT = "npm-publish";

/** The npm scope every published package lives under. */
export const NPM_SCOPE = "@allw";

/** Lockstep release tags: `v` + a semver version (prerelease allowed, build metadata not). */
const TAG_PATTERN = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/**
 * The published packages, **in dependency order** (every package appears after the workspace
 * packages it depends on), so a consumer can never observe a published package whose `@allw/*`
 * dependency at that exact version is not yet on the registry. Private packages (`@allw/relay`,
 * `@allw/web-approver`, the examples) are deployed or run from source and are never published.
 */
export const PUBLISHED_PACKAGES = Object.freeze([
  { name: "@allw/sdk", dir: "packages/sdk" },
  { name: "@allw/hook", dir: "packages/hook" },
  { name: "@allw/approver", dir: "packages/approver" },
  { name: "@allw/codex-hook", dir: "packages/codex-hook" },
  { name: "@allw/openclaw-bridge", dir: "packages/openclaw-bridge" },
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
      `release tag ${JSON.stringify(tag)} is not of the form v<major>.<minor>.<patch>`,
    );
  }
  return match[1];
}

/** `owner/repo` from a package.json `repository` field, or `null` if it is not a GitHub URL. */
export function githubRepoOf(repository) {
  const url = typeof repository === "string" ? repository : repository?.url;
  if (typeof url !== "string") return null;
  const match = /github\.com[/:]([^/]+\/[^/.]+?)(?:\.git)?\/?$/.exec(url);
  return match ? match[1] : null;
}

/**
 * Every reason the release set cannot be published as `version`. Empty ⇔ releasable.
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

/** Rewrite the `version` of every published manifest (lockstep bump), preserving formatting. */
export function setVersion(version, { root = REPO_ROOT, packages = PUBLISHED_PACKAGES } = {}) {
  if (!VERSION_PATTERN.test(version)) {
    throw new Error(`version ${JSON.stringify(version)} is not a semver x.y.z[-prerelease]`);
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
 * `pnpm pack` every published package into `outDir`, in publish order, and write
 * `outDir/release-manifest.json` (`[{ name, version, file }]`) for the publish step. `pnpm pack` is
 * what rewrites `workspace:*` dependencies to the exact sibling version.
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

/**
 * Whether `name@version` is already on the registry. A registry 404 means "not published"; any other
 * failure throws, so an outage can never be mistaken for "safe to publish" or "already done".
 */
export function isPublished(name, version, runNpm = defaultNpm) {
  const res = runNpm(["view", `${name}@${version}`, "version", "--json"]);
  if (res.status === 0) return res.stdout.trim() !== "";
  if (/E404/.test(`${res.stdout}\n${res.stderr}`)) return false;
  throw new Error(`could not query the registry for ${name}@${version}:\n${res.stderr}`);
}

function defaultNpm(args) {
  return spawnSync("npm", args, { encoding: "utf8" });
}

/**
 * Publish every tarball listed in `outDir/release-manifest.json`, in order. Already-published
 * versions are skipped, so re-running a partially failed release finishes it instead of failing on
 * the first package. Auth is npm trusted publishing (GitHub OIDC) — there is no token; provenance is
 * requested explicitly so a missing attestation fails the publish rather than shipping silently.
 */
export function publishAll(outDir, { dryRun = false, runNpm = defaultNpm } = {}) {
  const dest = resolve(outDir);
  const entries = JSON.parse(readFileSync(join(dest, "release-manifest.json"), "utf8"));
  for (const { name, version, file } of entries) {
    if (isPublished(name, version, runNpm)) {
      console.log(`skip ${name}@${version}: already on the registry`);
      continue;
    }
    const args = ["publish", join(dest, file), "--access", "public"];
    if (dryRun) args.push("--dry-run");
    else args.push("--provenance");
    console.log(`${dryRun ? "[dry-run] " : ""}npm ${args.join(" ")}`);
    const res = spawnSync("npm", args, { stdio: "inherit" });
    if (res.status !== 0) {
      throw new Error(`npm publish failed for ${name}@${version} (exit ${String(res.status)})`);
    }
  }
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
      console.log(`set ${PUBLISHED_PACKAGES.length} published packages to ${arg}`);
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
