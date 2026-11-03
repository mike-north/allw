#!/usr/bin/env node
/**
 * One-shot, operator-run bootstrap for npm trusted publishing of the `@allw/*` packages.
 *
 * Run it once, locally, after `npm login`:
 *
 *   node scripts/npm-bootstrap-trusted-publishing.mjs --dry-run   # see what it would do
 *   node scripts/npm-bootstrap-trusted-publishing.mjs             # do it (prompts before writes)
 *
 * Why it exists: npm can only attach a trusted publisher (GitHub Actions OIDC) to a package that
 * already exists on the registry, and none of ours do yet. So, for each package in the release set
 * (scripts/release-packages.mjs), this script:
 *
 *   1. If the package does not exist on npm: publishes a tiny **name-reservation placeholder**
 *      (`0.0.0-bootstrap.0`, dist-tag `bootstrap`, no code — importing it throws a pointer to the real
 *      releases). Real code is never published from a laptop: the first real version comes from the
 *      release workflow, with provenance. Announced, and gated on a y/N confirmation.
 *   2. Configures the trusted publisher with `npm trust github` (npm >= 11.15.0): repo
 *      mike-north/allw, workflow `release.yml`, environment `npm-publish`, permission `publish`. If a
 *      different trust config is already attached, it offers to revoke and replace it. If the CLI path
 *      fails, it prints the exact npmjs.com page and field values to enter by hand.
 *   3. Prints a checklist of what is done and what the human must still do.
 *
 * Idempotent: every step first reads registry state and skips work that is already done, so re-running
 * is safe (and is the fix for a trust config that expired before its first publish).
 *
 * Preconditions checked up front, each with a specific fix: npm new enough for `npm trust`, logged in
 * (`npm whoami`), the `@allw` scope exists and you are a member, and the release manifests are
 * consistent (names, public access, `repository.url` → the trusted repo, dependency order). No build is
 * needed: the placeholder is generated, and real tarballs are built by CI.
 *
 * It never runs `npm login`, never handles tokens, and never publishes real package contents.
 *
 * @see ../docs/releasing.md
 * @see https://docs.npmjs.com/trusted-publishers
 * @see https://docs.npmjs.com/cli/v11/commands/npm-trust
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

import {
  NPM_SCOPE,
  PUBLISHED_PACKAGES,
  RELEASE_ENVIRONMENT,
  RELEASE_WORKFLOW_FILE,
  REPO_ROOT,
  TRUSTED_REPOSITORY,
  readManifest,
  releaseProblems,
} from "./release-packages.mjs";

/** `npm trust` first shipped in npm 11.15.0. */
export const MIN_NPM_VERSION = "11.15.0";

/** Version of the name-reservation placeholder. Sorts below any real release. */
export const PLACEHOLDER_VERSION = "0.0.0-bootstrap.0";

/** Dist-tag the placeholder is published under (never `latest` on purpose). */
export const PLACEHOLDER_TAG = "bootstrap";

/** The npm org that owns the scope (scope without the `@`). */
const ORG = NPM_SCOPE.slice(1);

/** Thrown for a failed precondition: the message is the fix, shown verbatim. */
export class PreconditionError extends Error {}

/** Compare dotted numeric versions (`11.5.1` vs `11.15.0`); prerelease suffixes are ignored. */
export function versionAtLeast(actual, minimum) {
  const parse = (v) =>
    String(v)
      .trim()
      .split("-")[0]
      .split(".")
      .map((n) => Number.parseInt(n, 10) || 0);
  const a = parse(actual);
  const b = parse(minimum);
  for (let i = 0; i < 3; i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0);
  }
  return true;
}

/**
 * Parse `npm trust list --json` output. npm prints one JSON object per configuration (concatenated,
 * not an array) and nothing at all when there are none.
 */
export function parseTrustList(stdout) {
  const text = stdout.trim();
  if (text === "") return [];
  const parsed = JSON.parse(text.startsWith("[") ? text : `[${text.replace(/}\s*{/g, "},{")}]`);
  return parsed.flat();
}

/** Whether a trust config is exactly the one the release workflow needs. */
export function isExpectedTrust(config) {
  return (
    config?.type === "github" &&
    config.repository === TRUSTED_REPOSITORY &&
    config.file === RELEASE_WORKFLOW_FILE &&
    config.environment === RELEASE_ENVIRONMENT &&
    Array.isArray(config.permissions) &&
    config.permissions.includes("createPackage")
  );
}

/** The `npm trust github` arguments that attach our release workflow to `name`. */
export function trustGithubArgs(name, { dryRun = false } = {}) {
  return [
    "trust",
    "github",
    name,
    "--file",
    RELEASE_WORKFLOW_FILE,
    "--repo",
    TRUSTED_REPOSITORY,
    "--env",
    RELEASE_ENVIRONMENT,
    "--allow-publish",
    dryRun ? "--dry-run" : "--yes",
  ];
}

/** What to type into npmjs.com when the CLI path is unavailable. */
export function manualTrustInstructions(name) {
  return [
    `  ${name}: open https://www.npmjs.com/package/${name}/access → "Trusted publishing" → GitHub Actions`,
    `      Organization or user: ${TRUSTED_REPOSITORY.split("/")[0]}`,
    `      Repository:           ${TRUSTED_REPOSITORY.split("/")[1]}`,
    `      Workflow filename:    ${RELEASE_WORKFLOW_FILE}`,
    `      Environment name:     ${RELEASE_ENVIRONMENT}`,
    `      Allowed action:       npm publish`,
  ].join("\n");
}

/** Write the placeholder package for `pkg` into a fresh temp dir; returns the dir. */
export function writePlaceholder(pkg) {
  const dir = mkdtempSync(join(tmpdir(), "allw-npm-placeholder-"));
  const repoUrl = `https://github.com/${TRUSTED_REPOSITORY}`;
  const manifest = {
    name: pkg.name,
    version: PLACEHOLDER_VERSION,
    description: `Name reservation for ${pkg.name}. Real releases are published from CI with provenance — see ${repoUrl}.`,
    license: "MIT",
    main: "index.js",
    files: ["index.js", "README.md"],
    repository: { type: "git", url: `git+${repoUrl}.git`, directory: pkg.dir },
    publishConfig: { access: "public" },
  };
  writeFileSync(join(dir, "package.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(
    join(dir, "index.js"),
    `throw new Error(${JSON.stringify(
      `${pkg.name}@${PLACEHOLDER_VERSION} is an empty name-reservation placeholder. Install a real release: npm install ${pkg.name}@latest`,
    )});\n`,
  );
  writeFileSync(
    join(dir, "README.md"),
    `# ${pkg.name} (placeholder)\n\nThis version (\`${PLACEHOLDER_VERSION}\`) only reserves the package name so npm trusted publishing\ncan be configured. It contains no code. Install a real release instead: \`npm install ${pkg.name}@latest\`.\n\nSource and releases: ${repoUrl}\n`,
  );
  return dir;
}

/**
 * The default npm runner. `interactive` runs with the terminal attached (for 2FA/OTP prompts);
 * otherwise stdout is captured while stdin/stderr stay attached, so an OTP prompt from a read
 * command (e.g. `npm trust list`) still reaches the operator.
 */
function defaultNpm(args, { interactive = false } = {}) {
  const res = spawnSync("npm", args, {
    encoding: "utf8",
    stdio: interactive ? "inherit" : ["inherit", "pipe", "pipe"],
  });
  return { status: res.status ?? 1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

async function defaultConfirm(question) {
  if (!process.stdin.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await rl.question(`${question} [y/N] `);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

/** Fail with `message` unless `res` succeeded; registry 404s are reported by callers, not here. */
function requireOk(res, message) {
  if (res.status !== 0) throw new PreconditionError(`${message}\n${res.stderr.trim()}`);
  return res.stdout;
}

const is404 = (res) => /E404|not found/i.test(`${res.stdout}\n${res.stderr}`);
const needsOtp = (res) => /EOTP|one-time pass/i.test(`${res.stdout}\n${res.stderr}`);

/**
 * Check every precondition; returns the npm username. Throws PreconditionError with the fix.
 */
export function checkPreconditions({ npm, log, root = REPO_ROOT, packages = PUBLISHED_PACKAGES }) {
  const npmVersion = requireOk(npm(["--version"]), "could not run `npm --version`").trim();
  if (!versionAtLeast(npmVersion, MIN_NPM_VERSION)) {
    throw new PreconditionError(
      `npm ${npmVersion} is too old: \`npm trust\` needs npm >= ${MIN_NPM_VERSION}.\n` +
        `Fix: npm install -g npm@^${MIN_NPM_VERSION}`,
    );
  }
  log(`✓ npm ${npmVersion}`);

  const whoami = npm(["whoami"]);
  if (whoami.status !== 0) {
    throw new PreconditionError(
      "You are not logged in to npm.\nFix: run `npm login`, then re-run this script.",
    );
  }
  const user = whoami.stdout.trim();
  log(`✓ logged in to npm as ${user}`);

  const org = npm(["org", "ls", ORG, "--json"]);
  if (org.status === 0) {
    const members = JSON.parse(org.stdout || "{}");
    const role = members[user];
    if (!role) {
      throw new PreconditionError(
        `The npm org "${ORG}" exists but ${user} is not a member, so you cannot publish under ${NPM_SCOPE}.\n` +
          `Fix: have an owner of https://www.npmjs.com/org/${ORG} add ${user} (role owner or admin).`,
      );
    }
    log(`✓ ${NPM_SCOPE} scope: npm org "${ORG}" (your role: ${role})`);
    if (role !== "owner" && role !== "admin") {
      log(
        `  ! role "${role}" may not be allowed to create packages or edit their settings; owner/admin is safest`,
      );
    }
  } else if (is404(org) && user === ORG) {
    log(`✓ ${NPM_SCOPE} scope: your user scope`);
  } else if (is404(org)) {
    throw new PreconditionError(
      `The npm scope ${NPM_SCOPE} does not exist yet (no npm org or user named "${ORG}").\n` +
        `Fix: create the free npm organization "${ORG}" at https://www.npmjs.com/org/create\n` +
        `     (organization name: ${ORG}; plan: free / unlimited public packages), signed in as ${user},\n` +
        `     then re-run this script. If "${ORG}" is taken, the package names must change first.`,
    );
  } else if (/E403|forbidden/i.test(org.stderr)) {
    throw new PreconditionError(
      `The npm org "${ORG}" exists but ${user} cannot read it (not a member?).\n` +
        `Fix: have an owner of https://www.npmjs.com/org/${ORG} add ${user} (role owner or admin).`,
    );
  } else {
    throw new PreconditionError(`could not read the npm org "${ORG}":\n${org.stderr.trim()}`);
  }

  const profile = npm(["profile", "get", "--json"]);
  if (profile.status === 0) {
    const tfa = JSON.parse(profile.stdout || "{}").tfa;
    if (!tfa || tfa.pending) {
      log(
        "  ! two-factor auth looks disabled on your npm account; `npm trust` requires it.\n" +
          "    Fix: npm profile enable-2fa auth-and-writes  (or enable it on npmjs.com → Account)",
      );
    } else {
      log(`✓ two-factor auth enabled (${String(tfa.mode)})`);
    }
  }

  const version = readManifest(packages[0].dir, root).version;
  const problems = releaseProblems(version, { root, packages });
  if (problems.length > 0) {
    throw new PreconditionError(
      `the release manifests are not publishable as ${version}:\n  - ${problems.join("\n  - ")}`,
    );
  }
  if (!existsSync(join(root, ".github", "workflows", RELEASE_WORKFLOW_FILE))) {
    throw new PreconditionError(
      `.github/workflows/${RELEASE_WORKFLOW_FILE} is missing — the trusted publisher would name a workflow that does not exist.`,
    );
  }
  log(`✓ release set ${packages.map((p) => p.name).join(", ")} is consistent at ${version}`);
  return user;
}

/** Registry view of `name`: `null` if it does not exist, else its published versions. */
function registryVersions(npm, name) {
  const res = npm(["view", name, "versions", "--json"]);
  if (res.status === 0) {
    const parsed = JSON.parse(res.stdout || "[]");
    return Array.isArray(parsed) ? parsed : [parsed];
  }
  if (is404(res)) return null;
  throw new PreconditionError(`could not query the registry for ${name}:\n${res.stderr.trim()}`);
}

/**
 * Run the bootstrap. Every side effect goes through the injected `npm` / `confirm` / `log` /
 * `sleep`, so tests can drive it without a registry. Returns the per-package rows and exit code.
 */
export async function bootstrap({
  dryRun = false,
  npm = defaultNpm,
  confirm = defaultConfirm,
  log = (line) => console.log(line),
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  root = REPO_ROOT,
  packages = PUBLISHED_PACKAGES,
} = {}) {
  const mode = dryRun ? " (dry run — no changes will be made)" : "";
  log(`npm trusted-publishing bootstrap for ${TRUSTED_REPOSITORY}${mode}\n`);

  log("[1/3] preconditions");
  try {
    checkPreconditions({ npm, log, root, packages });
  } catch (err) {
    if (err instanceof PreconditionError) {
      log(`\n✗ ${err.message}`);
      return { exitCode: 1, rows: [] };
    }
    throw err;
  }

  /** @type {Array<{name: string, dir: string, versions: string[] | null, placeholder: string, trust: string}>} */
  const rows = packages.map((p) => ({ ...p, versions: null, placeholder: "", trust: "" }));
  let failed = false;

  log("\n[2/3] reserve package names");
  try {
    for (const row of rows) row.versions = registryVersions(npm, row.name);
  } catch (err) {
    // Fail closed: an unreadable registry must never be mistaken for "package missing".
    if (err instanceof PreconditionError) {
      log(`\n✗ ${err.message}`);
      return { exitCode: 1, rows };
    }
    throw err;
  }
  const missing = rows.filter((r) => r.versions === null);
  for (const row of rows.filter((r) => r.versions !== null)) {
    row.placeholder = "exists";
    log(`✓ ${row.name} exists on npm (${row.versions.length} version(s))`);
  }
  if (missing.length > 0) {
    log(
      `These packages do not exist on npm yet, so a trusted publisher cannot be attached to them:\n` +
        missing.map((r) => `  - ${r.name}`).join("\n") +
        `\nEach will get an empty name-reservation placeholder ${code(PLACEHOLDER_VERSION)} under dist-tag "${PLACEHOLDER_TAG}",\n` +
        `published from this machine as you. It contains no code; real versions come from CI.`,
    );
    if (dryRun) {
      for (const row of missing) {
        row.placeholder = "would publish placeholder";
        log(
          `  [dry-run] npm publish <placeholder for ${row.name}> --access public --tag ${PLACEHOLDER_TAG}`,
        );
      }
    } else if (await confirm(`Publish ${missing.length} placeholder package(s) now?`)) {
      for (const row of missing) {
        const dir = writePlaceholder(row);
        try {
          const res = npm(["publish", dir, "--access", "public", "--tag", PLACEHOLDER_TAG], {
            interactive: true,
          });
          if (res.status === 0) {
            row.placeholder = "placeholder published";
            row.versions = [PLACEHOLDER_VERSION];
            log(`✓ published ${row.name}@${PLACEHOLDER_VERSION}`);
          } else {
            failed = true;
            row.placeholder = "placeholder publish FAILED";
            log(`✗ npm publish failed for ${row.name}`);
          }
        } finally {
          rmSync(dir, { recursive: true, force: true });
        }
      }
    } else {
      for (const row of missing) row.placeholder = "skipped (declined)";
      log("Skipped: no placeholders published.");
    }
  }

  log("\n[3/3] trusted publishers");
  const toCreate = [];
  for (const row of rows) {
    if (row.versions === null) {
      if (dryRun) {
        const res = npm(trustGithubArgs(row.name, { dryRun: true }));
        row.trust =
          res.status === 0 ? "would configure" : "would configure (npm rejected the dry run)";
        log(`  [dry-run] npm ${trustGithubArgs(row.name).join(" ")}`);
      } else {
        row.trust = "not configured (package missing)";
      }
      continue;
    }
    const list = npm(["trust", "list", row.name, "--json"]);
    if (list.status !== 0 && needsOtp(list)) {
      // npm only prompts for 2FA when attached to a terminal, which a captured read is not. Show the
      // configs interactively (the operator authenticates there) and let the operator judge them.
      log(`  ${row.name}: reading trust configs needs 2FA — showing them interactively:`);
      const shown = npm(["trust", "list", row.name], { interactive: true });
      const expected = `repository ${TRUSTED_REPOSITORY}, file ${RELEASE_WORKFLOW_FILE}, environment ${RELEASE_ENVIRONMENT}`;
      if (shown.status === 0 && (await confirm(`Does the output above show ${expected}?`))) {
        row.trust = "configured";
        continue;
      }
      toCreate.push({ row, replace: [] });
      continue;
    }
    if (list.status !== 0) {
      failed = true;
      row.trust = "could not read";
      log(`✗ could not list trust configs for ${row.name}:\n${list.stderr.trim()}`);
      continue;
    }
    const configs = parseTrustList(list.stdout);
    if (configs.some(isExpectedTrust)) {
      row.trust = "configured";
      log(`✓ ${row.name}: trusted publisher already configured`);
      continue;
    }
    toCreate.push({ row, replace: configs });
  }

  if (toCreate.length > 0) {
    log(
      `Will attach the trusted publisher (repo ${TRUSTED_REPOSITORY}, workflow ${RELEASE_WORKFLOW_FILE}, ` +
        `environment ${RELEASE_ENVIRONMENT}, allow: npm publish) to:\n` +
        toCreate
          .map(({ row, replace }) =>
            replace.length > 0
              ? `  - ${row.name} (REPLACING existing: ${replace.map((c) => JSON.stringify(c)).join(", ")})`
              : `  - ${row.name}`,
          )
          .join("\n") +
        `\nnpm will ask for 2FA on the first change.`,
    );
    const proceed =
      dryRun || (await confirm(`Configure ${toCreate.length} trusted publisher(s) now?`));
    for (const [i, { row, replace }] of toCreate.entries()) {
      if (dryRun) {
        for (const c of replace)
          log(`  [dry-run] npm trust revoke ${row.name} --id=${String(c.id)}`);
        log(`  [dry-run] npm ${trustGithubArgs(row.name).join(" ")}`);
        row.trust = replace.length > 0 ? "would replace" : "would configure";
        continue;
      }
      if (!proceed) {
        row.trust = "skipped (declined)";
        continue;
      }
      if (i > 0) await sleep(2000); // npm docs: pace bulk trust calls to avoid rate limiting
      let ok = true;
      for (const c of replace) {
        ok =
          npm(["trust", "revoke", row.name, `--id=${String(c.id)}`], { interactive: true })
            .status === 0;
        if (!ok) break;
      }
      ok = ok && npm(trustGithubArgs(row.name), { interactive: true }).status === 0;
      if (ok) {
        row.trust = "configured (this run)";
        log(`✓ ${row.name}: trusted publisher configured`);
      } else {
        failed = true;
        row.trust = "FAILED — configure by hand";
        log(
          `✗ npm trust failed for ${row.name}. Configure it on the website instead:\n${manualTrustInstructions(row.name)}`,
        );
      }
    }
  }

  printChecklist({ rows, log, dryRun });
  return { exitCode: failed ? 1 : 0, rows };
}

/** Inline-code helper for log text. */
function code(text) {
  return `\`${text}\``;
}

function printChecklist({ rows, log, dryRun }) {
  const width = Math.max(...rows.map((row) => row.name.length));
  log("\nSummary");
  for (const row of rows) {
    log(`  ${row.name.padEnd(width)}  npm: ${row.placeholder.padEnd(26)}  trust: ${row.trust}`);
  }

  const todo = [];
  const allTrusted = rows.every((row) => row.trust.startsWith("configured"));
  const newTrust = rows.some((row) => row.trust === "configured (this run)");
  if (dryRun) todo.push("Re-run without --dry-run to apply the changes above.");
  const manual = rows.filter((row) => row.trust.startsWith("FAILED"));
  if (manual.length > 0) {
    todo.push(
      `Configure these trusted publishers on npmjs.com:\n${manual.map((row) => manualTrustInstructions(row.name)).join("\n")}`,
    );
  }
  if (!dryRun && !allTrusted && manual.length === 0) {
    todo.push(
      "Some packages are not configured yet (see above) — fix the cause and re-run this script.",
    );
  }
  if (newTrust || dryRun) {
    todo.push(
      "Cut the first real release within 48 hours — npm expires a trusted-publisher config that has not\n" +
        "     completed a publish in that window (re-running this script recreates an expired one):\n" +
        "       node scripts/release-packages.mjs verify v<version>   # lockstep version check\n" +
        "       git tag v<version> <commit on main> && git push https://github.com/mike-north/allw.git v<version>",
    );
  }
  todo.push(
    `Recommended: protect the "${RELEASE_ENVIRONMENT}" GitHub environment (required reviewer, deployment\n` +
      `     from \`v*\` tags only): https://github.com/${TRUSTED_REPOSITORY}/settings/environments`,
  );
  const placeholders = rows.filter((row) => row.versions?.includes(PLACEHOLDER_VERSION));
  if (placeholders.length > 0) {
    todo.push(
      "After the first CI release succeeds, deprecate the placeholders:\n" +
        placeholders
          .map(
            (row) =>
              `       npm deprecate "${row.name}@${PLACEHOLDER_VERSION}" "name-reservation placeholder; install ${row.name}@latest"`,
          )
          .join("\n"),
    );
  }
  todo.push(
    "After the first CI release succeeds, harden each package: npmjs.com → package → Settings →\n" +
      '     Publishing access → "Require two-factor authentication and disallow tokens" (OIDC keeps working).',
  );
  log("\nStill to do");
  for (const [i, item] of todo.entries()) log(`  ${i + 1}. ${item}`);
}

function usage() {
  return [
    "usage: node scripts/npm-bootstrap-trusted-publishing.mjs [--dry-run]",
    "",
    "Reserves the @allw/* package names on npm (placeholder) and attaches the GitHub Actions",
    "trusted publisher for .github/workflows/release.yml. Run after `npm login`. Safe to re-run.",
    "See docs/releasing.md.",
  ].join("\n");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.includes("--help") || args.includes("-h")) {
    console.log(usage());
    process.exit(0);
  }
  const unknown = args.filter((a) => a !== "--dry-run");
  if (unknown.length > 0) {
    console.error(`unknown argument(s): ${unknown.join(" ")}\n\n${usage()}`);
    process.exit(2);
  }
  const { exitCode } = await bootstrap({ dryRun: args.includes("--dry-run") });
  process.exit(exitCode);
}
