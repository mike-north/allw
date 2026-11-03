#!/usr/bin/env node
/**
 * The maintainer's pre-approval check for a staged npm release.
 *
 * Staging is the release workflow's only power. A version goes public only when a maintainer runs
 * `npm stage approve` with npm 2FA, so that approval is the release gate, and this script is what
 * makes the approval an informed one. The run's job summary can't do that job: any workflow run
 * that can get a stage-capable OIDC token can also write its own summary. For example, a modified
 * `release.yml` on a branch with a `v*` tag pushed at it can.
 *
 * Run it from a checkout of this repo, logged in to npm as a maintainer and to `gh`:
 *
 *   node scripts/verify-staged-release.mjs <x.y.z> [--run <run-id>]
 *       before approving: verifies every pending stage of <x.y.z>
 *   node scripts/verify-staged-release.mjs <x.y.z> --published [--run <run-id>]
 *       after approving: verifies what is now public
 *
 * It establishes, and exits non-zero unless every check holds:
 *
 *   0. **Not stale, not dirty.** The checkout is clean (`git status --porcelain` is empty) and
 *      `HEAD` is exactly GitHub's current `main`. That catches an out-of-date or accidentally
 *      modified checkout. It is **not** a defense against a hostile local agent or user. A
 *      self-check can't stop that: `git update-index --skip-worktree` hides edits from
 *      `git status`, and a PATH shim for `git`/`npm`/`gh`, `NODE_OPTIONS`, a git hook, or an
 *      edited copy of this file can all fake the answers. docs/releasing.md says how to run it
 *      from a fresh clone in a clean environment, and where to approve when the machine can't
 *      be trusted.
 *   1. **The run.** A successful `release.yml` run for tag `v<x.y.z>` (the one named by `--run`,
 *      or the only successful one), whose commit is the commit the tag points at on GitHub.
 *   2. **The commit is on `main`.** That commit is an ancestor of GitHub's `main`, so the workflow
 *      that ran, and the code it built, were reviewed. A hostile workflow lives on a commit that
 *      isn't on `main`.
 *   3. **The run's own tarballs.** It downloads the run's `npm-tarballs` artifact. The artifact's
 *      `release-manifest.json` must list exactly the release set at <x.y.z>, and every tarball
 *      must match its recorded sha512.
 *   4. **Exactly one pending stage per package, holding exactly those bytes.** `npm stage list`
 *      must show one open stage for each `name@<x.y.z>` and no other open stage of that package.
 *      The script then fetches the staged tarball with `npm stage download` and compares its
 *      sha512 with the manifest's.
 *   5. **Provenance names this run.** The SLSA provenance must name `release.yml` at
 *      `refs/tags/v<x.y.z>` in this repo, at that commit, from that run, for that sha512.
 *
 * For check 5, npm documents no read path that exposes a *staged* version's provenance:
 * `npm stage view --json` documents id, package, version, status, tag, actor and shasum. The
 * script verifies provenance whenever the stage view carries a DSSE envelope. If it doesn't, it
 * says so and fails, unless you pass `--provenance-after-approval`. In that case the byte-identity
 * of check 4 is what binds the stage to the run. Then run `--published` right after approving,
 * which reads the published attestation and checks it the same way. See docs/releasing.md.
 *
 * npm's stage reads don't prompt for 2FA. On accounts with auth-and-writes 2FA they fail with
 * EOTP, so the verifier asks for a one-time password and retries with it. The code reaches npm
 * through the environment (`npm_config_otp`), never argv, with npm's log file disabled. Without
 * a code, it fails closed.
 *
 * Every external call (`gh`, `git`, `npm`, HTTP) goes through an injected runner, so tests drive
 * it without a registry, GitHub or network.
 *
 * @see ../docs/releasing.md
 * @see https://docs.npmjs.com/staged-publishing
 * @see https://docs.npmjs.com/generating-provenance-statements
 * @see https://slsa.dev/spec/v1.0/provenance
 * @see https://github.com/slsa-framework/github-actions-buildtypes/tree/main/workflow/v1
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

import {
  PUBLISHED_PACKAGES,
  RELEASE_DIST_TAG,
  RELEASE_WORKFLOW_FILE,
  REPO_ROOT,
  TRUSTED_REPOSITORY,
  integrityOf,
  readVerifiedReleaseManifest,
} from "./release-packages.mjs";

/** The artifact `release.yml`'s build job uploads: the packed tarballs plus release-manifest.json. */
export const RELEASE_ARTIFACT = "npm-tarballs";

/** The SLSA predicate npm's GitHub Actions provenance uses. */
export const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";

/** The repo over HTTPS: what GitHub says the tag and `main` are, not whatever is checked out. */
const REMOTE_URL = `https://github.com/${TRUSTED_REPOSITORY}.git`;

const PLAIN_VERSION = /^\d+\.\d+\.\d+$/;

/** A stage status that can no longer be approved. Anything else counts as open (fail closed). */
const CLOSED_STAGE_STATUS = /^(approved|rejected|published|expired|cancel(l)?ed|deleted)$/i;

/** Whether a `npm stage list` item can still be approved. */
export function isOpenStage(item) {
  return !CLOSED_STAGE_STATUS.test(String(item?.status ?? ""));
}

/**
 * Every in-toto statement found in DSSE envelopes anywhere inside `value`. That covers a Sigstore
 * bundle, an attestations response, or a stage item that happens to carry one. Payloads that don't
 * decode as JSON are skipped.
 */
export function findStatements(value) {
  const out = [];
  const visit = (node) => {
    if (Array.isArray(node)) {
      for (const child of node) visit(child);
      return;
    }
    if (node === null || typeof node !== "object") return;
    const envelope = node.dsseEnvelope;
    if (envelope && typeof envelope.payload === "string") {
      try {
        out.push(JSON.parse(Buffer.from(envelope.payload, "base64").toString("utf8")));
      } catch {
        // not a JSON statement; ignore
      }
    }
    for (const child of Object.values(node)) visit(child);
  };
  visit(value);
  return out;
}

/** An SRI `sha512-<base64>` as the lowercase hex digest SLSA subjects carry. */
export function sriToHex(integrity) {
  return Buffer.from(String(integrity).replace(/^sha512-/, ""), "base64").toString("hex");
}

/**
 * Why `statement` does not prove that `name@version` with `integrity` was built by `release.yml`
 * at tag `v<version>` and `commit` in run `runId` of the trusted repo. Returns an empty list when it
 * does.
 */
export function provenanceProblems(statement, { name, version, integrity, commit, runId }) {
  const problems = [];
  if (statement?.predicateType !== SLSA_PROVENANCE_V1) {
    return [
      `provenance predicate is ${String(statement?.predicateType)}, not ${SLSA_PROVENANCE_V1}`,
    ];
  }
  const purl = `pkg:npm/${name.replace(/^@/, "%40")}@${version}`;
  const subject = (statement.subject ?? []).find((s) => s?.name === purl);
  if (!subject) problems.push(`provenance subject is not ${purl}`);
  else if (subject.digest?.sha512 !== sriToHex(integrity)) {
    problems.push(`provenance subject digest is not the release tarball's sha512`);
  }
  const build = statement.predicate?.buildDefinition ?? {};
  const workflow = build.externalParameters?.workflow ?? {};
  const want = {
    ref: `refs/tags/v${version}`,
    repository: `https://github.com/${TRUSTED_REPOSITORY}`,
    path: `.github/workflows/${RELEASE_WORKFLOW_FILE}`,
  };
  for (const [key, value] of Object.entries(want)) {
    if (workflow[key] !== value) {
      problems.push(`provenance workflow.${key} is ${String(workflow[key])}, not ${value}`);
    }
  }
  const commits = (build.resolvedDependencies ?? []).map((d) => d?.digest?.gitCommit);
  if (!commits.includes(commit)) {
    problems.push(`provenance commit is ${commits.join(", ") || "missing"}, not ${commit}`);
  }
  const invocation = String(statement.predicate?.runDetails?.metadata?.invocationId ?? "");
  if (!invocation.includes(`/${TRUSTED_REPOSITORY}/actions/runs/${String(runId)}/`)) {
    problems.push(`provenance run is ${invocation || "missing"}, not run ${String(runId)}`);
  }
  return problems;
}

/** Problems with the provenance statements found for one package (none found is a problem too). */
function checkProvenance(found, expected) {
  const slsa = found.filter((s) => s?.predicateType === SLSA_PROVENANCE_V1);
  if (slsa.length === 0) return { exposed: false, problems: [] };
  const results = slsa.map((s) => provenanceProblems(s, expected));
  if (results.some((p) => p.length === 0)) return { exposed: true, problems: [] };
  return { exposed: true, problems: results[0] };
}

function parseJson(text, what) {
  try {
    return JSON.parse(text);
  } catch {
    throw new VerifyError(`could not parse ${what} as JSON`);
  }
}

/** A failure that stops verification outright (an unreadable or missing prerequisite). */
export class VerifyError extends Error {}

function defaultExec(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, {
    encoding: "utf8",
    cwd: opts.cwd ?? REPO_ROOT,
    env: opts.env ? { ...process.env, ...opts.env } : process.env,
  });
  return { status: res.status ?? 1, stdout: res.stdout ?? "", stderr: res.stderr ?? "" };
}

/** Ask for an npm one-time password on the terminal; `null` when there is no terminal. */
async function defaultAskOtp(what) {
  if (!process.stdin.isTTY) return null;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return (await rl.question(`npm one-time password (2FA code) to ${what}: `)).trim();
  } finally {
    rl.close();
  }
}

async function defaultFetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new VerifyError(`GET ${url} → HTTP ${String(res.status)}`);
  return res.json();
}

/** Run `cmd`, requiring success; the error names the command and its stderr. */
function must(exec, cmd, args, opts) {
  const res = exec(cmd, args, opts);
  if (res.status !== 0) {
    throw new VerifyError(`${cmd} ${args.join(" ")} failed:\n${res.stderr.trim()}`);
  }
  return res.stdout;
}

const needsOtp = (res) => /EOTP|one-time pass/i.test(`${res.stdout}\n${res.stderr}`);

/** A one-time password as authenticator apps show it. */
const OTP_PATTERN = /^\d{6,8}$/;

/**
 * An `npm` runner for reads that may need 2FA. npm's `stage list`, `stage view` and `stage
 * download` don't prompt for a one-time password themselves. On an account with auth-and-writes
 * 2FA they fail with EOTP. So on EOTP this asks for a code, retries with it, and reuses the code
 * for later reads until npm rejects it. Without a code it throws (fail closed).
 *
 * The code goes to npm in the child's environment (`npm_config_otp`), never in argv. npm doesn't
 * redact `--otp=<code>`, so argv would leak it to `ps` and to npm's debug log. Every read also
 * passes `--logs-max=0`, so npm writes no log file. The code is never printed.
 */
export function npmReader(exec, askOtp) {
  const cache = { otp: null };
  return async (baseArgs, opts = {}) => {
    const args = [...baseArgs, "--logs-max=0"];
    const withOtp = (otp) => ({ ...opts, env: { ...opts.env, npm_config_otp: otp } });
    let res = exec("npm", args, opts);
    if (res.status !== 0 && needsOtp(res) && cache.otp) {
      res = exec("npm", args, withOtp(cache.otp));
    }
    for (let attempt = 0; res.status !== 0 && needsOtp(res) && attempt < 2; attempt++) {
      const otp = String((await askOtp(`run npm ${baseArgs.slice(0, 2).join(" ")}`)) ?? "").trim();
      if (!OTP_PATTERN.test(otp)) {
        throw new VerifyError(
          `npm ${baseArgs.join(" ")} needs a one-time password, and none was given`,
        );
      }
      cache.otp = otp;
      res = exec("npm", args, withOtp(otp));
    }
    if (res.status !== 0) {
      throw new VerifyError(`npm ${baseArgs.join(" ")} failed:\n${res.stderr.trim()}`);
    }
    return res.stdout;
  };
}

const RUN_FIELDS = "databaseId,headSha,headBranch,event,status,conclusion,url";

/** The `release.yml` run to verify against: the one named, or the only successful one for the tag. */
export function resolveRun(exec, { tag, runId }) {
  const runs = runId
    ? [
        parseJson(
          must(exec, "gh", [
            "run",
            "view",
            String(runId),
            "--repo",
            TRUSTED_REPOSITORY,
            "--json",
            RUN_FIELDS,
          ]),
          "gh run view",
        ),
      ]
    : parseJson(
        must(exec, "gh", [
          "run",
          "list",
          "--repo",
          TRUSTED_REPOSITORY,
          "--workflow",
          RELEASE_WORKFLOW_FILE,
          "--branch",
          tag,
          "--json",
          RUN_FIELDS,
          "--limit",
          "50",
        ]),
        "gh run list",
      );
  const good = runs.filter(
    (r) =>
      r?.headBranch === tag &&
      r.conclusion === "success" &&
      (r.event === "push" || r.event === "workflow_dispatch"),
  );
  if (runId && good.length === 0) {
    const r = runs[0] ?? {};
    throw new VerifyError(
      `run ${String(runId)} is not a successful release run for ${tag} ` +
        `(ref ${String(r.headBranch)}, event ${String(r.event)}, conclusion ${String(r.conclusion)})`,
    );
  }
  if (good.length !== 1) {
    throw new VerifyError(
      good.length === 0
        ? `no successful ${RELEASE_WORKFLOW_FILE} run found for ${tag}`
        : `${good.length} successful ${RELEASE_WORKFLOW_FILE} runs for ${tag} ` +
            `(${good.map((r) => r.databaseId).join(", ")}): pass --run <id> for the one whose stages you are approving`,
    );
  }
  return good[0];
}

/** The commit GitHub's `refs/tags/<tag>` points at (peeled, for an annotated tag), or null. */
export function remoteTagCommit(exec, tag) {
  const out = must(exec, "git", [
    "ls-remote",
    REMOTE_URL,
    `refs/tags/${tag}`,
    `refs/tags/${tag}^{}`,
  ]);
  const refs = new Map(
    out
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        const [sha, ref] = line.split(/\s+/);
        return [ref, sha];
      }),
  );
  return refs.get(`refs/tags/${tag}^{}`) ?? refs.get(`refs/tags/${tag}`) ?? null;
}

/** The commit GitHub's `main` points at right now, read over HTTPS. */
export function remoteMainCommit(exec) {
  const out = must(exec, "git", ["ls-remote", REMOTE_URL, "refs/heads/main"]);
  const sha = out
    .split("\n")
    .find((l) => /\srefs\/heads\/main$/.test(l))
    ?.split(/\s+/)[0];
  if (!/^[0-9a-f]{40}$/.test(sha ?? "")) {
    throw new VerifyError(`could not read GitHub's main from ${REMOTE_URL}`);
  }
  return sha;
}

/**
 * Refuse a stale or dirty checkout: `git status --porcelain` must be empty and `HEAD` must equal
 * the `main` SHA that `git ls-remote` reports. Returns that SHA, and throws otherwise.
 *
 * This guards against verifying with yesterday's code or a stray local edit. It can't guard
 * against a hostile local agent or user: skip-worktree hides edits, and PATH shims,
 * `NODE_OPTIONS`, git hooks or an edited verifier can fake every answer it reads. That protection
 * comes from where it runs (a fresh clone, a clean environment, a separate user); see
 * docs/releasing.md.
 */
export function checkTrustRoot(exec) {
  const dirty = must(exec, "git", ["status", "--porcelain"]).trim();
  if (dirty !== "") {
    throw new VerifyError(
      `this checkout has local changes, so it may not be the verifier on main:\n${dirty}\n` +
        `Fix: run it from a clean checkout of main.`,
    );
  }
  const head = must(exec, "git", ["rev-parse", "HEAD"]).trim();
  const main = remoteMainCommit(exec);
  if (head !== main) {
    throw new VerifyError(
      `this checkout is at ${head}, not GitHub's main (${main}).\n` +
        `Fix: git fetch ${REMOTE_URL} main && git checkout --detach FETCH_HEAD, then re-run.`,
    );
  }
  return main;
}

/**
 * Whether `commit` is an ancestor of `mainSha`, the exact `main` commit read with `ls-remote`.
 * Comparing against that SHA, rather than a moving FETCH_HEAD, means a concurrent fetch can't
 * change the answer. A commit missing from main's history isn't on main. Anything else throws.
 */
export function isAncestorOfMain(exec, commit, mainSha) {
  must(exec, "git", ["fetch", "--quiet", "--no-tags", REMOTE_URL, mainSha]);
  const res = exec("git", ["merge-base", "--is-ancestor", commit, mainSha]);
  if (res.status === 0) return true;
  if (res.status === 1) return false;
  // 128: the commit isn't in the fetched history at all, so it isn't on main either.
  if (/not a valid commit|bad object|unknown revision|no such commit/i.test(res.stderr))
    return false;
  throw new VerifyError(`git merge-base failed:\n${res.stderr.trim()}`);
}

/**
 * Verify a staged (or, with `published`, an approved) release. Returns `{ ok, problems, notes,
 * stages }`. `stages` lists the stage ids that were verified, the only ones to approve. Throws
 * `VerifyError` when a prerequisite cannot be read at all.
 */
export async function verifyRelease({
  version,
  runId = null,
  published = false,
  provenanceAfterApproval = false,
  exec = defaultExec,
  fetchJson = defaultFetchJson,
  askOtp = defaultAskOtp,
  log = (line) => console.log(line),
  packages = PUBLISHED_PACKAGES,
} = {}) {
  if (!PLAIN_VERSION.test(String(version))) {
    throw new VerifyError(`version ${JSON.stringify(version)} is not a plain x.y.z`);
  }
  const tag = `v${version}`;
  const problems = [];
  const notes = [];
  const fail = (message) => {
    problems.push(message);
    log(`  ✗ ${message}`);
  };
  const pass = (message) => log(`  ✓ ${message}`);

  log(
    `Verifying ${published ? "the published" : "the staged"} release ${tag} of ${TRUSTED_REPOSITORY}`,
  );

  // 0. The verifier's own code is main's, unmodified.
  const mainSha = checkTrustRoot(exec);
  pass(`running from a clean checkout of GitHub's main (${mainSha})`);
  const npmRead = npmReader(exec, askOtp);

  // 1–2. The run, the tag and main.
  const run = resolveRun(exec, { tag, runId });
  pass(
    `run ${String(run.databaseId)} (${run.event}, ${run.conclusion}) at ${run.headSha}: ${run.url}`,
  );
  const tagCommit = remoteTagCommit(exec, tag);
  if (tagCommit !== run.headSha) {
    fail(`GitHub's ${tag} points at ${String(tagCommit)}, but the run built ${run.headSha}`);
  } else {
    pass(`${tag} on GitHub points at the run's commit`);
  }
  if (isAncestorOfMain(exec, run.headSha, mainSha)) pass(`${run.headSha} is on main`);
  else fail(`${run.headSha} is NOT on main: this run's workflow and code were not reviewed`);

  // 3. The run's own tarballs and their recorded integrity.
  const work = mkdtempSync(join(tmpdir(), "allw-verify-release-"));
  try {
    const artifactDir = join(work, "artifact");
    must(exec, "gh", [
      "run",
      "download",
      String(run.databaseId),
      "--repo",
      TRUSTED_REPOSITORY,
      "--name",
      RELEASE_ARTIFACT,
      "--dir",
      artifactDir,
    ]);
    let entries;
    try {
      entries = readVerifiedReleaseManifest(artifactDir);
    } catch (err) {
      throw new VerifyError(`the run's ${RELEASE_ARTIFACT} artifact is unusable: ${err.message}`);
    }
    const names = entries.map((e) => e.name).join(", ");
    const expected = packages.map((p) => p.name).join(", ");
    if (names !== expected) fail(`the run packed [${names}], not the release set [${expected}]`);
    for (const e of entries.filter((x) => x.version !== version)) {
      fail(`the run packed ${e.name}@${e.version}, not ${version}`);
    }
    pass(`the run's ${RELEASE_ARTIFACT} artifact matches its release-manifest.json`);

    const stages = [];
    for (const entry of entries) {
      log(`${entry.name}@${version}  (built ${entry.integrity})`);
      const expectedProv = { ...entry, version, commit: run.headSha, runId: run.databaseId };
      let found = [];
      if (published) {
        const integrity = parseJson(
          await npmRead(["view", `${entry.name}@${version}`, "dist.integrity", "--json"]),
          "npm view dist.integrity",
        );
        if (integrity === entry.integrity) pass("published integrity equals the run's tarball");
        else fail(`published integrity ${String(integrity)} is not the run's ${entry.integrity}`);
        const attestations = parseJson(
          await npmRead(["view", `${entry.name}@${version}`, "dist.attestations", "--json"]),
          "npm view dist.attestations",
        );
        if (typeof attestations?.url === "string")
          found = findStatements(await fetchJson(attestations.url));
      } else {
        const listed = parseJson(
          await npmRead(["stage", "list", entry.name, "--json"]),
          "npm stage list",
        );
        const open = (Array.isArray(listed) ? listed : []).filter(isOpenStage);
        const mine = open.filter((i) => i.version === version);
        for (const other of open.filter((i) => i.version !== version)) {
          fail(
            `unexpected open stage ${String(other.id)} (${entry.name}@${String(other.version)}): reject it`,
          );
        }
        if (mine.length !== 1) {
          fail(
            mine.length === 0
              ? `no open stage for ${entry.name}@${version}`
              : `${mine.length} open stages for ${entry.name}@${version} ` +
                  `(${mine.map((i) => i.id).join(", ")}): at most one can be this run's; reject the rest`,
          );
          continue;
        }
        const stageId = String(mine[0].id);
        const item = parseJson(
          await npmRead(["stage", "view", stageId, "--json"]),
          "npm stage view",
        );
        if (item.packageName !== entry.name || item.version !== version) {
          fail(`stage ${stageId} is ${String(item.packageName)}@${String(item.version)}`);
          continue;
        }
        if (item.tag !== undefined && item.tag !== RELEASE_DIST_TAG) {
          fail(`stage ${stageId} would set dist-tag ${String(item.tag)}, not ${RELEASE_DIST_TAG}`);
        }
        const downloadDir = mkdtempSync(join(work, "stage-"));
        await npmRead(["stage", "download", stageId], { cwd: downloadDir });
        const tarball = readdirSync(downloadDir).find((f) => f.endsWith(".tgz"));
        if (!tarball) throw new VerifyError(`npm stage download ${stageId} wrote no tarball`);
        const stagedIntegrity = integrityOf(readFileSync(join(downloadDir, tarball)));
        if (stagedIntegrity === entry.integrity) {
          pass(`stage ${stageId} holds exactly the run's tarball`);
          stages.push({ name: entry.name, version, stageId });
        } else {
          fail(`stage ${stageId} holds DIFFERENT bytes (${stagedIntegrity}): reject it`);
        }
        found = findStatements(item);
      }

      const prov = checkProvenance(found, expectedProv);
      if (prov.exposed) {
        if (prov.problems.length === 0)
          pass("provenance: release.yml at the tag, this commit, this run");
        for (const p of prov.problems) fail(p);
      } else if (!published && provenanceAfterApproval) {
        const note = `${entry.name}: npm exposes no provenance for the stage; check it after approving`;
        notes.push(note);
        log(`  ! ${note}`);
      } else {
        fail(
          published
            ? `no SLSA provenance attestation is published for ${entry.name}@${version}`
            : `npm stage view exposes no provenance for ${entry.name}@${version} ` +
                `(rerun with --provenance-after-approval to rely on the byte match, then verify --published)`,
        );
      }
    }

    const ok = problems.length === 0;
    log("");
    if (!ok) {
      log(
        `✗ ${problems.length} problem(s). Do NOT approve. Reject every stage of ${tag} you can't account for:`,
      );
      log("    npm stage reject <stage-id>");
    } else if (published) {
      log(
        `✓ ${tag} is published exactly as run ${String(run.databaseId)} built it, with matching provenance.`,
      );
    } else {
      log(
        `✓ Every stage of ${tag} is run ${String(run.databaseId)}'s exact tarball. Approve these, in order, and nothing else:`,
      );
      for (const s of stages) log(`    npm stage approve ${s.stageId}   # ${s.name}`);
      if (notes.length > 0) {
        log(`  Right after approving, check provenance:`);
        log(
          `    node scripts/verify-staged-release.mjs ${version} --published --run ${String(run.databaseId)}`,
        );
      }
    }
    return { ok, problems, notes, stages, run };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

function usage() {
  return [
    "usage: node scripts/verify-staged-release.mjs <x.y.z> [--run <run-id>] [--published]",
    "                                              [--provenance-after-approval]",
    "",
    "Before `npm stage approve`: checks that every pending stage of <x.y.z> is exactly the tarball a",
    "successful release.yml run built from the tag on main. With --published, checks the approved",
    "release instead. Exits non-zero on any mismatch. See docs/releasing.md.",
  ].join("\n");
}

/** Parse argv into verifyRelease options; throws a usage error string on bad input. */
export function parseArgs(argv) {
  const opts = { version: null, runId: null, published: false, provenanceAfterApproval: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--published") opts.published = true;
    else if (arg === "--provenance-after-approval") opts.provenanceAfterApproval = true;
    else if (arg === "--run") {
      const id = argv[++i];
      if (!/^\d+$/.test(id ?? "")) throw new Error("--run needs a numeric run id");
      opts.runId = id;
    } else if (!arg.startsWith("-") && opts.version === null) opts.version = arg;
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (opts.version === null) throw new Error("missing <x.y.z>");
  return opts;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(usage());
    process.exit(0);
  }
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    console.error(`${err.message}\n\n${usage()}`);
    process.exit(2);
  }
  try {
    const { ok } = await verifyRelease(opts);
    process.exit(ok ? 0 : 1);
  } catch (err) {
    console.error(`✗ ${err instanceof VerifyError ? err.message : err.stack}`);
    console.error("Do NOT approve.");
    process.exit(1);
  }
}
