/**
 * Tests for the maintainer's pre-approval check, driven through fake `gh` / `git` / `npm` runners so
 * no registry, GitHub or network is involved. The central guarantee: the script passes only when
 * every pending stage is byte-for-byte the tarball a successful `release.yml` run built from a tag
 * whose commit is on `main`. Anything else, including a hostile run that writes its own job
 * summary, makes it exit non-zero.
 *
 * @see ../docs/releasing.md
 * @see https://docs.npmjs.com/staged-publishing
 * @see https://docs.npmjs.com/generating-provenance-statements (npm's GitHub provenance statement)
 * @see https://slsa.dev/spec/v1.0/provenance
 */

import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  RELEASE_ARTIFACT,
  findStatements,
  isOpenStage,
  parseArgs,
  provenanceProblems,
  sriToHex,
  verifyRelease,
} from "./verify-staged-release.mjs";
import { integrityOf } from "./release-packages.mjs";

const VERSION = "0.2.0";
const TAG = `v${VERSION}`;
const SHA = "a".repeat(40);
const RUN_ID = 4242;
const MAIN_SHA = "d".repeat(40);
const PACKAGES = [
  { name: "@allw/sdk", dir: "packages/sdk" },
  { name: "@allw/hook", dir: "packages/hook" },
];

const tarballFile = (name) => `${name.replace("@", "").replace("/", "-")}-${VERSION}.tgz`;
const bytesOf = (name) => `tarball bytes of ${name}`;
const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

/**
 * npm's GitHub Actions provenance statement for `name` as `release.yml` at `TAG` in run `RUN_ID`
 * builds it. The shape follows libnpmpublish's generateProvenance. The options alter one field
 * (bytes, a workflow field, the commit or the run) to model a wrong attestation.
 */
function statement(
  name,
  { bytes = bytesOf(name), workflow = {}, commit = SHA, runId = RUN_ID } = {},
) {
  return {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {
        name: `pkg:npm/${name.replace("@", "%40")}@${VERSION}`,
        digest: { sha512: sriToHex(integrityOf(bytes)) },
      },
    ],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: {
            ref: `refs/tags/${TAG}`,
            repository: "https://github.com/mike-north/allw",
            path: ".github/workflows/release.yml",
            ...workflow,
          },
        },
        resolvedDependencies: [
          {
            uri: `git+https://github.com/mike-north/allw@refs/tags/${TAG}`,
            digest: { gitCommit: commit },
          },
        ],
      },
      runDetails: {
        metadata: {
          invocationId: `https://github.com/mike-north/allw/actions/runs/${runId}/attempts/1`,
        },
      },
    },
  };
}

const bundle = (stmt) => ({
  mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
  dsseEnvelope: {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(stmt)).toString("base64"),
  },
});

/**
 * Fake world. `stages[name]` lists `{ id, version, status, bytes, provenance }` (provenance is a
 * statement embedded in the stage view, or undefined when npm exposes none). `artifact` overrides
 * the tarball bytes the run built.
 */
function fakeWorld({
  run = {
    databaseId: RUN_ID,
    headSha: SHA,
    headBranch: TAG,
    event: "push",
    status: "completed",
    conclusion: "success",
    url: "https://example.test/run",
  },
  runs = null,
  tagCommit = SHA,
  onMain = true,
  stages = null,
  published = null,
  mainSha = MAIN_SHA,
  head = MAIN_SHA,
  dirty = "",
  npmOtp = null,
} = {}) {
  const calls = [];
  /** Every spawn as the child would see it: argv and the extra environment. */
  const spawned = [];
  const stageMap =
    stages ??
    Object.fromEntries(
      PACKAGES.map((p, i) => [
        p.name,
        [
          {
            id: uuid(i + 1),
            version: VERSION,
            status: "pending",
            bytes: bytesOf(p.name),
            provenance: statement(p.name),
          },
        ],
      ]),
    );
  const byId = new Map(
    Object.entries(stageMap).flatMap(([name, list]) => list.map((s) => [s.id, { ...s, name }])),
  );
  const ok = (stdout = "") => ({ status: 0, stdout, stderr: "" });

  function exec(cmd, args, opts = {}) {
    calls.push([cmd, ...args]);
    spawned.push({ argv: [cmd, ...args], env: opts.env });
    const line = [cmd, ...args].join(" ");
    if (cmd === "gh" && args[1] === "view") return ok(JSON.stringify(run));
    if (cmd === "gh" && args[1] === "list") return ok(JSON.stringify(runs ?? [run]));
    if (cmd === "gh" && args[1] === "download") {
      const dir = args[args.indexOf("--dir") + 1];
      assert.equal(args[args.indexOf("--name") + 1], RELEASE_ARTIFACT);
      mkdirSync(dir, { recursive: true });
      const entries = PACKAGES.map((p) => {
        writeFileSync(join(dir, tarballFile(p.name)), bytesOf(p.name));
        return {
          name: p.name,
          version: VERSION,
          file: tarballFile(p.name),
          integrity: integrityOf(bytesOf(p.name)),
        };
      });
      writeFileSync(join(dir, "release-manifest.json"), JSON.stringify(entries));
      return ok();
    }
    if (cmd === "git" && args[0] === "status") return ok(dirty);
    if (cmd === "git" && args[0] === "rev-parse") return ok(`${head}\n`);
    if (cmd === "git" && args[0] === "ls-remote" && args.includes("refs/heads/main")) {
      return ok(`${mainSha}\trefs/heads/main\n`);
    }
    if (cmd === "git" && args[0] === "ls-remote") {
      return ok(tagCommit ? `${tagCommit}\trefs/tags/${TAG}\n` : "");
    }
    if (cmd === "git" && args[0] === "fetch") return ok();
    if (cmd === "git" && args[0] === "merge-base") {
      // Always against the exact main SHA from ls-remote, never a moving FETCH_HEAD.
      assert.equal(args.at(-1), mainSha);
      if (onMain === "missing") {
        return { status: 128, stdout: "", stderr: `fatal: Not a valid commit name ${args[2]}` };
      }
      if (onMain === "error") return { status: 128, stdout: "", stderr: "fatal: disk on fire" };
      return { status: onMain ? 0 : 1, stdout: "", stderr: "" };
    }
    // Auth-and-writes 2FA: npm's stage reads fail with EOTP unless given the code (npm_config_otp).
    if (cmd === "npm" && args[0] === "stage" && npmOtp && opts.env?.npm_config_otp !== npmOtp) {
      return {
        status: 1,
        stdout: "",
        stderr: "npm error code EOTP\nnpm error This operation requires a one-time password.",
      };
    }
    if (cmd === "npm" && args[0] === "stage" && args[1] === "list") {
      const list = (stageMap[args[2]] ?? []).map(({ id, version, status }) => ({
        id,
        packageName: args[2],
        version,
        status,
        tag: "latest",
      }));
      return ok(JSON.stringify(list));
    }
    if (cmd === "npm" && args[0] === "stage" && args[1] === "view") {
      const s = byId.get(args[2]);
      const item = {
        id: s.id,
        packageName: s.name,
        version: s.version,
        status: s.status,
        tag: "latest",
        actor: "github-actions",
        shasum: "x",
      };
      if (s.provenance) item.provenance = bundle(s.provenance);
      return ok(JSON.stringify(item));
    }
    if (cmd === "npm" && args[0] === "stage" && args[1] === "download") {
      const s = byId.get(args[2]);
      writeFileSync(join(opts.cwd, `${tarballFile(s.name).slice(0, -4)}-${s.id}.tgz`), s.bytes);
      return ok(`${s.id}.tgz\n`);
    }
    if (cmd === "npm" && args[0] === "view") {
      const name = args[1].slice(0, args[1].lastIndexOf("@"));
      const pub = published?.[name];
      if (args[2] === "dist.integrity")
        return ok(JSON.stringify(pub?.integrity ?? integrityOf(bytesOf(name))));
      if (args[2] === "dist.attestations")
        return ok(JSON.stringify({ url: `https://registry.example.test/att/${name}` }));
    }
    throw new Error(`unexpected call: ${line}`);
  }

  async function fetchJson(url) {
    const name = url.slice(url.lastIndexOf("/att/") + 5);
    const stmt = published?.[name]?.statement ?? statement(name);
    return {
      attestations: [{ predicateType: "https://slsa.dev/provenance/v1", bundle: bundle(stmt) }],
    };
  }

  return { exec, fetchJson, calls, spawned };
}

async function verify(world, opts = {}) {
  const lines = [];
  const result = await verifyRelease({
    version: VERSION,
    exec: world.exec,
    fetchJson: world.fetchJson,
    askOtp: async () => null,
    log: (l) => lines.push(l),
    packages: PACKAGES,
    ...opts,
  });
  return { ...result, out: lines.join("\n") };
}

test("a release staged by the trusted run passes, and lists exactly the stage ids to approve", async () => {
  const { ok, problems, stages, out } = await verify(fakeWorld());
  assert.deepEqual(problems, []);
  assert.equal(ok, true);
  assert.deepEqual(
    stages.map((s) => s.stageId),
    [uuid(1), uuid(2)],
  );
  assert.match(out, new RegExp(`npm stage approve ${uuid(1)}`));
});

// The attack the summary can't stop: a modified release.yml on a branch, with a v* tag pushed at it.
// Its run is successful and writes its own summary, but its commit is not on main.
test("a run whose commit is not on main fails, even if everything else matches", async () => {
  const { ok, problems } = await verify(fakeWorld({ onMain: false }));
  assert.equal(ok, false);
  assert.ok(problems.some((p) => /NOT on main/.test(p)));
});

test("a stage holding bytes other than the run's tarball fails", async () => {
  const stages = {
    "@allw/sdk": [
      {
        id: uuid(1),
        version: VERSION,
        status: "pending",
        bytes: "evil bytes",
        provenance: statement("@allw/sdk"),
      },
    ],
    "@allw/hook": [
      {
        id: uuid(2),
        version: VERSION,
        status: "pending",
        bytes: bytesOf("@allw/hook"),
        provenance: statement("@allw/hook"),
      },
    ],
  };
  const { ok, problems, stages: verified } = await verify(fakeWorld({ stages }));
  assert.equal(ok, false);
  assert.ok(problems.some((p) => /DIFFERENT bytes/.test(p)));
  assert.ok(
    !verified.some((s) => s.stageId === uuid(1)),
    "never offers the bad stage for approval",
  );
});

test("a second open stage for the same version fails: approve only stages you started", async () => {
  const stages = {
    "@allw/sdk": [
      {
        id: uuid(1),
        version: VERSION,
        status: "pending",
        bytes: bytesOf("@allw/sdk"),
        provenance: statement("@allw/sdk"),
      },
      { id: uuid(9), version: VERSION, status: "pending", bytes: "other", provenance: undefined },
    ],
    "@allw/hook": [
      {
        id: uuid(2),
        version: VERSION,
        status: "pending",
        bytes: bytesOf("@allw/hook"),
        provenance: statement("@allw/hook"),
      },
    ],
  };
  const { ok, problems } = await verify(fakeWorld({ stages }));
  assert.equal(ok, false);
  assert.ok(problems.some((p) => /2 open stages/.test(p)));
});

test("an open stage of another version fails; closed stages are ignored", async () => {
  const stages = {
    "@allw/sdk": [
      {
        id: uuid(1),
        version: VERSION,
        status: "pending",
        bytes: bytesOf("@allw/sdk"),
        provenance: statement("@allw/sdk"),
      },
      { id: uuid(7), version: "0.1.9", status: "rejected", bytes: "x" },
      { id: uuid(8), version: "9.9.9", status: "pending", bytes: "x" },
    ],
    "@allw/hook": [
      {
        id: uuid(2),
        version: VERSION,
        status: "pending",
        bytes: bytesOf("@allw/hook"),
        provenance: statement("@allw/hook"),
      },
    ],
  };
  const { problems } = await verify(fakeWorld({ stages }));
  assert.deepEqual(problems.filter((p) => /unexpected open stage/.test(p)).length, 1);
  assert.ok(problems[0].includes(uuid(8)));
});

test("provenance naming another workflow, ref, commit or run fails", async () => {
  for (const [label, stmt] of [
    ["path", statement("@allw/sdk", { workflow: { path: ".github/workflows/evil.yml" } })],
    ["ref", statement("@allw/sdk", { workflow: { ref: "refs/heads/evil" } })],
    [
      "repository",
      statement("@allw/sdk", { workflow: { repository: "https://github.com/someone/fork" } }),
    ],
    ["commit", statement("@allw/sdk", { commit: "b".repeat(40) })],
    ["run", statement("@allw/sdk", { runId: 999 })],
    ["subject", statement("@allw/sdk", { bytes: "other bytes" })],
  ]) {
    const stages = {
      "@allw/sdk": [
        {
          id: uuid(1),
          version: VERSION,
          status: "pending",
          bytes: bytesOf("@allw/sdk"),
          provenance: stmt,
        },
      ],
      "@allw/hook": [
        {
          id: uuid(2),
          version: VERSION,
          status: "pending",
          bytes: bytesOf("@allw/hook"),
          provenance: statement("@allw/hook"),
        },
      ],
    };
    const { ok } = await verify(fakeWorld({ stages }));
    assert.equal(ok, false, `wrong provenance ${label} must fail`);
  }
});

test("no provenance on the stage fails by default, and is a note with --provenance-after-approval", async () => {
  const stages = Object.fromEntries(
    PACKAGES.map((p, i) => [
      p.name,
      [{ id: uuid(i + 1), version: VERSION, status: "pending", bytes: bytesOf(p.name) }],
    ]),
  );
  const strict = await verify(fakeWorld({ stages }));
  assert.equal(strict.ok, false);
  assert.ok(strict.problems.every((p) => /exposes no provenance/.test(p)));

  const relaxed = await verify(fakeWorld({ stages }), { provenanceAfterApproval: true });
  assert.equal(relaxed.ok, true);
  assert.equal(relaxed.notes.length, PACKAGES.length);
  assert.match(
    relaxed.out,
    new RegExp(`verify-staged-release\\.mjs ${VERSION} --published --run ${RUN_ID}`),
  );
});

test("the tag must point at the run's commit on GitHub", async () => {
  const { ok, problems } = await verify(fakeWorld({ tagCommit: "c".repeat(40) }));
  assert.equal(ok, false);
  assert.ok(problems.some((p) => /points at c{40}/.test(p)));
});

test("run selection: a failed or foreign --run is refused; several candidates need --run", async () => {
  const failed = fakeWorld({
    run: { databaseId: 1, headSha: SHA, headBranch: TAG, event: "push", conclusion: "failure" },
  });
  await assert.rejects(verify(failed, { runId: "1" }), /not a successful release run/);
  const other = fakeWorld({
    run: {
      databaseId: 1,
      headSha: SHA,
      headBranch: "main",
      event: "workflow_dispatch",
      conclusion: "success",
    },
  });
  await assert.rejects(verify(other, { runId: "1" }), /not a successful release run/);
  const good = {
    databaseId: 1,
    headSha: SHA,
    headBranch: TAG,
    event: "push",
    conclusion: "success",
  };
  const two = fakeWorld({ runs: [good, { ...good, databaseId: 2, event: "workflow_dispatch" }] });
  await assert.rejects(verify(two), /2 successful release\.yml runs .*pass --run/);
  await assert.rejects(verify(fakeWorld({ runs: [] })), /no successful release\.yml run/);
});

test("--published checks the public integrity and attestation against the run", async () => {
  assert.equal((await verify(fakeWorld(), { published: true })).ok, true);
  const swapped = fakeWorld({ published: { "@allw/hook": { integrity: integrityOf("other") } } });
  assert.equal((await verify(swapped, { published: true })).ok, false);
  const foreign = fakeWorld({
    published: { "@allw/sdk": { statement: statement("@allw/sdk", { runId: 7 }) } },
  });
  assert.equal((await verify(foreign, { published: true })).ok, false);
});

test("rejects a non-plain version before touching anything", async () => {
  const world = fakeWorld();
  await assert.rejects(verify(world, { version: "0.2.0-rc.1" }), /not a plain x\.y\.z/);
  assert.deepEqual(world.calls, []);
});

test("helpers: stage status, DSSE decoding, SRI to hex, provenance checks, argv", () => {
  assert.equal(isOpenStage({ status: "pending" }), true);
  assert.equal(isOpenStage({ status: "unknown-new-state" }), true, "unknown states count as open");
  assert.equal(isOpenStage({ status: "rejected" }), false);
  assert.equal(isOpenStage({ status: "approved" }), false);

  const stmt = statement("@allw/sdk");
  assert.deepEqual(findStatements({ deep: [{ x: bundle(stmt) }] }), [stmt]);
  assert.deepEqual(findStatements({ dsseEnvelope: { payload: "%%%" } }), []);
  assert.equal(sriToHex(integrityOf("abc")).length, 128);
  const expected = {
    name: "@allw/sdk",
    version: VERSION,
    integrity: integrityOf(bytesOf("@allw/sdk")),
    commit: SHA,
    runId: RUN_ID,
  };
  assert.deepEqual(provenanceProblems(stmt, expected), []);
  assert.match(provenanceProblems({ predicateType: "x" }, expected)[0], /predicate/);

  assert.deepEqual(parseArgs(["0.2.0", "--run", "12", "--published"]), {
    version: "0.2.0",
    runId: "12",
    published: true,
    provenanceAfterApproval: false,
  });
  assert.throws(() => parseArgs(["--run", "abc", "0.2.0"]), /numeric run id/);
  assert.throws(() => parseArgs([]), /missing/);
  assert.throws(() => parseArgs(["0.2.0", "--bogus"]), /unknown argument/);
});

// The verifier's code and constants come from the local checkout. It must refuse to run from one
// that is modified or isn't GitHub's current main, before it reads anything else.
test("refuses to run from a dirty checkout, or one that isn't GitHub's main", async () => {
  const dirty = fakeWorld({ dirty: " M scripts/release-packages.mjs\n" });
  await assert.rejects(verify(dirty), /local changes/);
  assert.ok(!dirty.calls.some(([cmd]) => cmd === "gh" || cmd === "npm"), "stops before any check");

  const behind = fakeWorld({ head: "e".repeat(40) });
  await assert.rejects(verify(behind), /not GitHub's main/);
  assert.ok(!behind.calls.some(([cmd]) => cmd === "gh" || cmd === "npm"));
});

// npm 11.21's stage list/view/download don't prompt for 2FA, so on auth-and-writes accounts they
// fail with EOTP. The verifier must ask for a code, retry with it, and reuse the code. The code
// must never be in argv: npm doesn't redact `--otp=<code>`, so it would reach `ps` and npm's log.
test("stage reads that fail with EOTP are retried with a one-time password", async () => {
  const world = fakeWorld({ npmOtp: "246810" });
  const asks = [];
  const { ok, problems } = await verify(world, {
    askOtp: async (what) => {
      asks.push(what);
      return "246810";
    },
  });
  assert.deepEqual(problems, []);
  assert.equal(ok, true);
  assert.equal(asks.length, 1, "asks once, then reuses the code");
  assert.ok(
    world.spawned.every(({ argv }) => !argv.some((a) => a.includes("246810"))),
    "the code is never in argv",
  );
  const npmCalls = world.spawned.filter(({ argv }) => argv[0] === "npm");
  assert.ok(
    npmCalls.some(({ env }) => env?.npm_config_otp === "246810"),
    "the code goes via env",
  );
  assert.ok(
    npmCalls.every(({ argv }) => argv.includes("--logs-max=0")),
    "no npm log file",
  );
});

test("stage reads that need a one-time password fail closed without one", async () => {
  const world = fakeWorld({ npmOtp: "246810" });
  await assert.rejects(verify(world), /needs a one-time password, and none was given/);
  assert.ok(
    !world.calls.some(
      ([cmd, sub, verb]) => cmd === "npm" && sub === "stage" && verb === "download",
    ),
  );
});

test("merge-base exit 128: a commit missing from main's history is not on main; other errors throw", async () => {
  const missing = await verify(fakeWorld({ onMain: "missing" }));
  assert.equal(missing.ok, false);
  assert.ok(missing.problems.some((p) => /NOT on main/.test(p)));
  await assert.rejects(verify(fakeWorld({ onMain: "error" })), /git merge-base failed/);
});
