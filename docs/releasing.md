# Releasing the npm packages

How the public `@allw/*` packages get to npm. Releases are published **only from CI** using
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers). The release workflow gets a
short-lived OIDC token from GitHub Actions and exchanges it with npm. There is no `NPM_TOKEN` secret,
and every version carries a provenance attestation that links it to the workflow run that built it.

## First-time setup, ~10 minutes

Do this once. It reserves the package names and connects npm to the release workflow. It publishes no
real code and doesn't start a release.

```sh
# 1. In a browser, signed in to npmjs.com, create the free npm org "allw":
#      https://www.npmjs.com/org/create   (organization name: allw; plan: free / unlimited public)

# 2. Get npm 11.15+ (needed for `npm trust`) and log in. Your npm account must have 2FA turned on.
npm install -g npm@^11.15.0
npm login

# 3. Get a checkout of this repo (use main once the release tooling has merged).
git clone --branch infra/npm-trusted-publishing https://github.com/mike-north/allw.git
cd allw
pnpm install

# 4. Preview the plan (no changes), then run it for real.
node scripts/npm-bootstrap-trusted-publishing.mjs --dry-run
node scripts/npm-bootstrap-trusted-publishing.mjs
```

The real run prompts you at these points, in this order. Answer `y` to each. Answering `N` (or just
pressing Enter) skips that step only, and you can re-run the script later.

1. **`Publish 5 release-package placeholder(s) now? [y/N]`** publishes empty placeholders for
   `@allw/sdk`, `@allw/hook`, `@allw/approver`, `@allw/codex-hook` and `@allw/openclaw-bridge`. npm
   then asks for 2FA on each publish, either a one-time code or a browser approval.
2. **`Configure 5 trusted publisher(s) now? [y/N]`** attaches the release workflow to those
   packages. npm asks for 2FA again.
3. **`Publish 5 unscoped name-claim placeholder(s) now? [y/N]`** claims `allw`, `allw-hook`,
   `allw-approver`, `allw-codex-hook` and `allw-openclaw-bridge` against squatting. npm asks for 2FA on
   each publish.

If npm needs 2FA just to read a package's trust settings, the script shows them and asks
**`Does the output above show repository mike-north/allw, file release.yml, environment npm-publish?`**
Answer `y` if they match.

The run ends with a summary table and a **Still to do** list. A successful run shows every
`@allw/*` row as `configured (this run)` and every unscoped row as `placeholder published`.
Re-running it is safe: anything already done is skipped. If it stops at a precondition, such as not
being logged in or a missing org, the error message says exactly what to fix.

**The first real release is on hold, and that's fine.** npm expires a trusted-publisher config that
hasn't completed a publish within 48 hours, so the configs created today will lapse. Right before the
first real release, recreate them with
`node scripts/npm-bootstrap-trusted-publishing.mjs --refresh-trust`, then push the release tag within
48 hours (see [Cutting a release](#cutting-a-release)).

## What gets published

| Package                 | Notes                                            |
| ----------------------- | ------------------------------------------------ |
| `@allw/sdk`             | Includes the vendored WASM build of `allw-core`. |
| `@allw/hook`            | Claude Code PreToolUse hook.                     |
| `@allw/approver`        | Stand-in software approver.                      |
| `@allw/codex-hook`      | Codex hook.                                      |
| `@allw/openclaw-bridge` | OpenClaw gateway operator client.                |

They are published in this order, which is dependency order. `@allw/relay`, `@allw/web-approver` and
the examples are private: they are deployed or run from source, never published. The list, its order
and the trusted identity (repo `mike-north/allw`, workflow `release.yml`, environment `npm-publish`)
are defined in one place, [`scripts/release-packages.mjs`](../scripts/release-packages.mjs). The
release workflow and the bootstrap both read it, so they cannot drift apart.

**Claimed, never released.** That module's `CLAIM_ONLY_NAMES` holds the unscoped names `allw`,
`allw-hook`, `allw-approver`, `allw-codex-hook` and `allw-openclaw-bridge`. `npx <bin>`, run outside a
project that has the scoped package installed, fetches a registry package named after the bin, so
whoever owns `allw-hook` controls what `npx allw-hook` runs. Each of these names holds a permanent
inert placeholder whose import and bin throw an error that points at the real `@allw/*` package. None
of them gets a trusted publisher, and the release workflow never publishes them. A test enforces that
every bin a published package declares is in this list.

## Versioning: lockstep

Every published package has the same version, and a release is the tag `v<version>`. The packages
share one WASM core and pin each other exactly (`pnpm pack` rewrites `workspace:*` to the sibling's
version), so versioning them separately would add bookkeeping without real independence. The repo
has no changesets. If it adopts changesets later, its "version packages" step replaces the manual
bump below, and publishing stays in `release.yml`.

## Cutting a release

1. Bump the version in a normal PR:

   ```sh
   node scripts/release-packages.mjs set-version 0.2.0
   node scripts/release-packages.mjs verify v0.2.0   # lockstep, public, repo URL, dependency order
   ```

2. Unless the trusted-publisher configs were created in the last 48 hours, recreate them now, because
   they expire if no publish has used them yet:

   ```sh
   node scripts/npm-bootstrap-trusted-publishing.mjs --refresh-trust
   ```

   This step is only needed until the first release succeeds. After that, the configs are validated
   and no longer expire.

3. After the PR merges and CI is green on `main`, tag that commit and push the tag:

   ```sh
   git tag v0.2.0 <merge-commit-on-main>
   git push https://github.com/mike-north/allw.git v0.2.0
   ```

4. [`.github/workflows/release.yml`](../.github/workflows/release.yml) then runs in two jobs:
   - **build** (read-only token): refuses tags that are not on `main`, checks the tag against every
     manifest, builds the WASM and the packages, runs the release-script tests and the
     [packaged-install smoke](../scripts/smoke-packaged-install.mjs) (pack, then a clean `npm install`,
     then headless checks), packs the tarballs, and uploads them as an artifact.
   - **publish** (environment `npm-publish`, `id-token: write`): installs npm ≥ 11.5.1 and runs
     `npm publish --provenance` on those exact tarballs, in order. It installs no dependencies and
     runs no package scripts. Versions already on the registry are skipped, so re-running a release
     that failed partway finishes it.

To rehearse a release, run the workflow manually (**Actions → Release → Run workflow**) from a branch.
The rehearsal does everything except publish, and runs `npm publish --dry-run` instead. If you
dispatch it on a `v*` tag, it publishes, which is how to retry a failed release.

## What the bootstrap does

[`scripts/npm-bootstrap-trusted-publishing.mjs`](../scripts/npm-bootstrap-trusted-publishing.mjs)
reads registry state before every step and asks before every write.

1. **Preconditions.** It checks that npm is at least 11.15.0, that you're logged in (`npm whoami`),
   that the `@allw` org exists and you're a member, and that the release manifests are consistent.
   It warns if 2FA looks disabled.
2. **Release-package placeholders.** npm can only attach a trusted publisher to a package that
   already exists. For each `@allw/*` package that doesn't, the bootstrap publishes an empty
   placeholder: version `0.0.0-bootstrap.0`, dist-tag `bootstrap`, no code, and importing it throws
   an error that points at the real release. This and the name claims below are the only publishes
   that ever happen from a laptop. Real code ships only from CI, with provenance.
3. **Trusted publishers.** It runs `npm trust github` on each `@allw/*` package (workflow
   `release.yml`, repo `mike-north/allw`, environment `npm-publish`, allowed action `npm publish`).
   If a different config is already attached, it offers to revoke and replace it, and
   `--refresh-trust` replaces all of them. If the CLI call fails, it prints the npmjs.com page and
   the exact field values to enter by hand.
4. **Name claims.** For each name in `CLAIM_ONLY_NAMES` that is free, it publishes the inert claim
   placeholder. If someone else already owns one of those names, it reports that in the checklist
   and does not try to publish over it.
5. **Checklist.** It prints what's done and what's left, including the optional hardening below.

## Recommended hardening

- In the repo's settings, under [Environments](https://github.com/mike-north/allw/settings/environments),
  give `npm-publish` a required reviewer and allow deployments only from `v*` tags. Every release then
  waits for a human approval.
- After the first CI release, set each `@allw/*` package's npm _Settings → Publishing access_ to
  **Require two-factor authentication and disallow tokens**. Trusted publishing keeps working because
  it doesn't use tokens.
- After the first CI release, deprecate the `@allw/*` placeholders. The bootstrap prints the
  `npm deprecate` commands. The unscoped claim placeholders stay as they are.

npm also offers [staged publishing](https://docs.npmjs.com/staged-publishing), where CI uploads with
`npm stage publish` and a maintainer approves the release with 2FA. We don't use it: the protected
`npm-publish` environment already puts a human gate in front of every release. To switch, change
`--allow-publish` to `--allow-stage-publish` in the bootstrap's `trustGithubArgs`, run it with
`--refresh-trust`, and change the publish step to `npm stage publish`.

## What can't be automated

- **Creating the npm org.** npm has no CLI or API for it.
- **The first publish of each name.** npm only attaches a trusted publisher to a package that already
  exists, so the bootstrap publishes the empty placeholder described above.
- **2FA prompts.** Each `npm publish` and `npm trust` call from your machine asks you for a second
  factor.
- **GitHub environment protection rules.** These are repo settings, so you configure them yourself.

## Changing the trusted identity

Renaming `release.yml`, changing the `npm-publish` environment, or moving the repo changes the
identity npm trusts. Update the constants in `scripts/release-packages.mjs`, then re-run the
bootstrap. It detects the mismatched configs and offers to replace them. Replacement configs also need
a publish within 48 hours, or they expire.
