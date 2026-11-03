# Releasing the npm packages

How the public `@allw/*` packages get to npm. Releases are published **only from CI** using
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers). The release workflow gets a
short-lived OIDC token from GitHub Actions and exchanges it with npm. There is no `NPM_TOKEN` secret,
and every version carries a provenance attestation that links it to the workflow run that built it.

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
release workflow and the bootstrap below both read it, so they cannot drift apart.

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

2. After it merges and CI is green on `main`, tag that commit and push the tag:

   ```sh
   git tag v0.2.0 <merge-commit-on-main>
   git push https://github.com/mike-north/allw.git v0.2.0
   ```

3. [`.github/workflows/release.yml`](../.github/workflows/release.yml) then runs in two jobs:
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

## One-time setup (bootstrap)

npm can only attach a trusted publisher to a package that **already exists**, and the `@allw/*`
packages have never been published. Run this once:

1. **Create the npm org `allw`** if `@allw` isn't owned yet: <https://www.npmjs.com/org/create>
   (free plan, public packages). There is no CLI for creating an org. The bootstrap checks for the org
   and stops with this instruction if it's missing.
2. **Log in and enable 2FA**. `npm trust` requires 2FA:

   ```sh
   npm install -g npm@^11.15.0   # `npm trust` first shipped in 11.15.0
   npm login
   ```

3. **Run the bootstrap.** Do a dry run first:

   ```sh
   node scripts/npm-bootstrap-trusted-publishing.mjs --dry-run
   node scripts/npm-bootstrap-trusted-publishing.mjs
   ```

   For each package, the bootstrap:
   - publishes an **empty name-reservation placeholder** if the package doesn't exist yet.
     It is version `0.0.0-bootstrap.0` under dist-tag `bootstrap`, has no code, and importing it
     throws an error that points at the real releases. The bootstrap lists these and asks before
     publishing them. This is the only publish that ever happens from a laptop, and it ships no real
     code: the first real version comes from CI, with provenance.
   - attaches the trusted publisher with `npm trust github` (workflow `release.yml`, repo
     `mike-north/allw`, environment `npm-publish`, allowed action `npm publish`). If a different
     trust config is already attached, it offers to revoke and replace it. If the CLI call fails, it prints the npmjs.com page and the exact field values to
     enter by hand.
   - prints a checklist of what's done and what's left.

   It is idempotent. Every step reads registry state first, so re-running it does nothing once
   everything is configured.

4. **Cut the first release within 48 hours.** npm expires a trusted-publisher config that hasn't
   completed a publish within 48 hours. If it expires, re-run the bootstrap to recreate it.
5. **Recommended hardening**:
   - In the repo's settings, under [Environments](https://github.com/mike-north/allw/settings/environments),
     give `npm-publish` a required reviewer and allow deployments only from `v*` tags. Every release
     then waits for a human approval.
   - After the first CI release, set each package's npm _Settings → Publishing access_ to **Require
     two-factor authentication and disallow tokens**. Trusted publishing keeps working because it
     doesn't use tokens.
   - Deprecate the placeholders. The bootstrap prints the `npm deprecate` commands.

npm also offers [staged publishing](https://docs.npmjs.com/staged-publishing), where CI uploads with
`npm stage publish` and a maintainer approves the release with 2FA. We don't use it: the protected
`npm-publish` environment already puts a human gate in front of every release. To switch, re-run the
bootstrap after changing `--allow-publish` to `--allow-stage-publish` in its `trustGithubArgs`, and
change the publish step to `npm stage publish`.

## What can't be automated

- **Creating the npm org.** npm has no CLI or API for it.
- **The first publish of each name.** npm only attaches a trusted publisher to a package that already
  exists, so the bootstrap publishes the empty placeholder described above.
- **2FA prompts.** Each `npm publish` and `npm trust` call from your machine asks you for a second
  factor.
- **GitHub environment protection rules.** These are repo settings, so you configure them yourself.

## Changing the trusted identity

Renaming `release.yml`, changing the `npm-publish` environment, or moving the repo changes the
identity npm trusts. Update the constants in `scripts/release-packages.mjs`, then re-run the bootstrap.
It detects the mismatched configs and offers to replace them, and the new configs need a publish
within 48 hours.
