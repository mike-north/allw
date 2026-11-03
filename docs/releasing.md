# Releasing the npm packages

How the public `@allw/*` packages get to npm. CI **stages** each release with
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers) and
[staged publishing](https://docs.npmjs.com/staged-publishing). A maintainer then **approves** each
staged version with npm 2FA. Nothing is public until that approval.

- The release workflow gets a short-lived OIDC token from GitHub Actions and exchanges it with npm.
  There is no `NPM_TOKEN` secret.
- The trusted-publisher config on each package is **stage-only** (`--allow-stage-publish`). The
  workflow's token can run `npm stage publish` and nothing else. It can't publish directly, and it
  can't move a dist-tag.
- The release gate is the maintainer's npm 2FA approval (`npm stage approve`). The GitHub-side checks
  (tag on `main`, the `npm-publish` environment) are defense in depth, not the gate. Anyone with write
  access to the repo can edit the workflow in the commit they tag.

Agents never push `v*` tags, never dispatch the Release workflow, and never approve or reject staged
packages (see [`ENG_TEAM_INSTRUCTIONS.md`](../ENG_TEAM_INSTRUCTIONS.md)). Releases are cut by a human
maintainer.

## First-time setup, ~10 minutes

Do this once. It reserves the package names and connects npm to the release workflow. It publishes no
real code and doesn't start a release. The `@allw` org and the `@allw/*` placeholders already exist,
so on this repo a run only creates the stage-only trust configs and claims any free unscoped names.

```sh
# 1. In a browser, signed in to npmjs.com, create the free npm org "allw" (already done):
#      https://www.npmjs.com/org/create   (organization name: allw; plan: free / unlimited public)

# 2. Get npm 11.15+ (needed for `npm trust` and `npm stage`) and log in. Your npm account must have
#    2FA turned on.
npm install -g npm@^11.15.0
npm login

# 3. Get a checkout of this repo.
git clone https://github.com/mike-north/allw.git
cd allw
pnpm install

# 4. Make sure no trust config can publish directly: list every config with its permissions,
#    then revoke each one that isn't exactly stage-only. This creates nothing.
node scripts/npm-bootstrap-trusted-publishing.mjs --audit-trust --dry-run
node scripts/npm-bootstrap-trusted-publishing.mjs --audit-trust

# 5. Preview the plan (no changes), then run it for real.
node scripts/npm-bootstrap-trusted-publishing.mjs --dry-run
node scripts/npm-bootstrap-trusted-publishing.mjs

# 6. Log out of npm when you're done. Log back in only to release.
npm logout
```

The real run prompts you at these points, in this order. It only asks about steps that still have
work to do. Answer `y` to each. Answering `N` (or just pressing Enter) skips that step only, and you
can re-run the script later.

1. **`Publish N release-package placeholder(s) now? [y/N]`** publishes empty placeholders for any of
   `@allw/sdk`, `@allw/hook`, `@allw/approver`, `@allw/codex-hook` and `@allw/openclaw-bridge` that
   don't exist yet. npm asks for 2FA on each publish, either a one-time code or a browser approval.
2. **`Configure N trusted publisher(s) now? [y/N]`** attaches the release workflow to those packages,
   allowed to **stage only**. A package can hold several configs, and any one of them is enough to
   publish. So the script revokes **every** config that isn't exactly the stage-only one, including
   direct-publish (`--allow-publish`) ones. It revokes those first, then creates the stage-only
   config if it's missing. It lists each revoke and create before asking. npm asks for 2FA on each
   change.
3. **`Publish N unscoped name-claim placeholder(s) now? [y/N]`** claims `allw-hook`, `allw-approver`,
   `allw-codex-hook` and `allw-openclaw-bridge` against squatting. npm asks for 2FA on each publish.

If your npm account's 2FA covers authorization as well as writes, npm needs a one-time password just
to read trust settings. The script then asks
**`npm one-time password (2FA code) to read <package>'s trust configs:`**. Enter the current code
from your authenticator. The script reuses it for the next package until it expires. If you give no
code, or it isn't a terminal session, the script stops for that package and changes nothing there.
It never asks you to judge the configs by eye. The audit (`--audit-trust`) reads them the same way.

The run ends with a summary table and a **Still to do** list. A successful run shows every `@allw/*`
row as `configured` and every unscoped row as `placeholder published`. Re-running it is safe: anything
already done is skipped. If it stops at a precondition, such as not being logged in or a missing org,
the error message says exactly what to fix.

**The first real release is on hold, and that's fine.** npm expires a trusted-publisher config that
hasn't been used within 48 hours, so the configs created today will lapse. Right before the first
real release, recreate them with `node scripts/npm-bootstrap-trusted-publishing.mjs --refresh-trust`,
then push the release tag within 48 hours (see [Cutting a release](#cutting-a-release)).

## What gets published

| Package                 | Notes                                            |
| ----------------------- | ------------------------------------------------ |
| `@allw/sdk`             | Includes the vendored WASM build of `allw-core`. |
| `@allw/hook`            | Claude Code PreToolUse hook.                     |
| `@allw/approver`        | Stand-in software approver.                      |
| `@allw/codex-hook`      | Codex hook.                                      |
| `@allw/openclaw-bridge` | OpenClaw gateway operator client.                |

They are staged in this order, which is dependency order, and should be approved in the same order.
`@allw/relay`, `@allw/web-approver` and the examples are private: they are deployed or run from
source, never published. The list, its order and the trusted identity (repo `mike-north/allw`,
workflow `release.yml`, environment `npm-publish`) are defined in one place,
[`scripts/release-packages.mjs`](../scripts/release-packages.mjs). The release workflow and the
bootstrap both read it, so they cannot drift apart.

**Claimed, never released.** That module's `CLAIM_ONLY_NAMES` holds the unscoped bin names
`allw-hook`, `allw-approver`, `allw-codex-hook` and `allw-openclaw-bridge`. `npx <bin>`, run outside a
project that has the scoped package installed, fetches a registry package named after the bin, so
whoever owns `allw-hook` controls what `npx allw-hook` runs. Each of these names holds a permanent
inert placeholder whose import and bin throw an error that points at the real `@allw/*` package. None
of them gets a trusted publisher, and the release workflow never publishes them. A test enforces that
every bin a published package declares is in this list. Bare `allw` isn't claimed: npm refuses it as
too similar to existing package names, which blocks a squatter just the same.

## Versioning: lockstep

Every published package has the same version, and a release is the tag `v<x.y.z>`. The packages
share one WASM core and pin each other exactly (`pnpm pack` rewrites `workspace:*` to the sibling's
version), so versioning them separately would add bookkeeping without real independence. The repo
has no changesets. If it adopts changesets later, its "version packages" step replaces the manual
bump below, and staging stays in `release.yml`.

Two kinds of release are refused on purpose, because each needs a dist-tag other than `latest`:

- **Prereleases** (`v1.2.3-rc.1`) and build metadata. `verify` and `set-version` reject them.
- **Backports**, meaning a version lower than one already on the registry. The stage job refuses
  these before it stages anything. npm would otherwise move `latest` backwards.

Supporting either means adding an explicit `--tag` choice to the release path. Until then, release
only forward on `latest`.

## Cutting a release

1. Bump the version in a normal PR:

   ```sh
   node scripts/release-packages.mjs set-version 0.2.0
   node scripts/release-packages.mjs verify v0.2.0   # lockstep, public, repo URL, dependency order
   ```

2. Unless the trusted-publisher configs were created in the last 48 hours, recreate them now, because
   they expire if nothing has used them yet:

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
   - **build** (read-only token): refuses tags that are not on `main` and checks the tag against
     every manifest. It builds **cold**, with no caches restored or saved: a cache entry is keyed
     by name, not by who wrote it, so a run on a hostile tag could otherwise poison a later real
     release. It builds the WASM and the packages and runs the release-script tests. It packs
     the five tarballs into `dist-release/`, then runs the
     [packaged-install smoke](../scripts/smoke-packaged-install.mjs) on **exactly those tarballs**: a
     clean `npm install` of all five, every bin's `--version`, an import of every package, and a
     hook run. It uploads the tarballs as an artifact.
   - **stage** (environment `npm-publish`, `id-token: write`): installs an exactly pinned npm
     (≥ 11.15.0, which `npm stage` needs) and runs
     `npm stage publish --provenance --tag latest` on those exact tarballs, in order. It installs no
     dependencies and runs no package scripts. It plans every package before staging any:
     - A version already on the registry is skipped only if its `dist.integrity` equals the local
       tarball's sha512.
     - Any mismatch fails the job, and so does a backport, with nothing staged.
     - Each tarball must still have the sha512 that `pack` recorded in `release-manifest.json`.
     - The job summary lists each stage id and tarball sha512, plus the verify command.

5. **Verify, then approve the staged versions.** The approval is the release gate. The job summary
   lists each stage id and tarball sha512, but the run writes that summary itself. Any run that gets
   a stage-capable token can write one, for example a modified `release.yml` on a branch with a `v*`
   tag pushed at it. So the summary proves nothing. Treat only these steps as evidence.
   1. Review what changed since the last release in everything that builds or ships it:

      ```sh
      git fetch https://github.com/mike-north/allw.git main --tags
      git log --stat <previous-tag>..v0.2.0 -- .github scripts packages crates
      ```

      Every commit there is on `main`, so it was reviewed, but it's your last look before the
      bytes go public.

   2. Get a **fresh clone of GitHub's `main`** in a new temp directory, never your working checkout.
      Then log in to npm (`npm login`) and to `gh`.

      ```sh
      MAIN=$(git ls-remote https://github.com/mike-north/allw.git refs/heads/main | cut -f1)
      DIR=$(mktemp -d)
      git -c core.hooksPath=/dev/null clone --filter=blob:none \
        https://github.com/mike-north/allw.git "$DIR"
      cd "$DIR" && test "$(git rev-parse HEAD)" = "$MAIN" && echo "at main $MAIN"
      ```

      `--filter=blob:none` keeps every commit but fetches file contents lazily. A `--depth 1`
      clone would be smaller, but it lacks the history the ancestry check needs, so the verifier
      would report every tag as not on `main`. That fails safe, but you couldn't use it.

   3. Run the verifier from that clone in a **clean environment**, so your shell's `NODE_OPTIONS`,
      aliases and extra PATH entries don't apply. Name the run whose stages you mean to approve:

      ```sh
      NODE_DIR=$(dirname "$(nodenv which node 2>/dev/null || command -v node)")
      env -i HOME="$HOME" TERM="$TERM" PATH="$NODE_DIR:/opt/homebrew/bin:/usr/bin:/bin" \
        node scripts/verify-staged-release.mjs 0.2.0 --run <run-id>
      ```

      The verifier also refuses a dirty checkout, or one whose `HEAD` isn't GitHub's current
      `main`. That only catches a stale or accidentally edited checkout. It is not a defense
      against a hostile process on your machine:
      - `git update-index --skip-worktree` hides edits from `git status`;
      - a shim for `git`, `npm`, `gh` or `node` on your PATH, a git hook, or an edited copy of the
        verifier can make every check pass.

      The fresh clone and the clean environment narrow that. They don't close it.

      [`scripts/verify-staged-release.mjs`](../scripts/verify-staged-release.mjs) exits non-zero
      unless all of the following hold:
      - The run is a successful `release.yml` run for tag `v0.2.0`.
      - GitHub's `v0.2.0` tag points at the commit that run built.
      - That commit is an ancestor of GitHub's `main`, so the workflow and code were reviewed.
      - The run's `npm-tarballs` artifact lists exactly the five packages at `0.2.0`, and each
        tarball matches the sha512 `pack` recorded in `release-manifest.json`.
      - `npm stage list` shows exactly one open stage per package at `0.2.0`, and no open stage of
        any other version.
      - Each stage's bytes, fetched with `npm stage download`, have exactly the run's sha512.
      - If npm exposes provenance on the stage, it names `.github/workflows/release.yml` at
        `refs/tags/v0.2.0` in `mike-north/allw`, at that commit, from that run, for that sha512.

      npm's stage reads don't prompt for 2FA themselves. If your account's 2FA covers authorization,
      the verifier asks for a one-time password and retries with it. Without one, it stops. The
      code reaches npm only through the child process's environment, never its command line, and
      npm's log file is disabled for those calls, so the code doesn't show up in `ps` or
      `~/.npm/_logs`.

   4. If it passes, approve **only the stage ids it prints**, in the order it prints them:

      ```sh
      npm stage approve <stage-id>   # asks for npm 2FA; the version goes public on `latest`
      ```

      Never approve a stage you didn't start, or one the verifier didn't list.

   5. Log out of npm (`npm logout`). Stay logged out when you're not releasing, so a stray
      `npm stage approve` can't happen.

   **Residual risk: the 2FA approval is only as strong as the machine you type it on.** Malware or
   a compromised agent on that machine could fake the verifier's output, or swap what you approve.
   The verifier can't prove its own integrity. For a release you need to be sure of, verify and
   approve somewhere no agent runs:
   - **On npmjs.com:** open each package's **Staged Packages** tab in a browser, check that each
     stage's version and shasum match the verifier's output, and approve there.
   - **From a separate macOS user account** that runs no coding agents: do steps 2–5 there.

   **What actually protects you before approval is the byte match.** The verifier checks that each
   staged tarball is byte-for-byte what a successful run built from a reviewed commit on `main`.
   Provenance is a **post-approval** check. npm documents no read path for a _staged_ version's
   provenance: `npm stage view --json` documents only id, package, version, status, tag, actor and
   shasum. The verifier checks provenance on a stage only if an attestation happens to be there.
   Otherwise it fails and says so. Rerun it with `--provenance-after-approval` to rely on the byte
   match alone. Then, right after approving, run:

   ```sh
   node scripts/verify-staged-release.mjs 0.2.0 --published --run <run-id>
   ```

   It checks each published `dist.integrity` against the run's tarball. It also checks that each
   published SLSA provenance attestation names `release.yml` at `refs/tags/v0.2.0`, that commit and
   that run. If it fails, deprecate the affected versions right away and cut a new release.
   - If a check fails, or you didn't start the release, reject every stage of it with
     `npm stage reject <stage-id>`. Then fix the problem and cut a new version.
   - `npm stage list @allw/sdk` (and so on for each package) lists pending ids. They also appear
     under the **Staged Packages** tab on each package's npmjs.com page.
   - Approve all five, or reject all five. Approving only some of them leaves a set whose exact
     sibling pins can't install.

To rehearse a release, run the workflow manually (**Actions → Release → Run workflow**) from a branch.
The rehearsal does everything except stage, and runs `npm stage publish --dry-run` instead.
Dispatching it on a `v*` tag stages for real, which is how a maintainer retries a failed release.
Before you retry, check `npm stage list <pkg>` and reject anything left staged from the failed run.
How npm treats a second staging of a version that is still pending is not documented.

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
   that ever happen from a laptop. Real code ships only from CI, staged with provenance and approved
   by a maintainer.
3. **Trusted publishers.** It runs `npm trust github` on each `@allw/*` package (workflow
   `release.yml`, repo `mike-north/allw`, environment `npm-publish`, `--allow-stage-publish` only).
   - It reads every config on the package. If reading needs 2FA, it asks for a one-time password
     and retries with it, and it fails closed when it gets none. The code goes to npm through the
     child process's environment (`npm_config_otp`), never its command line, and npm's log file is
     disabled for those reads.
   - Every config that differs in any way is revoked: a different identity, or one that allows
     direct `npm publish`, even alongside staging. The stage-only config is created only after the
     revokes succeed.
   - `--refresh-trust` revokes and recreates all of them.
   - `--audit-trust` only lists every config with its permissions, then revokes the wrong ones. It
     creates nothing and publishes nothing.
   - If the CLI call fails, it prints the npmjs.com page and the exact field values to enter by hand.
     The allowed action to tick is **`npm stage publish` only**, and every other trusted publisher
     on that page must be deleted.
4. **Name claims.** For each name in `CLAIM_ONLY_NAMES` that is free, it publishes the inert claim
   placeholder. If someone else already owns one of those names, it reports that in the checklist
   and does not try to publish over it.
5. **Checklist.** It prints what's done and what's left, including the hardening below.

## Recommended hardening (defense in depth)

The 2FA approval is the gate. These settings make it harder to get a bad version staged in the first
place:

- In the repo's settings, under [Environments](https://github.com/mike-north/allw/settings/environments),
  give `npm-publish` a required reviewer (you) and allow deployments only from `v*` tags.
- Add a [tag ruleset](https://github.com/mike-north/allw/settings/rules) for `v*`:
  - restrict creation to maintainers, so nobody else can push a release tag;
  - block update and deletion **with no bypass actors**, so a release tag can never be moved or
    reused once it exists. Otherwise a hostile run could take a tag name, and the real tag pushed
    under that name later would inherit whatever that run left behind;
  - this complements the cold builds in `release.yml`, which already leave a hostile run no cache to
    poison.
- After the first release, set each `@allw/*` package's npm _Settings → Publishing access_ to
  **Require two-factor authentication and disallow tokens**. Trusted publishing keeps working because
  it doesn't use tokens.
- After the first release, deprecate the `@allw/*` placeholders. The bootstrap prints the
  `npm deprecate` commands. The unscoped claim placeholders stay as they are.

## What can't be automated

- **Creating the npm org.** npm has no CLI or API for it.
- **The first publish of each name.** npm only attaches a trusted publisher to a package that already
  exists, so the bootstrap publishes the empty placeholder described above.
- **2FA prompts.** Each `npm publish`, `npm trust` and `npm stage approve` call from your machine asks
  you for a second factor.
- **Approving a release.** That's the point of staging. No workflow or agent can do it.
- **GitHub environment protection rules and tag rulesets.** These are repo settings, so you configure
  them yourself.

## Changing the trusted identity

Renaming `release.yml`, changing the `npm-publish` environment, or moving the repo changes the
identity npm trusts. Update the constants in `scripts/release-packages.mjs`, then re-run the
bootstrap. It detects the mismatched configs and offers to replace them. Replacement configs also need
to be used within 48 hours, or they expire.
