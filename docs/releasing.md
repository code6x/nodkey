# Releasing nodkey

Releases are automatic. A tool called
[release-please](https://github.com/googleapis/release-please) makes them
from the commit messages on `main`. This page explains how it works, how the
repository is protected, and the one-time setup it needs.

## Pull request titles

Every pull request title must follow
[Conventional Commits](https://www.conventionalcommits.org/):

```text
<type>: <what changed>
<type>(<scope>): <what changed>
```

Examples:

- `feat: add the approve command`
- `fix(sign): reject an empty key name`
- `docs: explain the threat model`

The allowed types are `feat`, `fix`, `perf`, `revert`, `docs`, `chore`,
`ci`, `test`, `refactor`, `build` and `style`.

For a breaking change, add `!` after the type. For example:
`feat!: change the config file format`.

The **PR title** check tests the title. If the check fails, edit the title.
The check runs again by itself.

## Squash merges

This repository allows only squash merges. When you merge a pull request,
GitHub makes one commit on `main`. The commit message is only the pull
request title. release-please reads this title. For `feat`, `fix`, `perf`,
`revert` and `docs`, the title also becomes a line in the changelog.

release-please also reads the description of each merged pull request. A
`BEGIN_COMMIT_OVERRIDE` block there replaces the commit message, even after
the merge. Do not write such a block unless you mean it. This is one more
reason to read the release pull request carefully before you merge it.

## What release-please does

After every push to `main`, the **Release** workflow runs release-please.

1. It reads the commit messages since the last release.
2. If one of them makes a release (see the table below), it opens a
   *release pull request*. Its title looks like `chore(main): release 0.2.0`.
   It changes `CHANGELOG.md` and `.release-please-manifest.json`.
3. Later merges to `main` update the same release pull request. You can
   leave it open as long as you want.
4. **Before you merge the release pull request, read the version and every
   line of the changelog in it.** This text becomes the release notes.
5. When you merge it, release-please creates the tag (for example `v0.2.0`)
   and a **draft** GitHub release with the release notes.
6. Then two more jobs run in the same workflow:
   - `build` can only read the repository. It checks that the tag is the
     commit of this workflow run. Then it builds static `nodkey` binaries
     for Linux amd64 and arm64 (`CGO_ENABLED=0`, `-trimpath`), packs each
     one with `LICENSE` and `README.md` into
     `nodkey_<version>_linux_<arch>.tar.gz`, and writes `SHA256SUMS`.
   - `publish` gets these files from `build`. It checks them against
     `SHA256SUMS` and checks the tag again. Then it makes a signed build
     provenance attestation for the tarballs, uploads the files to the draft
     release and publishes it.

The release is never public without its files. Immutable releases are on
for this repository: after a release is published, nobody can change its
files or move its tag. This is why the files are added while the release is
still a draft.

### If `build` or `publish` fails

The release stays a draft. **Re-run failed jobs** uses the same commit and
the same workflow file as the first run. So a re-run only helps when the
failure was temporary, for example a network error.

For any other problem, fix it in a new `fix:` pull request, then merge the
next release pull request. That release gets a new version. You can delete
the old draft release. Its tag stays, because tags cannot be deleted.

## Which types make a release

| Type | Section in the release notes | Makes a release? |
|---|---|---|
| `feat` | Features | yes |
| `fix` | Bug Fixes | yes |
| `perf` | Performance Improvements | yes |
| `revert` | Reverts | yes |
| `docs` | Documentation | yes |
| `chore`, `ci`, `test`, `refactor`, `build`, `style` | not shown | no |

If `main` has only `chore`, `ci`, `test`, `refactor`, `build` or `style`
commits since the last release, release-please does not open a release pull
request. These changes go out with the next release, but the release notes
do not list them.

## Versions before 1.0

- The first release is `0.1.0`. This is `initial-version` in
  `release-please-config.json`.
- `feat` makes a minor release: `0.1.0` → `0.2.0`.
- A breaking change (`!`) also makes only a minor release before 1.0, not
  `1.0.0`. This is `bump-minor-pre-major` in `release-please-config.json`.
- `fix`, `perf`, `revert` and `docs` make a patch release: `0.1.0` → `0.1.1`.

## Dependency updates

Dependabot checks Go modules and GitHub Actions once a week. Its pull request
titles start with `chore(deps):` or `ci(deps):`, so they do not make a
release.

If an update fixes a security problem in a Go module that nodkey uses,
change the pull request title to `fix(deps): ...` before you merge it. Then
the fix gets a release.

## Vulnerability checks

The **CI** workflow runs govulncheck on every pull request, on every push to
`main`, and every Monday:

- on the code, with the newest Go;
- on Mondays also on the binaries of the newest release. They contain the
  Go standard library of the Go version that built them.

A problem in the standard library of the published binaries does not go
away by itself. Only a new release fixes those binaries. Make a `fix:` pull
request, for example one that raises the `go` line in `go.mod` to a Go
release with the fix. Then merge the release pull request. The new release
is built with the newest Go.

GitHub turns off scheduled workflows in a public repository after 60 days
without activity. If this happens, turn on the CI workflow again in the
**Actions** tab.

## Repository settings

These settings protect `main` and the releases:

- **Ruleset for `main`**: changes only through a pull request; the CI checks
  and the PR title check must pass; no force push; `main` cannot be deleted.
- **Ruleset for `v*` tags**: a tag cannot be moved or deleted.
- **Immutable releases**: on.
- **Actions**: every action must be pinned to a full commit SHA. Dependabot
  keeps these SHAs up to date.
- **Environment `release`**: only `main` can use it. It holds the private
  key of the GitHub App (see below).

## One-time setup: a GitHub App

Until this setup is done, the `release-please` job skips itself. In the
**Release** workflow runs it shows as "skipped". Nothing else breaks.

### Why not the default `GITHUB_TOKEN`

release-please could use the built-in `GITHUB_TOKEN`. But GitHub does not
start workflows for a pull request or a push that `GITHUB_TOKEN` made. So CI
and the PR title check would not run on the release pull request, and it
could not pass the required checks. A token from a GitHub App does start
workflows.

An App is also better than a personal access token: it does not belong to a
person, it has only the permissions it needs, and each token from it expires
after one hour.

### Steps

1. Create the App. In the **code6x** organization, open
   **Settings → Developer settings → GitHub Apps → New GitHub App**.
   - **GitHub App name**: any free name, for example `code6x-nodkey-release`.
   - **Homepage URL**: `https://github.com/code6x/nodkey`.
   - **Webhook**: clear the **Active** box. The App needs no webhook.
   - **Repository permissions**:
     - **Contents**: Read and write. It creates the release branch, the tag
       and the release.
     - **Pull requests**: Read and write. It opens the release pull request
       and adds labels and comments to it.
     - Leave all other permissions at "No access". GitHub adds
       **Metadata: Read-only** by itself.
   - **Where can this GitHub App be installed?**: **Only on this account**.
   - Click **Create GitHub App**.
2. On the App page, copy the **Client ID**.
3. On the same page, under **Private keys**, click
   **Generate a private key**. Your browser downloads a `.pem` file.
4. Install the App: **Install App** → **code6x** →
   **Only select repositories** → `code6x/nodkey` → **Install**.
5. Save the Client ID as a repository variable, and the private key as a
   secret of the `release` environment:

   ```sh
   gh variable set RELEASE_APP_CLIENT_ID --repo code6x/nodkey --body '<Client ID>'
   gh secret set RELEASE_APP_PRIVATE_KEY --repo code6x/nodkey --env release < path/to/key.pem
   ```

   On the web, the variable is under
   **Settings → Secrets and variables → Actions → Variables**, and the
   secret is under **Settings → Environments → release →
   Environment secrets**. Do not save the key as a repository secret: then
   workflow runs on other branches could read it too.
6. Delete the `.pem` file from your computer. If you need a key again,
   generate a new one on the App page and delete the old one there.
7. Let only the App create release tags. Open
   **Settings → Rules → Rulesets**, open the ruleset for `v*` tags, turn on
   **Restrict creations**, and add the App to the bypass list. The App must
   be the only entry in that list.

The next push to `main` runs release-please with the App.

## Verify a download

Download the tarball for your machine and `SHA256SUMS` from the release
page, or use `gh`:

```sh
gh release download v0.1.0 --repo code6x/nodkey \
  --pattern 'nodkey_0.1.0_linux_amd64.tar.gz' --pattern SHA256SUMS
```

1. Check the checksum:

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS
   ```

   It must print `nodkey_0.1.0_linux_amd64.tar.gz: OK`. `--ignore-missing`
   skips the tarballs that you did not download.

2. Check the build provenance attestation. It proves that the Release
   workflow on `main` of `code6x/nodkey` built this exact file, on a runner
   that GitHub hosts:

   ```sh
   gh attestation verify nodkey_0.1.0_linux_amd64.tar.gz \
     --repo code6x/nodkey \
     --cert-identity https://github.com/code6x/nodkey/.github/workflows/release.yml@refs/heads/main \
     --deny-self-hosted-runners
   ```
