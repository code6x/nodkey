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

The allowed types are `security`, `feat`, `fix`, `perf`, `revert`, `docs`,
`chore`, `ci`, `test`, `refactor`, `build` and `style`.

For a breaking change, add `!` after the type. For example:
`feat!: change the config file format`.

The **PR title** check tests the title. If the check fails, edit the title.
The check runs again by itself.

## Security fixes

Use the type `security` for a pull request that fixes a real security
problem, and only for that. If other pull requests use it, the mark means
nothing. Examples:

- `security: deny a request with two Host headers`
- `security(deps): bump golang.org/x/crypto (GHSA-xxxx-xxxx-xxxx)`

The title may name advisory IDs in the form `GHSA-xxxx-xxxx-xxxx`.

A `security` pull request puts its line in a `### Security` section. This
section comes first in CHANGELOG.md and in the release notes. The update
notices of nodkey will use this section to flag a security release (issue
#122).

Do not name an unfixed problem in public. Fix a privately reported problem
in the temporary private fork of its GitHub security advisory, and merge it
from there just before the release. Name the advisory ID in a public title
only after the advisory is published.

## Squash merges

This repository allows only squash merges. When you merge a pull request,
GitHub makes one commit on `main`. The commit message is only the pull
request title. release-please reads this title. For `security`, `feat`,
`fix`, `perf`, `revert` and `docs`, the title also becomes a line in the
changelog.

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
     provenance attestation for the tarballs. It saves the attestation as
     one more file, `nodkey_<version>.sigstore.json` (a Sigstore bundle
     for both tarballs), and checks both tarballs with it, with no login,
     as in [Verify a download](#verify-a-download). Then it uploads the
     files to the draft release and publishes it.

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
| `security` | Security (first) | yes |
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
- `security`, `fix`, `perf`, `revert` and `docs` make a patch release:
  `0.1.0` → `0.1.1`.

## Dependency updates

Dependabot checks Go modules and GitHub Actions once a week. Its pull request
titles start with `chore(deps):` or `ci(deps):`, so they do not make a
release.

If an update fixes a security problem in a Go module that nodkey uses,
change the pull request title to `security(deps): ...` before you merge it.
Then the fix gets a release, and the release is marked as a security
release.

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
- **Rulesets for `v*` tags**: nobody can move or delete a tag, not even the
  release App. Only the release App can create one.
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

One App can serve several repositories of the organization. Give each
repository its own private key. Then you can delete one key without
breaking the others. The keys do not keep the repositories apart: any key
of the App can get a token for every repository the App is installed on.
If a repository must be kept apart, give it its own App.

If the organization already has a release App (for code6x it is
`code6x-release`), skip step 1.

1. Create the App. In the **code6x** organization, open
   **Settings → Developer settings → GitHub Apps → New GitHub App**.
   - **GitHub App name**: any free name, for example `<organization>-release`.
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
2. In the **code6x** organization, open the App page: **Settings →
   Developer settings → GitHub Apps → Edit** next to the App. Copy the
   **Client ID**. If the App already existed, check that its permissions
   match step 1.
3. Open **Credentials → Key pairs** and click **New key**. Your browser
   downloads a `.pem` file. Use this key only for this repository.
4. Find the key's fingerprint:

   ```sh
   echo "SHA256:$(openssl rsa -in path/to/key.pem -pubout -outform DER | openssl sha256 -binary | openssl base64 -A)"
   ```

   Check that the **Key pairs** page shows this exact value next to the new
   key. If it does not, stop: the path is wrong, or the file is not the new
   key.
5. Install the App: **Install App** → **code6x** →
   **Only select repositories** → add `code6x/nodkey` → **Install**
   (or **Save**, if the App is already installed on other repositories).
6. Save the Client ID and the fingerprint as repository variables, and the
   private key as a secret of the `release` environment:

   ```sh
   gh variable set RELEASE_APP_CLIENT_ID --repo code6x/nodkey --body '<Client ID>'
   gh variable set RELEASE_APP_KEY_FINGERPRINT --repo code6x/nodkey --body '<the line from step 4>'
   gh secret set RELEASE_APP_PRIVATE_KEY --repo code6x/nodkey --env release < path/to/key.pem
   ```

   On the web, the variables are under
   **Settings → Secrets and variables → Actions → Variables**, and the
   secret is under **Settings → Environments → release →
   Environment secrets**. Do not save the key as a repository secret: then
   workflow runs on other branches could read it too.
   `RELEASE_APP_KEY_FINGERPRINT` is not used by the workflow. It tells you
   which key on the **Key pairs** page belongs to this repository.
7. Delete the `.pem` file from your computer.
8. Protect the release tags with two rulesets. Open
   **Settings → Rules → Rulesets**:
   - **release tags** (tags `v*`): turn on **Restrict updates** and
     **Restrict deletions**. Leave the bypass list empty.
   - **release tag creation** (tags `v*`): turn on **Restrict creations**,
     and add the App to the bypass list. The App must be the only entry in
     that list.

   Two rulesets are needed because a bypass entry skips every rule of its
   ruleset. With one ruleset, the App could also move or delete tags.

The next push to `main` runs release-please with the App.

### Change the key

1. Write down the fingerprint of the key in use now:

   ```sh
   gh variable get RELEASE_APP_KEY_FINGERPRINT --repo code6x/nodkey
   ```

2. Make a new key and check its fingerprint (setup steps 3 and 4).
3. Save the new key and the new fingerprint (setup step 6).
4. Check that the new key works: open **Actions → Release**, open the
   latest run on `main`, click **Re-run jobs → Re-run all jobs**, and check
   that its `release-please` job passes. GitHub allows a re-run only up to
   30 days after a run. If there is no re-run button, merge any pull
   request and check that new run.
5. On the **Key pairs** page, delete the key with the fingerprint from
   step 1. First check that it is not the new key. Delete only that key:
   the other keys belong to other repositories.
6. Delete the `.pem` file.

If a key leaked (this repository's key, or the key of another repository
that uses the App), delete it on the **Key pairs** page at once. For
this repository's key, do step 1 first; releases then fail until you
finish steps 2 to 4. Then check nodkey for tags, releases and merged pull
requests that you did not expect. Tokens made with the key before you
deleted it can still work for up to one hour.

## Verify a download

A release has these files:

- `nodkey_<version>_linux_amd64.tar.gz` and
  `nodkey_<version>_linux_arm64.tar.gz`: the binary, `LICENSE` and
  `README.md`;
- `SHA256SUMS`: the SHA-256 of both tarballs;
- `nodkey_<version>.sigstore.json`: the build provenance attestation of
  both tarballs, as a Sigstore bundle. 0.1.0 does not have this file.

Set the version you want, and your machine's arch: `amd64`, or `arm64`
on 64-bit ARM.

```sh
VERSION=0.1.0
ARCH=amd64
```

Then download the tarball, `SHA256SUMS` and the bundle file, with `curl`
or with `gh`. 0.1.0 has no bundle file, so skip that download for 0.1.0:

```sh
U="https://github.com/code6x/nodkey/releases/download/v$VERSION"
curl -fLO "$U/nodkey_${VERSION}_linux_${ARCH}.tar.gz"
curl -fLO "$U/SHA256SUMS"
curl -fLO "$U/nodkey_${VERSION}.sigstore.json"
```

```sh
gh release download "v$VERSION" --repo code6x/nodkey \
  --pattern "nodkey_${VERSION}_linux_${ARCH}.tar.gz" --pattern SHA256SUMS \
  --pattern "nodkey_${VERSION}.sigstore.json"
```

`curl` needs no login. For `gh release download`, gh older than 2.96.0
needs a login (`gh auth login`), even for this public repository.

1. Check the checksum:

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS
   ```

   It must print `nodkey_<version>_linux_<arch>.tar.gz: OK`.
   `--ignore-missing` skips the tarballs that you did not download.

   The checksum alone is not enough. Whoever can publish a release can also
   publish a matching `SHA256SUMS`. Always do steps 2 and 3 too.

2. Check the build provenance attestation. It proves that the Release
   workflow on `main` of `code6x/nodkey` built this exact file, on a
   runner that GitHub hosts. With the bundle file of the release, gh needs
   no login. This is the way for a host that must have no GitHub login,
   such as the broker host:

   ```sh
   gh attestation verify "nodkey_${VERSION}_linux_${ARCH}.tar.gz" \
     --bundle "nodkey_${VERSION}.sigstore.json" \
     --repo code6x/nodkey \
     --cert-identity https://github.com/code6x/nodkey/.github/workflows/release.yml@refs/heads/main \
     --deny-self-hosted-runners
   ```

   Without `--bundle`, gh gets the attestation from GitHub. Then it needs a
   login, even for this public repository. Use this form for 0.1.0, which
   has no bundle file:

   ```sh
   gh attestation verify "nodkey_${VERSION}_linux_${ARCH}.tar.gz" \
     --repo code6x/nodkey \
     --cert-identity https://github.com/code6x/nodkey/.github/workflows/release.yml@refs/heads/main \
     --deny-self-hosted-runners
   ```

   Both forms check the same thing. Both still go online to get the
   Sigstore trusted root. Use gh 2.93.0 or newer: older versions have
   known bugs in `gh attestation verify`
   ([GHSA-fgw4-v983-mgp8](https://github.com/cli/cli/security/advisories/GHSA-fgw4-v983-mgp8),
   [GHSA-8xvp-7hj6-mcj9](https://github.com/cli/cli/security/advisories/GHSA-8xvp-7hj6-mcj9)).
   When no terminal is attached, gh prints nothing on success. Then check
   its exit code: 0 means the check passed.

3. Check the version. The attestation proves which workflow built the
   file, but not which version it is: the tarball of an older release
   passes step 2 under a newer name too. The attestation holds the file
   names that the workflow gave the tarballs. Run step 2 again with
   `--format json`, and check that the name of your file is in it. Add
   the same `--format` and `--jq` lines to the form without `--bundle`
   for 0.1.0.

   ```sh
   gh attestation verify "nodkey_${VERSION}_linux_${ARCH}.tar.gz" \
     --bundle "nodkey_${VERSION}.sigstore.json" \
     --repo code6x/nodkey \
     --cert-identity https://github.com/code6x/nodkey/.github/workflows/release.yml@refs/heads/main \
     --deny-self-hosted-runners \
     --format json --jq '.[].verificationResult.statement.subject[].name' |
     grep -Fx "nodkey_${VERSION}_linux_${ARCH}.tar.gz"
   ```

   It must print the name of your file. If it prints nothing, stop: the
   file is not the version that its name says. On the machine that the
   binary is for, `nodkey version` must also print the version, after you
   take it out of the tarball (`tar -xzf <tarball> nodkey`, then
   `./nodkey version`). Its first line is `nodkey` and the version, such
   as `nodkey 0.1.0`. On a terminal, a nodkey newer than 0.1.x then asks
   GitHub for the newest release, from the machine where you check the
   binary, and prints one more line on stderr. To check it without that
   call, run `./nodkey version --offline`. nodkey 0.1.x does not know
   `--offline`, and does not ask GitHub.
