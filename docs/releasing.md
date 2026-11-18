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

## Changes in behavior for callers

Before 1.0, a feature and a breaking change both make a minor release
(see [Versions before 1.0](#versions-before-10)). So the version number
does not warn the people who update. 0.6.0 changed a default that
programs and scripts depend on (#171), and it was listed as a normal
feature (#191). This gate makes such a change visible.

### The line in the description

The description of every pull request has this line, with `yes` or `no`
([`.github/pull_request_template.md`](../.github/pull_request_template.md)):

```text
Changes behavior for existing callers: no
```

"Behavior" means: defaults, the content of stdout and stderr, exit codes,
signals, which process runs the command, the meaning of the config, and
time limits. A program or a script that uses nodkey can break when one
of them changes.

For `yes`, the pull request must also:

- have `!` after the type or the scope of the title, for example
  `feat(run)!: mask the output by default`;
- add a section `## Updating from X` to
  [docs/updating.md](updating.md). It says who is affected, what to do,
  and gives a command that shows the new way. `X` is the newest release
  that still has the old behavior, for example `0.5.0 or older`.

### The check

The **PR title** workflow runs the check in its job
**Conventional Commits title**, after the title check. This job is
already a required check of `main`. The check fails when:

- the line is missing, is there more than once, or has another value
  than `yes` or `no` (in small letters, with nothing else; a line in an
  HTML comment `<!-- -->` does not count);
- the answer is `yes` and the title has no `!`;
- the answer is `yes` and the pull request adds no line
  `## Updating from X` to `docs/updating.md`;
- the answer is `no` and the title has a `!`;
- the pull request changes, removes or moves a file under
  `test/contract/`, and the answer is `no`. These tests pin what callers
  see, so a change to one of them is a change in behavior for callers.
  A new test file right in `test/contract/` (a name that ends in
  `_test.go`) does not count: a new test pins behavior that callers
  already have. A change to `test/contract/README.md` does not count
  either. Any other new file there counts, such as a `go.mod` or a file
  in `testdata/`, because it can change the tests that are there. A
  new test file can still change the others, for example with a
  `TestMain`: the review must check this.

The error says what to fix. Edit the title or the description: the
check runs again by itself.

Two kinds of pull requests need no line:

- the release pull request of release-please: its author is the release
  App, its branch is `release-please--branches--main`, and it changes
  only `CHANGELOG.md` and `.release-please-manifest.json`. Its commits
  passed the check one by one;
- a pull request of Dependabot with no `!` in the title that changes
  only `go.mod`, `go.sum`, files under `.github/workflows/` and files
  under `test/e2e/testdata/sshd/`.

The check is `tools/prgate`, with its tests in
`tools/prgate/main_test.go`. The workflow runs it with
`pull_request_target`, from the code on `main`, never from the pull
request. It reads only the title, the description, the author and the
branch name of the pull request, and the list of changed files from the
GitHub API: their names, their status (added, changed, removed, moved),
and the diff of `docs/updating.md` only, as text. It never prints text of the pull request to the log. A change to
the check itself takes effect only after it is merged.

### "⚠ BREAKING CHANGES" in the release notes

release-please lists a commit with `!` after the type or the scope under
**⚠ BREAKING CHANGES**, at the top of the release notes and of
CHANGELOG.md. The commit on `main` must keep the `!`. It does: the
squash commit takes the pull request title as its message (repository
setting: the default commit message of a squash merge is the pull
request title; checked on 2026-11-17). So never change the title in the
merge dialog, and never remove the `!` from it. Before you merge a
release pull request, check that each change of `docs/updating.md` since
the last release has its line under **⚠ BREAKING CHANGES**.

## Security fixes

Use the type `security` for a pull request that fixes a real security
problem, and only for that. If other pull requests use it, the mark means
nothing. Examples:

- `security: deny a request with two Host headers`
- `security(deps): bump golang.org/x/crypto (GHSA-xxxx-xxxx-xxxx)`

The title may name the IDs of published advisories, in the form
`GHSA-xxxx-xxxx-xxxx`.

A `security` pull request puts its line in a `### Security` section. This
section comes first in CHANGELOG.md and in the release notes. The update
notices of nodkey will use this section to flag a security release (issue
#122).

Do not name an unfixed problem in public. Fix a privately reported problem
in the temporary private fork of its GitHub security advisory, and merge it
from there just before the release. The title becomes public when it is
merged, before the advisory is published. So keep the advisory ID and the
details of the problem out of that title.

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
     commit of this workflow run. Then it runs
     [`scripts/build-release.sh`](../scripts/build-release.sh), the one
     build of the release files. It builds static `nodkey` binaries
     for Linux amd64 and arm64 (`CGO_ENABLED=0`, `-trimpath`), packs each
     one with `LICENSE` and `README.md` into
     `nodkey_<version>_linux_<arch>.tar.gz`. It packs the files of
     `contrib/pullgate/` with `LICENSE` into
     `nodkey_<version>_pullgate.tar.gz`. It makes the Ansible recipe
     with `contrib/ansible/build.sh` and packs it into
     `nodkey_<version>_ansible.tar.gz`, and writes `SHA256SUMS`.
   - `publish` gets these files from `build`. It checks them against
     `SHA256SUMS` and checks the tag again. Then it makes a signed build
     provenance attestation for the tarballs. It saves the attestation as
     one more file, `nodkey_<version>.sigstore.json` (a Sigstore bundle
     for all tarballs), and checks all tarballs with it, with no login,
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

## Check a release candidate

Before you merge the release pull request, run the **Release check**
workflow on its branch. It checks that the candidate works with the last
two releases. Run it only when you want to release, not on each update
of the release pull request. It publishes nothing and needs no secret.

1. Open **Actions**, then **Release check**, then **Run workflow**.
2. In "Use workflow from", choose the branch
   `release-please--branches--main`. Then click **Run workflow**.

Or with gh:

```sh
gh workflow run release-check.yml --repo code6x/nodkey --ref release-please--branches--main
```

The candidate is the newest commit of that branch, and its version is
the one in `.release-please-manifest.json`. N-1 and N-2 are the two
highest published releases below it. A draft, a prerelease, or a tag
without a release do not count.

### The checks

| # | check | what passes |
|---|---|---|
| 1 | build | `scripts/build-release.sh` builds the candidate, and a second build gives the same files. |
| 2 | N-1 and N-2 | Both are found, and their files pass `SHA256SUMS` and the attestation check. |
| 3 | update path | In a container, the real N-1 and N-2 run `nodkey update`, and the `install.sh` of their own release, against a local HTTPS server with the candidate's files: both install the candidate. A wrong or missing checksum, a missing or changed file, and a failed attestation check are refused, and the old binary stays. The candidate has no attestation, so a fake `gh` stands for it. The release workflow checks the real one. |
| 4 | configs | Each config in `test/compat/configs/` gives the same result with N-1 and the candidate (`nodkey broker check`). `ok-*` files must pass N-1, `bad-*` files must fail it. |
| 5 | audit log | The end-to-end test with N-1 as the first broker: N-1 writes the audit log and stops, and the candidate goes on with it with no alarm. `nodkey audit verify` of both versions passes, and both refuse a changed or a cut copy. |
| 6 | mixed versions | The end-to-end test three times: candidate broker and clients, N-1 broker with candidate clients, and candidate broker with N-1 clients. The test expects the version notices and warnings of two releases. |
| 7 | stress | `go test -race -count=5 -cpu 1,2,4 ./...` |
| 8 | changelog | Every pull request merged since N-1 is in the notes of the release pull request, or has a hidden type. Every `!` pull request has its section `## Updating from N-1` in [docs/updating.md](updating.md). |
| 9 | timing report | A login of agent-browser with a fake `bw` that takes 6 s per run: without a pre-approval, the pre-approval on a cold broker, and the login after it. It shows the times, the limit of the plugin (12 s) and the runs of `bw`. **It never fails the workflow.** Timing on shared runners is not stable, so you read it. |

The end-to-end test takes the binaries from these variables. Without
them it builds nodkey from the source, as before:

- `NODKEY_E2E_BROKER_BIN`: the broker;
- `NODKEY_E2E_CLIENT_BIN`: the clients;
- `NODKEY_E2E_FIRST_BROKER_BIN`: a broker for the first case only. Then
  the broker of `NODKEY_E2E_BROKER_BIN` goes on with its audit log.

Each one is the absolute path of a nodkey binary.

### Read the result

The summary of the run has a table with each check: `pass`, `fail`, or
`report` for the timing report. Under it is the timing report. The
artifact `release-check-result` has `release-check.json`:

- `candidate`: the commit, the branch and the version that were checked;
- `n1`, `n2`: the versions of N-1 and N-2;
- `passed`: `true` when no check failed;
- `checks`: each check with its `result` and its `evidence`, the end of
  the log of the check.

A check that did not run counts as `fail`. The workflow fails when a
check fails, but never because of the timing report.

For the timing report, look at `login_after_preapproval`: it must be
`success: true`, well under `plugin_resolve_time_seconds`, with
`bw_calls: 0`. A slow `preapproval_cold` is normal: the tap waits for
the person, not for agent-browser.

When a check fails, do not merge the release pull request. Read the
evidence, fix the problem in a new pull request, and run the check
again on the updated release pull request.

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
  and the PR title check (with the gate of
  [Changes in behavior for callers](#changes-in-behavior-for-callers))
  must pass; no force push; `main` cannot be deleted.
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
- `nodkey_<version>_pullgate.tar.gz`: the pullgate recipe, the files of
  `contrib/pullgate/` and `LICENSE` (docs/setup.md, "Change the config
  from git with pullgate"). Releases before 0.7.0 do not have it;
- `nodkey_<version>_ansible.tar.gz`: the Ansible recipe, the role, the
  playbooks and `check-data` of `contrib/ansible/`, with the `install.sh`
  and the unit of the tag in the role, and `LICENSE`
  (contrib/ansible/README.md). Releases before 0.8.0 do not have it;
- `SHA256SUMS`: the SHA-256 of all tarballs;
- `nodkey_<version>.sigstore.json`: the build provenance attestation of
  all tarballs, as a Sigstore bundle. 0.1.0 does not have this file.

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
