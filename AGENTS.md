# Working on nodkey

nodkey gives an AI coding agent a secret or an SSH signature only after a
person approves that one request on a phone. Read [DESIGN.md](DESIGN.md)
and [THREAT-MODEL.md](THREAT-MODEL.md) before you change code. They are the
rules the code must follow.

## Layout

Planned. Each v1 issue adds its part.

- `install.sh` - the installer: it installs a release on a host, as root,
  after it checks the release (DESIGN.md section 18). `install.go`
  (package `nodkey`, at the root of the module) builds it into the
  binary with `go:embed`, for `nodkey update`. The tests of the script
  are in `install_linux_test.go`. CI checks it with shellcheck.
- `cmd/nodkey/` - the one binary. Subcommands: `broker`, `try`, `run`,
  `ssh-agent`, `ssh-grant`, `preapprove`, `keygen`, `audit verify`, `update`,
  `version`, `doctor`.
  `nodkey broker` starts the broker's parts in a fixed order, and stops
  them in a fixed order (DESIGN.md section 15). Its tests run it in a
  child process, with a fake Telegram server behind a fake HTTPS proxy.
  `nodkey try` (`try.go`, `tryapprover.go`, `trystore.go`) is the trial
  on one machine: the terminal approver and the test store live only
  there, and a test fails if any other file uses them (DESIGN.md section
  15, THREAT-MODEL.md T38).
- `internal/` - one package per part (config, transport, audit, approval,
  telegram, store, sshauth, client parts). Packages do not import
  `cmd/`.
  - `internal/api/` - the protocol between the clients and the broker:
    the paths, the headers, the request and answer types, and their caps.
  - `internal/version/` - versions of nodkey: the rule of a version that
    the other side sends, release versions, and how two compare (DESIGN.md
    section 10).
  - `internal/grantkey/` - the token of a standing grant: make, parse,
    hash, and hide it in every format (DESIGN.md section 8).
  - `internal/doctor/` - the checks of `nodkey doctor` (client) and
    `nodkey doctor broker`: read only, with the text and JSON form of
    the result (DESIGN.md section 15).
  - `internal/release/` - the newest release of nodkey on GitHub: the
    lookup for `nodkey version`, and the broker's check for a newer
    release, with its notice (DESIGN.md section 15). Its tests use a fake
    GitHub server; no test reaches the real GitHub.
  - `internal/broker/` - the broker's service: it answers each request in
    the order of DESIGN.md sections 5 and 6. `nodkey broker` makes its
    parts and runs it.
  - `internal/client/` - the client side: the requests to the broker
    (config, TLS key, deadline, short code, strict answer),
    `nodkey run` (DESIGN.md sections 5 and 15), `nodkey ssh-agent`
    (sections 6 and 15), `nodkey ssh-grant` (sections 13 and 15) and
    `nodkey preapprove` (sections 8 and 15).
- `contrib/systemd/` - the example systemd unit of the broker, with
  encrypted credentials and a sandbox (DESIGN.md section 16).
- `docs/` - the guides for people:
  - `docs/setup.md` - the setup guide: the broker host, the stores, the
    Telegram bot, the safety of the account and the host, the clients,
    upgrades and key changes. `README.md` has a short quick start that
    points to it.
  - `docs/manual-telegram-test.md` - the manual test with a real
    Telegram bot (issue #17), with a table for the results.
  - `docs/manual-ntfy-test.md` - the manual test with a real ntfy
    server, on Android and on an iPhone (issue #24), with a table for
    the results.
  - `docs/releasing.md` - how releases are made and checked.
- `test/e2e/` - the end-to-end test with `sshd` in a container (DESIGN.md
  section 17). Build tag `e2e`. The image of the container is
  `test/e2e/testdata/sshd`.
- `.claude/agents/security-reviewer.md` - the security review every change
  gets.

## Commands

```sh
go test -race ./...
go vet ./...
golangci-lint run --build-tags e2e       # the tag adds the files of test/e2e
go test -race -tags e2e ./test/e2e/...   # needs Docker, ssh and git
```

The last one is the end-to-end test (DESIGN.md section 17). It builds
nodkey and a Docker image, and removes every container, network and image
that it makes.

## Rules

- **This repository is public.** Never add a real host name, domain name,
  IP address, MAC address, VPN or tailnet name, token, key, serial number,
  private name of a person, household or company, or a link to a private
  repository. Public product and project names are fine. Use example
  names: `laptop`, `web-1`, `db-1`, `example.com`, and IP addresses from
  `192.0.2.0/24`. Test keys and tokens are made by the test itself.
- **Never log, print or return a secret value**, not even in an error or a
  test failure. A type that holds a secret must hide it in `String` and
  `Format`.
- **Fail closed.** Every error, timeout, cancel or unclear case means deny.
- **The broker trusts nothing from the client** except what the pinned TLS
  key proves. Check every input on the broker side.
- **Every change has tests**, and they test the deny paths, not only the
  happy path.
- **Every change gets a security review** by the agent in
  `.claude/agents/security-reviewer.md` before it is committed. Fix what it
  finds. If you do not fix a finding, say why in the pull request.
- **If a change alters** what a message shows, what the broker checks, or
  where a value goes, update DESIGN.md and THREAT-MODEL.md in the same pull
  request. If it changes the config, the example unit, a command, or a
  line that `docs/setup.md` or a `docs/manual-*-test.md` guide shows,
  update these guides too.
- **Dependencies:** the standard library, `golang.org/x/crypto` and
  `github.com/BurntSushi/toml`. Anything else needs a reason in the pull
  request. The `1password` store also links the official 1Password Go SDK
  (DESIGN.md section 4).
- **Git:** one feature branch and one pull request per issue. Pull request
  titles follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`). Pull requests are
  squash merged. Never push to `main` directly.
- **Open work is a GitHub issue** with a "Done when" checklist, never a TODO
  file.
- **Every error says how to fix it.** Every error that a person or an
  agent sees says what is wrong, where (the file and line, the section and
  key, or the step), and how to fix it (a command, or a docs section). An
  error without a fix is a bug.
- **A hint is safe.** A hint never holds a secret value or text that the
  other side chose (T19, DESIGN.md section 15). It never tells the person to
  weaken a check, such as to copy a new pin without checking it. It says "as
  root", never `sudo`. On a client, it says only what the client may know
  about a refusal (#106).
- **A usage error is one line**, for example `nodkey run: give at least one
  --secret VAR=NAME; see "nodkey run --help" (exit 64)`. No usage text comes
  after it, so the error is the first and the last line.
- **Docs** use plain English and short sentences. Many readers are not
  native speakers. Dates are absolute (`2026-10-12`).
