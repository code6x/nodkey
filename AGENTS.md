# Working on nodkey

nodkey gives an AI coding agent a secret or an SSH signature only after a
person approves that one request on a phone. Read [DESIGN.md](DESIGN.md)
and [THREAT-MODEL.md](THREAT-MODEL.md) before you change code. They are the
rules the code must follow.

## Layout

Planned. Each v1 issue adds its part.

- `cmd/nodkey/` - the one binary. Subcommands: `broker`, `run`,
  `ssh-agent`, `ssh-grant`, `keygen`, `audit verify`, `version`.
  `nodkey broker` starts the broker's parts in a fixed order, and stops
  them in a fixed order (DESIGN.md section 15). Its tests run it in a
  child process, with a fake Telegram server behind a fake HTTPS proxy.
- `internal/` - one package per part (config, transport, audit, approval,
  telegram, store, sshauth, client parts). Packages do not import
  `cmd/`.
  - `internal/api/` - the protocol between the clients and the broker:
    the paths, the request and answer types, and their caps.
  - `internal/broker/` - the broker's service: it answers each request in
    the order of DESIGN.md sections 5 and 6. `nodkey broker` makes its
    parts and runs it.
  - `internal/client/` - the client side: the requests to the broker
    (config, TLS key, deadline, short code, strict answer),
    `nodkey run` (DESIGN.md sections 5 and 15), `nodkey ssh-agent`
    (sections 6 and 15) and `nodkey ssh-grant` (sections 13 and 15).
- `contrib/systemd/` - the example systemd unit of the broker, with
  encrypted credentials and a sandbox (DESIGN.md section 16).
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
  request.
- **Dependencies:** the standard library, `golang.org/x/crypto` and
  `github.com/BurntSushi/toml`. Anything else needs a reason in the pull
  request.
- **Git:** one feature branch and one pull request per issue. Pull request
  titles follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`). Pull requests are
  squash merged. Never push to `main` directly.
- **Open work is a GitHub issue** with a "Done when" checklist, never a TODO
  file.
- **Docs** use plain English and short sentences. Many readers are not
  native speakers. Dates are absolute (`2026-10-12`).
