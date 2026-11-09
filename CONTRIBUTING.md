# Contributing to nodkey

Thank you for your help. nodkey is a security tool, so the rules for a
change are strict. This page says what they are and where to read more.

Please read these first. They are the rules the code must follow:

- [AGENTS.md](AGENTS.md): the layout of the code, the commands, and the
  rules for every change. They apply to people and to AI agents alike.
- [DESIGN.md](DESIGN.md): how nodkey works.
- [THREAT-MODEL.md](THREAT-MODEL.md): what nodkey promises, and what it
  does not.

Everyone who takes part follows the
[code of conduct](CODE_OF_CONDUCT.md).

## Report a bug or ask for a feature

Open an [issue](https://github.com/code6x/nodkey/issues/new/choose) and
choose a form. Every issue has a **"Done when"** list: the checks that
show the work is done. The issue closes when every box has evidence.

Before you paste a log or a config, remove every token, key, host name
and address from it.

## Report a security problem

Do **not** open a public issue. Report it privately, as
[SECURITY.md](SECURITY.md) says.

## Build and test

You need Go 1.26 or newer. The commands are in
[AGENTS.md](AGENTS.md#commands):

```sh
go test -race ./...
go vet ./...
golangci-lint run --build-tags e2e
```

The end-to-end test runs `sshd` in a container. It needs Docker, `ssh`
and `git` ([DESIGN.md section 17](DESIGN.md)):

```sh
go test -race -tags e2e ./test/e2e/...
```

## Make a pull request

- **One issue gives one pull request**, on its own branch. Say which
  issue it closes.
- **The title follows [Conventional Commits](https://www.conventionalcommits.org/)**,
  for example `fix: deny an empty key name`. The allowed types are in
  [docs/releasing.md](docs/releasing.md#pull-request-titles). Pull
  requests are squash merged, so the title becomes the commit message.
- **Tests cover the deny paths too**, not only the happy path. nodkey
  fails closed: every error, timeout or unclear case means deny.
- **The docs change in the same pull request.** If a change alters what a
  message shows, what the broker checks, or where a value goes, update
  DESIGN.md and THREAT-MODEL.md. If it changes the config, a command or a
  line that a guide in `docs/` shows, update that guide too.
- **Dependencies:** only the standard library, `golang.org/x/crypto` and
  `github.com/BurntSushi/toml`. Anything else needs a reason in the pull
  request ([AGENTS.md](AGENTS.md#rules)).
- **No private data.** This repository is public. Never add a real host
  name, domain name, IP address, MAC address, token, key, serial number,
  or private name. Use `laptop`, `web-1`, `example.com` and addresses
  from `192.0.2.0/24`.
- **Plain English** in docs and messages, with short sentences. Many
  readers are not native speakers. Dates are absolute (`2026-10-12`).
- **Every change gets a security review** before it is merged
  ([AGENTS.md](AGENTS.md#rules)).

## License of a contribution

nodkey is under the [Apache License 2.0](LICENSE). By section 5 of the
license, what you send in a pull request is under the same license. There
is no contributor license agreement (CLA) to sign.
