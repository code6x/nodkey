# nodkey

nodkey lets an AI coding agent use a secret or an SSH key only after a
person approves that one request on a phone.

**Status:** early work. Nothing here is ready to use yet. Version 1 is
being built; see the [v1 milestone](https://github.com/code6x/nodkey/milestone/1).

## How it works

- A small daemon, the **broker**, runs on a trusted machine. It holds the
  SSH keys and the access to your secret stores (Bitwarden Secrets Manager
  through `bws`, or the Bitwarden Password Manager through `bw`).
- The agent's machine gets only the `nodkey` client. It holds no SSH key
  and no store token. Its own TLS key lets it ask, not approve.
- When the agent needs a secret, it runs
  `nodkey run --secret GH_TOKEN=github-token -- gh release create v1.2.0`.
  The value goes only into that one command's environment. nodkey never
  prints it.
- When `ssh`, `git` or Ansible need a signature, `nodkey ssh-agent` sends
  the request to the broker. The key stays on the broker.
- When a request needs approval, you get a Telegram message with
  **Approve once** and **Deny**, and for some secrets and keys also
  **Approve N min**. It shows which machine asks, for which secret or key,
  and for SSH the real target host, checked by the broker. No answer
  means no.
- Every request and decision goes into a hash-chained audit log.

## Read more

- [DESIGN.md](DESIGN.md): how version 1 works.
- [THREAT-MODEL.md](THREAT-MODEL.md): what nodkey protects against, and
  what it does not. Please read section 5 before you use nodkey.
- [SECURITY.md](SECURITY.md): how to report a security problem.

## License

[Apache-2.0](LICENSE)
