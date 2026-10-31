# nodkey

nodkey lets an AI coding agent use a secret or an SSH key only after a
person approves that one request on a phone.

**Status:** on 2026-10-15, the code of version 1 is on `main`, and the
test with a real Telegram bot
([#17](https://github.com/code6x/nodkey/issues/17)) is done. The latest
release is on the
[release page](https://github.com/code6x/nodkey/releases/latest).
Try it on a test setup first. See the
[v1 milestone](https://github.com/code6x/nodkey/milestone/1).

## How it works

- A small daemon, the **broker**, runs on a trusted machine. It holds the
  SSH keys and the access to your secret stores (Bitwarden Secrets Manager
  through `bws`, the Bitwarden Password Manager through `bw`, a vault of
  1Password, or a project of Infisical).
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
  In place of Telegram, the broker can use an ntfy server that you run
  yourself ([docs/setup.md](docs/setup.md#ntfy-in-place-of-the-telegram-bot)).
- Every request and decision goes into a hash-chained audit log.

## Try it

See the flow first, on one Linux machine, in a few minutes. `nodkey try`
needs no root, no second host, no Telegram bot, no store account and no
config file. It uses three fake secrets, and asks in its own terminal in
place of your phone.

With `nodkey` installed (step 1 of the quick start), run in one terminal:

```sh
nodkey try
```

In a second terminal, run the command that it prints:

```sh
nodkey try run --secret DEMO_TOKEN=demo-token -- sh -c 'echo "got ${#DEMO_TOKEN} characters"'
```

The request shows up in the first terminal. Type `1` (Approve once), `2`
(Approve 5 min) or `3` (Deny), then Enter. Or wait 2 minutes: the
request expires and is denied. Press Ctrl-C to end the trial; it removes
its files.

Try mode is not a setup. The agent could type the answer in that
terminal, so the trial has only fake values (they start with `TRY-`) and
can never reach a real secret. A real setup adds a separate broker host,
a secret store, Telegram on your phone and the rules of each secret: see
below and [docs/setup.md](docs/setup.md).

## Quick start

This is the short way, for a first test with one secret. The full setup,
with the safety steps that real use needs, is in
[docs/setup.md](docs/setup.md).

| where | what it gets |
|---|---|
| the **broker host**: a trusted Linux machine with systemd, always on, with no agent on it | `nodkey`, which runs `nodkey broker`; `bws`; the bot token, the store token and the TLS key of the broker, as encrypted systemd credentials |
| the **agent machine**: where the agent works | `nodkey`, and its own TLS key |
| your **phone** | Telegram, with a bot of your own |

**Do the setup of the broker host on its console, or from a trusted
computer where no agent runs.** Make and copy the tokens only there or
on your phone, never through the agent machine: the agent may read its
clipboard, terminals and browser. Keep no SSH key or other way to get
root on the broker host on the agent machine
([docs/setup.md section 1](docs/setup.md#where-you-do-the-setup)).

1. **Install** `nodkey` on both machines, as root on each machine. Never
   download, build or copy it as the user of the agent. Get the root
   shell in a way that does not go through the agent's account: on the
   broker host, its console or a trusted computer; on the agent machine,
   its console or SSH as an admin user from a trusted computer, not
   `sudo` in the terminal where the agent works. (nodkey's promises come
   from the broker, which trusts nothing from the client: a changed
   client gets no more than what you approve on the phone.)

   The easy way is the installer. It installs the newest release as
   `/usr/local/bin/nodkey`. First it checks the SHA-256 and the build
   attestation of the release, and the version of the new file. Download
   it as root, read it, and run it as root:

   ```sh
   sudo curl --proto '=https' --tlsv1.2 -fsSL -o /root/install.sh https://raw.githubusercontent.com/code6x/nodkey/main/install.sh
   sudo less /root/install.sh
   sudo sh /root/install.sh
   ```

   The installer needs the Sigstore bundle of the attestation in the
   release, and 0.1.0 has none. For 0.1.0, get nodkey by hand on a
   trusted machine, check it, and copy it to both machines, as
   [docs/setup.md section 2](docs/setup.md#2-get-nodkey) says. Later,
   `nodkey update`, as root, installs a new release.

2. **Make a Telegram bot** with [@BotFather](https://t.me/BotFather)
   (`/newbot`), on your phone or a trusted computer. Open the bot and
   tap **Start**, and find your Telegram user ID
   ([docs/setup.md section 4](docs/setup.md#4-the-telegram-bot)).
   **Never log in to this Telegram account on a machine where an agent
   runs:** whoever can use the account can approve.
   Put the secret into Bitwarden Secrets Manager, and make a machine
   account with an access token that can read it. **Do this with a
   Bitwarden account that is never logged in on a machine where an agent
   runs:** whoever can use the account can read the secret without
   nodkey. Install `bws` as `/usr/local/bin/bws`, owned by root
   ([section 5](docs/setup.md#5-stores)).
3. **On the broker host, as root**, make the user of the broker, its TLS
   key and the encrypted credentials. Use `--with-key=host` instead of
   `--with-key=host+tpm2` if `systemd-creds has-tpm2` does not say `yes`.

   ```sh
   useradd --system --home-dir /var/lib/nodkey --shell /usr/sbin/nologin nodkey
   install -d -m 0755 /etc/nodkey
   install -d -m 0700 /etc/nodkey/credentials /run/nodkey-setup
   nodkey keygen --out /run/nodkey-setup/broker-tls-key    # prints the pin of the broker
   systemd-creds encrypt --with-key=host+tpm2 --name=broker-tls-key \
     /run/nodkey-setup/broker-tls-key /etc/nodkey/credentials/broker-tls-key.cred
   rm /run/nodkey-setup/broker-tls-key
   systemd-ask-password -n "Telegram bot token:" |
     systemd-creds encrypt --with-key=host+tpm2 --name=telegram-token - /etc/nodkey/credentials/telegram-token.cred
   systemd-ask-password -n "bws access token:" |
     systemd-creds encrypt --with-key=host+tpm2 --name=bws-token - /etc/nodkey/credentials/bws-token.cred
   install -m 0644 /dev/null /etc/nodkey/known_hosts       # empty: no SSH keys yet
   ```

4. **On the agent machine**, make the TLS key of the client:

   ```sh
   install -d -m 0700 ~/.config/nodkey
   nodkey keygen --out ~/.config/nodkey/client.key         # prints the pin of the client
   ```

   Then write `~/.config/nodkey/client.toml`, with mode `0600`:

   ```toml
   broker = "192.0.2.10:7743"                # the broker host on your private network
   broker_pin = "sha256:Q2b9...base64..."    # the pin of the broker
   tls_key = "~/.config/nodkey/client.key"
   ```

5. **On the broker host**, write `/etc/nodkey/broker.toml`, owned by root
   with mode `0644`:

   ```toml
   listen = "192.0.2.10:7743"
   tls_key = "${CREDENTIALS_DIRECTORY}/broker-tls-key"
   audit_log = "/var/lib/nodkey/audit.jsonl"
   known_hosts = "/etc/nodkey/known_hosts"

   [telegram]
   token_file = "${CREDENTIALS_DIRECTORY}/telegram-token"
   user_id = 123456789                       # your Telegram user ID

   [client.laptop]
   pin = "sha256:Yf3c...base64..."           # the pin of the client

   [store.main]
   type = "bws"
   program = "/usr/local/bin/bws"
   token_file = "${CREDENTIALS_DIRECTORY}/bws-token"

   [secret.github-token]
   store = "main"
   id = "00000000-0000-0000-0000-000000000000"   # the ID of the secret in Secrets Manager
   clients = ["laptop"]
   ask = "always"
   ```

   Take the example unit from the tag of the version you installed
   (`contrib/systemd/nodkey.service` at the tag `vX.Y.Z`), never through
   the agent machine
   ([docs/setup.md section 8](docs/setup.md#8-the-systemd-unit)). After
   a build from the source, use the unit in your copy of the repository
   instead. For a release, on the broker host:

   ```sh
   VERSION=$(/usr/local/bin/nodkey version | cut -d' ' -f2)
   curl -fL -o /etc/systemd/system/nodkey.service "https://raw.githubusercontent.com/code6x/nodkey/refs/tags/v$VERSION/contrib/systemd/nodkey.service"
   ```

   Keep only the `LoadCredentialEncrypted=` lines of `broker-tls-key`,
   `telegram-token` and `bws-token`. Then start the broker, and read its
   log:

   ```sh
   systemctl daemon-reload
   systemctl enable --now nodkey
   journalctl -u nodkey
   ```

6. **The first run**, on the agent machine:

   ```sh
   nodkey run --secret GH_TOKEN=github-token --reason "test the setup" -- \
     sh -c 'echo "the command got ${#GH_TOKEN} characters"'
   ```

   A Telegram message comes, with the same short code that the client
   prints. Tap **Approve once**. The command gets the secret in
   `GH_TOKEN`, and prints only its length.

Before real use, read
[docs/setup.md](docs/setup.md): above all the safety of your Telegram
and Bitwarden accounts and of the broker host
([section 9](docs/setup.md#9-account-and-host-safety)), SSH logins
([section 11](docs/setup.md#11-a-client-on-the-agent-machine)), and the
check of the audit log
([section 12](docs/setup.md#12-check-the-audit-log)).

## Read more

- [docs/setup.md](docs/setup.md): the full setup of the broker, the
  stores, the Telegram bot and the clients.
- [docs/manual-telegram-test.md](docs/manual-telegram-test.md): the
  manual test with a real Telegram bot.
- [docs/manual-ntfy-test.md](docs/manual-ntfy-test.md): the manual
  test with a real ntfy server.
- [DESIGN.md](DESIGN.md): how version 1 works.
- [THREAT-MODEL.md](THREAT-MODEL.md): what nodkey protects against, and
  what it does not. Please read section 5 before you use nodkey.
- [SECURITY.md](SECURITY.md): how to report a security problem.

## License

[Apache-2.0](LICENSE)
