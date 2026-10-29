# Set up nodkey

This guide sets up nodkey from the start: the broker on a trusted
machine, a Telegram bot for the approvals, the secret stores, and the
client on the machine where the AI agent works.

[DESIGN.md](../DESIGN.md) says how nodkey works, and
[THREAT-MODEL.md](../THREAT-MODEL.md) says what it protects against.
Please read
[section 5 of the threat model](../THREAT-MODEL.md#5-what-nodkey-does-not-promise)
before you rely on nodkey.

The examples use these names. Use your own names instead.

| name | what it is |
|---|---|
| `broker-host` | the trusted machine that runs the broker |
| `192.0.2.10` | the address of the broker host on your private network |
| `laptop` | the agent machine, and the name of its client key in the broker config |
| `web-1`, `web-2` | SSH hosts that the agent may log in to |
| `deploy` | the remote user on these hosts, and the name of the broker's SSH key |
| `github-token` | a secret that the agent may ask for |
| `123456789` | the Telegram user ID of the approver: you |

Run the commands for the broker host as root, for example in a shell
from `sudo -i`, on its console or from a trusted computer
([section 1](#where-you-do-the-setup)). Run the commands for the agent
machine as the user who runs the agent. Only the install of nodkey is
different: run it as root on each host, also on the agent machines, from
a root shell that does not come through the agent's account
([section 2](#2-get-nodkey)).

## Contents

1. [Before you start](#1-before-you-start)
2. [Get nodkey](#2-get-nodkey)
3. [The broker host](#3-the-broker-host)
4. [The Telegram bot](#4-the-telegram-bot)
5. [Stores](#5-stores)
6. [SSH keys and the broker's known_hosts](#6-ssh-keys-and-the-brokers-known_hosts)
7. [The config file](#7-the-config-file)
8. [The systemd unit](#8-the-systemd-unit)
9. [Account and host safety](#9-account-and-host-safety)
10. [Start the broker](#10-start-the-broker)
11. [A client on the agent machine](#11-a-client-on-the-agent-machine)
12. [Check the audit log](#12-check-the-audit-log)
13. [Upgrades and key changes](#13-upgrades-and-key-changes)
14. [When something does not work](#14-when-something-does-not-work)

## 1. Before you start

You need:

- **A broker host.** A Linux machine that is always on, with systemd 250
  or newer (`systemctl --version`; for example Debian 12, or Ubuntu
  24.04) and cgroup v2. No AI agent runs on it, and only you have root
  there. It uses no swap, or only encrypted swap, and no hibernation
  ([section 9](#swap-and-hibernation)). If it has a TPM2 chip, the keys
  of nodkey can be bound to it.
- **One or more agent machines.** The Linux machines where the agent
  works. For SSH logins, they need OpenSSH 8.9 or newer (`ssh -V`).
- **A private network** between them, such as your LAN or a VPN, and a
  fixed address of the broker host on it. The clients connect to one
  TCP port of the broker: 7743 in the examples.
- **Telegram on your phone.** This Telegram account approves the
  requests.
- **A store for the secret values**: Bitwarden Secrets Manager (`bws`),
  or a separate account of the Bitwarden Password Manager (`bw`). If you
  use nodkey only for SSH logins, you need no store.

The broker host is the root of trust. Root on it, or a copy of its
memory, gives every key and token (THREAT-MODEL.md section 5, item 5).
[DESIGN.md section 4](../DESIGN.md#4-the-parts) shows how the parts fit
together.

**Never log in to the approving Telegram account on a machine where an
agent runs.** Whoever can use that account can approve
([section 9](#the-approvers-telegram-account)).

**On a machine where an agent runs, never log in to a Bitwarden account
that can read the secrets.** Whoever can use such an account can read
them without nodkey
([section 9](#the-bitwarden-accounts-that-can-read-the-secrets)).

### Where you do the setup

The agent machine is not trusted. The agent may read its clipboard, its
terminals, its browser and its files. A token that passes through it
may be the agent's from then on. With the `bws` token alone, the agent
could read every secret of its project, without a tap (THREAT-MODEL.md
section 5, item 8). So:

- **Do the setup of the broker host on its console, or from a trusted
  computer where no agent runs.** Do not log in to the broker host from
  an agent machine.
- **Make and copy tokens and passwords only on that trusted computer,
  or on your phone**: the bot token, the `bws` access token, the
  master password of each Bitwarden account that can read the secrets,
  and the API key of a `bw` account. Never let them pass through an
  agent machine: not its clipboard, not its terminal, not its browser.
  Do not save them in a password manager that is open on an agent
  machine.
- **Keep no way to get root on the broker host on an agent machine**:
  no SSH key for the broker host, no SSH agent or `ControlMaster`
  socket that reaches it, no saved password.
- **The user of the agent never downloads, builds or copies the nodkey
  binary**, on any machine: the agent could change the file before it is
  installed. Install nodkey as root on each host, with the installer. Or
  copy it straight from a trusted machine where you built or downloaded
  it, not through an agent machine, and check its SHA-256 on the broker
  host ([section 2](#2-get-nodkey)).

## 2. Get nodkey

Install the same version of nodkey on the broker host and on each agent
machine, as `/usr/local/bin/nodkey`, owned by root. When the versions
differ, nodkey says so ([section 13](#a-new-version-of-nodkey)). **Do it
as root on each host, never as the user of the agent.** The agent can
change what its own user downloads, builds or copies
([section 1](#where-you-do-the-setup)). Get the root shell in a way that
does not go through the agent's account:

- **On the broker host:** on its console, or from a trusted computer, as
  for the rest of the setup. Never set it up or update it through an
  agent machine.
- **On an agent machine:** on its console, or with SSH as an admin user
  from a trusted computer. If you can, do not type `sudo` in the terminal
  where the agent works, or in the agent's account. The agent can put its
  own `sudo` there (a program of that name earlier in `PATH`, an alias or
  a function), or type into that terminal.

This has a limit. On an agent machine that the agent controls, nodkey
cannot keep its own client safe. But nodkey's promises come from the
broker, which trusts nothing from the client: a changed client binary
gets no more than what you approve on the phone
([THREAT-MODEL.md T20](../THREAT-MODEL.md)).

There are two ways to install: the installer, or by hand.

### The installer

`install.sh` in the repository installs the newest release, or the
version of `--version X.Y.Z`. It needs `curl`, `tar`, `gzip`,
`sha256sum`, `install`, `mktemp`, `stat` and `uname`, and no GitHub
login. Before it installs anything, it checks the SHA-256 and the build
attestation of the release, and that the new nodkey says it is the
version that you want
([DESIGN.md section 18](../DESIGN.md#18-build-ci-and-releases)). If a
check fails, it installs nothing. It restarts nothing. As root, it also
refuses a directory or a file that another user than root can change:
`/usr/local/bin`, the old `nodkey` in it, and the temporary directory
(`TMPDIR`, or `/tmp`).

The first time, on each host: download the script as root, read it, and
run it as root:

```sh
sudo curl --proto '=https' --tlsv1.2 -fsSL -o /root/install.sh https://raw.githubusercontent.com/code6x/nodkey/main/install.sh
sudo less /root/install.sh
sudo sh /root/install.sh
nodkey version
```

On the broker host, where no agent runs, the short form works too. But
it runs the script before you can read it:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/code6x/nodkey/main/install.sh | sudo sh
```

To check the attestation, the installer downloads gh 2.102.0, and
checks it against the SHA-256 in the script. To use a gh that is
installed already, 2.93.0 or newer, add `--gh /usr/bin/gh`. Only root may
be able to change that gh and its directories: root runs it. The
installer needs the Sigstore bundle of the attestation in the release,
`nodkey_<version>.sigstore.json`. 0.1.0 has none: install 0.1.0 by hand.

When that version is installed already, the installer does nothing. It
does not check the installed file then. To replace it with a checked
copy, add `--reinstall`.

Later, `nodkey update` runs the copy of the installer that is built into
the installed nodkey ([section 13](#a-new-version-of-nodkey)). It takes
`--version`, `--gh` and `--reinstall` too.

### By hand

Use a trusted machine for this, never an agent machine
([section 1](#where-you-do-the-setup)). Get nodkey from a release, or
from the source.

**From a release.** Download the tarball for your machine, such as
`nodkey_0.1.0_linux_amd64.tar.gz` (`nodkey_0.1.0_linux_arm64.tar.gz` on
64-bit ARM), `SHA256SUMS`, and the bundle `nodkey_<version>.sigstore.json`
if the release has one, from the
[release page](https://github.com/code6x/nodkey/releases). Check it, as
[docs/releasing.md](releasing.md#verify-a-download) says, with all the
steps there. From gh 2.96.0 on, `gh release download` needs no GitHub
login. `gh attestation verify` needs none with `--bundle`, but needs one
without it, such as for 0.1.0. Then take the file `nodkey` out of the
tarball:

```sh
tar -xzf nodkey_0.1.0_linux_amd64.tar.gz nodkey
```

**From the source.** Build nodkey with Go 1.26 or newer. Never build it
on an agent machine: the agent could change the build.

```sh
git clone https://github.com/code6x/nodkey.git
cd nodkey
CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$(git rev-parse --short HEAD)" -o nodkey ./cmd/nodkey
```

The `-ldflags` part is optional. It puts the commit into
`nodkey version` and into the `broker_started` entry of the audit log.

**Then, for both ways:** copy the file `nodkey` straight from the
trusted machine to each machine, never through an agent machine
([section 1](#where-you-do-the-setup)). On the broker host, check that it
is the same file: `sha256sum nodkey` must print the same SHA-256 as on
the trusted machine. Then install it, and check it:

```sh
install -o root -g root -m 0755 nodkey /usr/local/bin/nodkey
nodkey version
```

On a terminal, `nodkey version` of a release also asks GitHub whether a
newer release is out, and says so in one more line. `--offline` skips
that.

## 3. The broker host

### The user and the directories

The broker runs as a system user of its own, `nodkey`:

```sh
useradd --system --home-dir /var/lib/nodkey --shell /usr/sbin/nologin nodkey
install -d -o root -g root -m 0755 /etc/nodkey
install -d -o root -g root -m 0700 /etc/nodkey/credentials /run/nodkey-setup
```

- `/etc/nodkey` holds the config file and the broker's `known_hosts`.
  Only root may change them. The broker only reads them.
- `/etc/nodkey/credentials` holds the encrypted credentials. Only root
  reads them: systemd opens them for the broker at each start.
- `/run/nodkey-setup` is a work directory in memory: `/run` is a tmpfs.
  Plain keys and tokens stay there only for a moment. They do not reach
  the disk, unless the machine moves them to swap. So before you make
  any key, make sure that the machine has no swap, or only encrypted
  swap ([section 9](#swap-and-hibernation)). The directory is gone after
  a reboot; then make it again with the same command.
- `/var/lib/nodkey` is the state directory: the audit log, and a home
  directory for each store. systemd makes it at the first start
  (`StateDirectory=` in the unit). For some store steps, you make it
  earlier by hand ([section 5](#5-stores)).

### Encrypted credentials

Every key, token and password of the broker is a systemd credential: a
file that `systemd-creds` encrypted. At each start, systemd decrypts the
credentials and gives them to the broker in `$CREDENTIALS_DIRECTORY`, a
directory in memory that only the broker can read. The config names
each one as `${CREDENTIALS_DIRECTORY}/NAME`
([DESIGN.md section 11](../DESIGN.md#11-decision-2-loading-keys-after-a-restart)).

Check whether the machine has a TPM2 chip that systemd can use:

```sh
systemd-creds has-tpm2
```

If the first line of the output is `yes`, bind the credentials to the
TPM2 chip and to this installation:

```sh
WITH_KEY=host+tpm2
```

Otherwise, use the key of this installation only:

```sh
WITH_KEY=host
```

Without the TPM2 chip, anyone with a full copy of the disk can decrypt
the credentials: the key is in `/var/lib/systemd/credential.secret`. So
can anyone with a backup that holds both that file and the credentials.
With `host+tpm2`, they also need the TPM2 chip of this machine. On a
disk without encryption, `systemd-creds` warns that this file "is not
located on encrypted media"; that is the risk just described. Set
`WITH_KEY` again in each new shell; the commands below use it.

Before systemd 258, `host+tpm2` also binds each credential to PCR 7 of
the TPM2 chip: the state of Secure Boot. A firmware update or a change
of the Secure Boot settings can change PCR 7. Then no credential can be
decrypted any more, and systemd does not start the broker
([section 14](#14-when-something-does-not-work)). That fails closed, but
you must make the credentials again. If you did not update the firmware
or change Secure Boot, find out why before you make new credentials:
someone may have changed how the machine starts. systemd 258 and newer bind to no
PCR by default. To get that on an older systemd, add `--tpm2-pcrs=`
(with nothing after `=`) to each `systemd-creds encrypt`. Then the
credentials survive such updates, but the TPM2 chip no longer checks
how the machine was started.

Each credential has a name. `systemd-creds` writes the name into the
file, and systemd refuses the file under another name. The example
config and the example unit use these names:

| name | what it holds | made in |
|---|---|---|
| `broker-tls-key` | the TLS key of the broker | [this section](#the-tls-key-of-the-broker) |
| `telegram-token` | the token of the bot | [section 4](#4-the-telegram-bot) |
| `bws-token` | the access token of a Secrets Manager machine account | [section 5](#bws-bitwarden-secrets-manager) |
| `bws-token-backup` | the access token of a second machine account | [section 5](#bws-bitwarden-secrets-manager) |
| `bw-master-password` | the master password of a separate Bitwarden account | [section 5](#bw-a-separate-bitwarden-account) |
| `ssh-deploy` | the SSH key `deploy` | [section 6](#the-ssh-keys-of-the-broker) |

There are two ways to make a credential:

- From a file, such as a key. Then remove the plain file:

  ```sh
  systemd-creds encrypt --with-key="$WITH_KEY" --name=NAME FILE /etc/nodkey/credentials/NAME.cred
  ```

- From what you type, for a token or a password. `systemd-ask-password`
  shows a `*` for each character, never the text, and the value never
  goes to a file, a command line or the shell history. It waits at most
  90 seconds. `-n` leaves out the newline at the end:

  ```sh
  systemd-ask-password -n "NAME:" |
    systemd-creds encrypt --with-key="$WITH_KEY" --name=NAME - /etc/nodkey/credentials/NAME.cred
  ```

To check a credential without showing it, count its bytes:

```sh
systemd-creds decrypt --name=NAME /etc/nodkey/credentials/NAME.cred - | wc -c
```

### The TLS key of the broker

The clients and the broker connect over mutual TLS. Each side pins the
key of the other side; there is no certificate authority
([DESIGN.md section 10](../DESIGN.md#10-decision-1-how-client-and-broker-connect)).
Make the key of the broker:

```sh
nodkey keygen --out /run/nodkey-setup/broker-tls-key
```

`nodkey keygen` prints the pin of the new key, such as
`sha256:Q2b9...`. Write it down: each client needs it as `broker_pin`.
The broker also logs it at each start. Now make the credential, and
remove the plain key:

```sh
systemd-creds encrypt --with-key="$WITH_KEY" --name=broker-tls-key \
  /run/nodkey-setup/broker-tls-key /etc/nodkey/credentials/broker-tls-key.cred
rm /run/nodkey-setup/broker-tls-key
```

## 4. The Telegram bot

The broker sends each request to you as a Telegram message from a bot
of your own. Only your taps count.

1. **Make the bot.** Use Telegram on your phone, or on a trusted
   computer where no agent runs: **never use BotFather on an agent
   machine.** Open the chat with [@BotFather](https://t.me/BotFather)
   and send `/newbot`. Choose a name and a user name for the bot.
   BotFather answers with the bot token. Use this bot for this one
   broker only: Telegram lets only one program read the answers of a
   bot.
2. **Start the chat.** Open the new bot in Telegram, and tap **Start**.
   A bot cannot write to you before you do this.
3. **Save the token as a credential.** On the broker host:

   ```sh
   systemd-ask-password -n "Telegram bot token:" |
     systemd-creds encrypt --with-key="$WITH_KEY" --name=telegram-token - /etc/nodkey/credentials/telegram-token.cred
   ```

   Never paste the token into a chat, an issue, a file in a repository,
   or a command line.
4. **Find your user ID.** The tap on **Start** sent the message
   `/start` to the bot. On the broker host, before the first start of
   the broker:

   ```sh
   read -rs TOKEN    # paste the token, then press Enter; it is not shown
   printf 'url = "https://api.telegram.org/bot%s/getUpdates"\n' "$TOKEN" |
     curl -sS --config - -H 'Content-Type: application/json' \
       -d '{"allowed_updates":["message","my_chat_member"]}'
   unset TOKEN
   ```

   Your user ID is the number in `"from":{"id":123456789`. `printf` is
   part of the shell, and curl reads the address from its input, so the
   token is not in the list of processes.

   Never call `getUpdates` while the broker runs. Telegram lets only one
   program read the updates of a bot. The broker would see a conflict,
   send an alert that the token may be stolen, and stop (exit code 76).
5. **A chat for notices (optional).** A "never ask" rule
   ([section 7](#7-the-config-file)) sends a silent notice for each use.
   By default, the notices go to your chat with the bot. To keep that
   chat for approvals only, make a Telegram group with only you in it,
   and add the bot. Nobody else may join this group: its members see
   the names of the secrets, the clients and the hosts. Then run the
   `getUpdates` command again. The ID of the group is the negative
   number in `"chat":{"id":-...`. It starts with `-100` for a
   supergroup. It goes into `notice_chat_id`.
6. **Keep the bot out of other groups (optional).** If the bot is in no
   group, send `/setjoingroups` to BotFather and choose **Disable**.
   Then nobody can add the bot to a group.

## 5. Stores

For each value, the broker runs the program of the store: `bws` or `bw`
([DESIGN.md section 16](../DESIGN.md#store-programs)). The program gets
a token or the master password from the broker, so it must be the real
program, and nobody else may change it.

### Where bws and bw come from

- Take them only from the official releases: `bws` from the `bws-v...`
  releases of
  [bitwarden/sdk-sm](https://github.com/bitwarden/sdk-sm/releases), and
  the standalone `bw` from the `cli-v...` releases of
  [bitwarden/clients](https://github.com/bitwarden/clients/releases).
  The broker also accepts `bw` from npm (`@bitwarden/cli`), but see
  below. Check each download.
- Install them owned by root, with mode `0755`, in a directory that only
  root can write to, such as `/usr/local/bin`. The broker checks this at
  start: the program and every directory on the way to it must be owned
  by root (or by `nodkey`), and group and others must not be able to
  write to them.
- A `bw` from npm is a Node.js script. The broker runs `bw` with
  `PATH=/usr/local/bin:/usr/bin:/bin`, and the script starts the `node`
  that it finds there. That `node` must be owned by root, below
  directories that only root can write to, also after its links. The
  broker checks this at start. A `node` from nvm in a home directory is
  not found there.
- There must be no directory named `bw-data` next to `bw`, next to the
  file that `bw` links to, or next to that `node`. With it, bw keeps its
  login and its copy of the vault there, not in the home directory of
  the store, so the broker refuses to start.

An example with bws 2.1.0 on x86-64 (take the newest release, and
`aarch64` instead of `x86_64` on 64-bit ARM). The checksum file of the
release lists the SHA-256 of each file:

```sh
cd /run/nodkey-setup
curl -fLO https://github.com/bitwarden/sdk-sm/releases/download/bws-v2.1.0/bws-x86_64-unknown-linux-gnu-2.1.0.zip
curl -fLO https://github.com/bitwarden/sdk-sm/releases/download/bws-v2.1.0/bws-sha256-checksums-2.1.0.txt
sha256sum -c --ignore-missing bws-sha256-checksums-2.1.0.txt
unzip bws-x86_64-unknown-linux-gnu-2.1.0.zip bws
install -o root -g root -m 0755 bws /usr/local/bin/bws
rm bws bws-x86_64-unknown-linux-gnu-2.1.0.zip bws-sha256-checksums-2.1.0.txt
```

`sha256sum` must print `OK` for the zip file. An example with the
standalone bw 2026.9.1 (`bw-linux-arm64-...` on 64-bit ARM). Its release
has no checksum file, so compare the SHA-256 with the `sha256:` value
that GitHub shows next to the file on the release page:

```sh
cd /run/nodkey-setup
curl -fLO https://github.com/bitwarden/clients/releases/download/cli-v2026.9.1/bw-linux-2026.9.1.zip
sha256sum bw-linux-2026.9.1.zip
unzip bw-linux-2026.9.1.zip bw
install -o root -g root -m 0755 bw /usr/local/bin/bw
rm bw bw-linux-2026.9.1.zip
```

With [gh](https://cli.github.com/), this prints the value from the
release page:

```sh
gh release view cli-v2026.9.1 --repo bitwarden/clients --json assets \
  --jq '.assets[] | select(.name == "bw-linux-2026.9.1.zip") | .digest'
```

Prefer the standalone `bw`. `npm install --global` runs the install
scripts of every package in the tree as root, on the most trusted
machine that you have. If you still want the `bw` from npm, install the
`node` of your distribution (in `/usr/bin`), and an exact version of the
package, as root:

```sh
npm install --global @bitwarden/cli@2026.9.1
ls -l /usr/local/bin/bw "$(readlink -f /usr/local/bin/bw)" "$(command -v node)"
```

All of them must be owned by root. A bad version of `@bitwarden/cli` was
on npm for about 90 minutes on 2026-04-22 (THREAT-MODEL.md T20). So
choose the version, and read the release notes before an upgrade.

### bws: Bitwarden Secrets Manager

**Use a Bitwarden account that is never logged in on an agent machine**:
no web app in a browser, no browser extension, no desktop app and no CLI
there. Every owner and admin of the organization can read every secret
in Secrets Manager, and so can each member that you give access to the
project ([THREAT-MODEL.md T32](../THREAT-MODEL.md#6-threats-and-answers)).
If your main Bitwarden account is logged in on an agent machine, make
the organization for Secrets Manager with a separate account, and do not
add your main account to it.

Bitwarden offers Secrets Manager for Free, Teams and Enterprise
organizations. Its Free plan is for up to 2 users, 3 projects and 3
machine accounts. With a Families plan, Bitwarden says to make a new
Free organization for Secrets Manager
([Secrets Manager plans](https://bitwarden.com/help/secrets-manager-plans/),
seen 2026-10-16).

In the web app of Secrets Manager, with that account, on a trusted
computer ([section 1](#where-you-do-the-setup)):

1. Make a project for the secrets that nodkey may hand out. Put these
   secrets into it.
2. Make a machine account. Give it read access to this project only.
3. Make an access token for the machine account. It is shown only
   once.
4. Copy the ID of each secret, a UUID. It goes into `id` in the config.
   nodkey hands out the value of the secret.

On the broker host, make the credential:

```sh
systemd-ask-password -n "bws access token:" |
  systemd-creds encrypt --with-key="$WITH_KEY" --name=bws-token - /etc/nodkey/credentials/bws-token.cred
```

bws logs in with the token at each run, so there is no login step. Its
state is in the home directory of the store,
`/var/lib/nodkey/stores/NAME`, where `NAME` is the name of the
`[store.NAME]` section: `main` in the example.

**Bitwarden's EU cloud or your own server.** Set the server once for
each `bws` store, as the broker runs bws: as the user `nodkey`, with
only `HOME` in the environment, in the home directory of the store. Do
this while the broker is stopped. `umask 077` makes the new files
private, as `UMask=0077` does for the broker. Without it, the files get
the umask of your shell, often `022`. For the store `main`:

```sh
(
umask 077
install -d -o nodkey -g nodkey -m 0700 /var/lib/nodkey /var/lib/nodkey/stores /var/lib/nodkey/stores/main
sudo -u nodkey env -i -C /var/lib/nodkey/stores/main HOME=/var/lib/nodkey/stores/main \
  /usr/local/bin/bws config server-base https://vault.bitwarden.eu
)
```

The parentheses keep `umask 077` inside this one block, so later files,
such as the unit, get their normal mode.

bws answers `Profile updated successfully!`.

**A second machine account.** A job with a "never ask" rule
([DESIGN.md section 12](../DESIGN.md#12-decision-3-unattended-runs))
should get its secret through a machine account of its own. Put the
secret into a project of its own, and give the new machine account
access to that project only. Then give it a store section of its own:
in the example config, `[store.backup-job]` with the credential
`bws-token-backup`. Now even a mistake in the config cannot hand out
another secret through that store. Its token can read only that one
project.

### bw: a separate Bitwarden account

The Password Manager CLI cannot unlock the vault without the master
password, so the broker must keep the password. Anyone who breaks into
the broker host gets the whole vault
([DESIGN.md section 11](../DESIGN.md#11-decision-2-loading-keys-after-a-restart),
THREAT-MODEL.md T24). So use `bw` only with a **separate Bitwarden
account** that holds nothing but the items that nodkey may hand out.

**Never log in to this account on an agent machine**: no web app in a
browser, no browser extension, no desktop app and no CLI there. Whoever
can use the account can read every item in it, without nodkey
([THREAT-MODEL.md T32](../THREAT-MODEL.md#6-threats-and-answers)).
Share its items with no other account, and give no account emergency
access to it: such an account could read them too.

1. **Make the account**, on a trusted computer
   ([section 1](#where-you-do-the-setup)). Give it a long random master
   password, for example from `openssl rand -base64 24`.
2. **Add the items.** Each secret is a **login item**, and nodkey hands
   out its password. nodkey refuses an item of another type, and an
   item in the trash or in the archive. Note the ID of each item, a
   UUID. One way: on a trusted computer where you use bw with this
   account, `bw get item "NAME OF THE ITEM" | jq -r .id` prints only the
   ID.
3. **Check the KDF settings.** The KDF settings are in the security
   settings of the account in the web vault. An unlock computes the key
   of the vault from the master password with them, and the broker gives
   each run of bw 30 seconds. Start with the default settings, and check
   the unlock after the first start (step 7). If it takes too long, such
   as on a small ARM board, lower them. With a long random master
   password, lower settings are still safe.
4. **Make the credential of the master password:**

   ```sh
   systemd-ask-password -n "bw master password:" |
     systemd-creds encrypt --with-key="$WITH_KEY" --name=bw-master-password - /etc/nodkey/credentials/bw-master-password.cred
   ```

   bw reads only the first line of this file, so the password must be
   one line.
5. **Log in once, with exactly the environment of the broker.** The
   broker runs bw as the user `nodkey`, with only `HOME` and a fixed
   `PATH` in the environment, in the home directory of the store. Run
   the login and the server setup in the same way, or bw keeps the
   login in another place
   ([DESIGN.md section 16](../DESIGN.md#store-programs)). Do this while
   the broker is stopped, on the console of the broker host or from a
   trusted computer. `umask 077` keeps the new files private, as for
   bws. For the store `vault`:

   ```sh
   umask 077  # new files private; run `umask 022` before you copy the unit (section 8)
   install -d -o nodkey -g nodkey -m 0700 /var/lib/nodkey /var/lib/nodkey/stores /var/lib/nodkey/stores/vault
   # Only for Bitwarden's EU cloud or your own server:
   sudo -u nodkey env -i -C /var/lib/nodkey/stores/vault HOME=/var/lib/nodkey/stores/vault \
     PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/bw config server https://vault.bitwarden.eu
   sudo -u nodkey env -i -C /var/lib/nodkey/stores/vault HOME=/var/lib/nodkey/stores/vault \
     PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/bw login --apikey
   sudo -u nodkey env -i -C /var/lib/nodkey/stores/vault HOME=/var/lib/nodkey/stores/vault \
     PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/bw status
   ```

   `login --apikey` asks for the personal API key of the account,
   `client_id` and `client_secret`. You find it in the security
   settings of the account in the web vault. bw shows the
   `client_secret` on the screen while you paste it. `clear` does not
   remove it from the scrollback of tmux or screen, or from a log of
   the terminal. So log in on the console of the broker host, or clear
   the scrollback too, for example with `tmux clear-history`. Then
   `bw status` must show the separate account in `userEmail`, and
   `"status":"locked"`. Do not unlock: the broker does it.
6. **Never run `bw lock`, `bw unlock` or `bw logout` by hand in the
   home directory of a store.** Each unlock makes a new session key, and
   ends the key of the broker. A lock locks the vault for the broker
   too. Then the next request is denied, and the broker unlocks again.
   After a logout, every request for that store is denied until you log
   in again as in step 5.
7. **Check the unlock after the first start**
   ([section 10](#10-start-the-broker)). The journal must show
   `a store started` with `store=vault`. If it says that a store could
   not start, and the error has `bw unlock` and `took too long`, the
   unlock took more than 30 seconds: lower the KDF settings (step 3).

## 6. SSH keys and the broker's known_hosts

Skip this section if you use nodkey only for secrets. The broker still
needs a `known_hosts` file then. Make an empty one:

```sh
install -o root -g root -m 0644 /dev/null /etc/nodkey/known_hosts
```

### The SSH keys of the broker

Make a new key on the broker host for each purpose. Do not use a key
that was ever on an agent machine: the agent may have a copy
(THREAT-MODEL.md section 5, item 8). The broker refuses a key with a
passphrase; the encrypted credential protects the key instead. It takes
Ed25519, ECDSA (P-256, P-384 and P-521) and RSA keys with at least 2048
bits.

```sh
ssh-keygen -t ed25519 -N '' -C nodkey-deploy -f /run/nodkey-setup/ssh-deploy
systemd-creds encrypt --with-key="$WITH_KEY" --name=ssh-deploy \
  /run/nodkey-setup/ssh-deploy /etc/nodkey/credentials/ssh-deploy.cred
install -o root -g root -m 0644 /run/nodkey-setup/ssh-deploy.pub /etc/nodkey/ssh-deploy.pub
rm /run/nodkey-setup/ssh-deploy /run/nodkey-setup/ssh-deploy.pub
```

Add the public key, `/etc/nodkey/ssh-deploy.pub`, to
`~deploy/.ssh/authorized_keys` on each target host. Manage
`authorized_keys` with your configuration management, so that a key
that the agent adds there is removed again (THREAT-MODEL.md section 5,
item 2).

### The broker's known_hosts

The broker finds the name of a host in its own `known_hosts`, never on
the agent machine. The name is what the message shows, so the file has
stricter rules than the `known_hosts` of OpenSSH
([DESIGN.md section 14](../DESIGN.md#14-configuration)):

- one plain host name on each line: no list of names, no wildcards, no
  hashed names, no `[host]:port`, and no `@cert-authority` or
  `@revoked`;
- plain host keys only, no certificates;
- at most one key of each key type for a name. A name may be on several
  lines, one for each key type;
- each host key only once. Two hosts with the same host key, such as
  cloned machines, are refused. Give each clone new host keys.

The name is the name in the messages, in the `hosts` lists of the
config, and in `nodkey ssh-grant --host`. It does not need to be the DNS
name.

Get the host keys in a safe way. Never copy them from the `known_hosts`
of an agent machine: the agent can change that file.

1. On each target host, list the fingerprints of its host keys. Use the
   console of the host, or an SSH session that you already trust:

   ```sh
   for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done
   ```

2. On the broker host, fetch the host keys, and give each line the plain
   name. `-p` gives the port, if it is not 22:

   ```sh
   ssh-keyscan -t ed25519,ecdsa,rsa web-1.example.com 2>/dev/null |
     awk '{print "web-1", $2, $3}' >> /run/nodkey-setup/known_hosts
   ssh-keyscan -t ed25519,ecdsa,rsa -p 2222 web-2.example.com 2>/dev/null |
     awk '{print "web-2", $2, $3}' >> /run/nodkey-setup/known_hosts
   ```

3. Show the fingerprints of the fetched keys, and compare them with the
   list from step 1. Each one must be the same. If one differs, stop:
   something between the broker host and that host may change the keys.

   ```sh
   ssh-keygen -lf /run/nodkey-setup/known_hosts
   ```

4. Install the file:

   ```sh
   install -o root -g root -m 0644 /run/nodkey-setup/known_hosts /etc/nodkey/known_hosts
   rm /run/nodkey-setup/known_hosts
   ```

Keep all host keys of a host in the file: ssh may use any of them. When
a host gets a new host key, check its fingerprint in the same way,
change the file, and restart the broker.

## 7. The config file

The config file is `/etc/nodkey/broker.toml`. A complete example, the
same as in
[DESIGN.md section 14](../DESIGN.md#14-configuration):

```toml
listen = "192.0.2.10:7743"          # an address on your private network only
tls_key = "${CREDENTIALS_DIRECTORY}/broker-tls-key"
audit_log = "/var/lib/nodkey/audit.jsonl"
known_hosts = "/etc/nodkey/known_hosts"

[telegram]
token_file = "${CREDENTIALS_DIRECTORY}/telegram-token"
user_id = 123456789                 # the approver
notice_chat_id = 123456789          # optional; default: the approver's chat
timeout = "120s"                    # secrets
ssh_timeout = "90s"                 # SSH signatures

[updates]
check = true                        # optional; false: never ask GitHub for a newer release

[preapprove]                        # optional; the limits of scheduled grants
max_ahead = "168h"                  # how far ahead a grant may start; default 7 days
max_open = "8h"                     # the longest time from start to end
max_uses = 10                       # the most uses of one grant
max_grants = 5                      # the most per client: approved, not ended, plus waiting

[standing]                          # optional; the limits of standing grants (DESIGN.md section 8)
summary = "mon 09:00"               # the weekly list of standing grants, in broker local time

[client.laptop]
pin = "sha256:Yf3c...base64..."     # printed by `nodkey keygen`

[store.main]                         # any name; `type` picks the program
type = "bws"
program = "/usr/local/bin/bws"
token_file = "${CREDENTIALS_DIRECTORY}/bws-token"

[store.backup-job]                   # a second machine account, one project
type = "bws"
program = "/usr/local/bin/bws"
token_file = "${CREDENTIALS_DIRECTORY}/bws-token-backup"

[store.vault]
type = "bw"
program = "/usr/local/bin/bw"
password_file = "${CREDENTIALS_DIRECTORY}/bw-master-password"

[secret.github-token]
store = "main"
id = "00000000-0000-0000-0000-000000000000"
clients = ["laptop"]
ask = "window"
window = "15m"
preapprove = true                   # optional; default false: allows `nodkey preapprove`

[key.deploy]
file = "${CREDENTIALS_DIRECTORY}/ssh-deploy"
clients = ["laptop"]
ask = "window"
window = "15m"
hosts = ["web-1", "web-2"]          # optional; empty means any known host
```

Leave out what you do not use, such as a store or a key.

**The top.** `listen` is one IP address and port of the broker host on
the private network. A host name, `0.0.0.0` and `::` are refused: the
broker must not listen on every network. `tls_key` is the credential
from [section 3](#the-tls-key-of-the-broker). The home directories of
the stores are in `stores`, next to `audit_log`.

**`[telegram]`.** `token_file` and `user_id` come from
[section 4](#4-the-telegram-bot). `notice_chat_id` is optional.
`timeout` is how long a request for secrets waits for your tap: 15
seconds to 10 minutes, 120 seconds by default. `ssh_timeout` is the same
for an SSH login: 15 to 110 seconds, 90 seconds by default. sshd drops a
login that takes longer than its `LoginGraceTime` (120 seconds by
default).

**`[preapprove]` and `preapprove`.** A secret or key with
`preapprove = true` lets a client ask for a scheduled grant with
`nodkey preapprove` ([section 11](#a-job-that-runs-later-nodkey-preapprove)).
It is off by default, and it is an error with `ask = "never"`. The four
limits are optional. Their defaults are in the example above. They are
safe, so leave them unless you need more.

**`[updates]`.** `check` is optional, `true` by default. Then the broker
asks GitHub 10 minutes after its start, and then once a day, whether a
newer release of nodkey is out, and sends you a silent notice when one
is ([section 13](#a-new-version-of-nodkey)). For this, the broker host
needs outbound HTTPS to `api.github.com`. The check uses the proxy of
`HTTPS_PROXY`, as the calls to Telegram do
([section 8](#8-the-systemd-unit)). GitHub sees the address of the
broker host, or of its proxy, and the version of nodkey
([THREAT-MODEL.md T34](../THREAT-MODEL.md#6-threats-and-answers)). If
the broker host cannot reach GitHub, or GitHub should not see this, set
`check = false`. Otherwise the journal gets a line about the failed
check every hour.

**`[client.NAME]`.** One section for each agent machine, with the pin of
its TLS key. Make that key on the agent machine first
([section 11](#the-key-and-the-config-of-the-client)). The name shows in
each message as `machine:`.

**`[store.NAME]`.** `type` is `bws` with a `token_file`, or `bw` with a
`password_file`. `program` is the absolute path of the program.

**`[secret.NAME]`.** The name is what the client asks for, and what the
message shows. `store` names a store section, and `id` is the UUID of
the item in that store. `clients` lists the clients that may ask for
it.

**`[key.NAME]`.** `file` is the credential with the SSH key. `clients`
lists the clients that may use it. `hosts` lists the names in the
broker's `known_hosts` that it may log in to; without `hosts`, it may
log in to every host there.

**The rule of each secret and key, `ask`**
([DESIGN.md section 8](../DESIGN.md#8-rules-and-grants)):

- `"always"`: ask for each request. The buttons are **Approve once** and
  **Deny**.
- `"window"`: ask, and also offer **Approve N min**, where N is the
  `window`: 1 minute to 8 hours. A tap on it allows the same client the
  same secret, or the same key, host and remote user, for N minutes.
- `"never"`: do not ask. This is an open door for that one secret or key
  ([DESIGN.md section 12](../DESIGN.md#12-decision-3-unattended-runs)).
  It needs exactly one client, and a key needs `hosts`. It can have
  `hours`, `max_per_day` and `notify`.

Two more examples. A secret in the `bw` store, and a nightly job on a
machine of its own (`backup-1`) that gets its secret without a tap:

```toml
[secret.npm-token]
store = "vault"
id = "11111111-1111-1111-1111-111111111111"   # a login item; nodkey hands out its password
clients = ["laptop"]
ask = "always"

[client.backup-1]
pin = "sha256:...base64..."

[secret.backup-token]
store = "backup-job"
id = "22222222-2222-2222-2222-222222222222"
clients = ["backup-1"]
ask = "never"
hours = "03:00-03:20"     # local time of the broker; outside these hours, it asks
max_per_day = 1           # more uses in a day ask again
notify = true             # the default: a silent notice for each use
```

The broker is strict, so that a typo never turns a rule off. An unknown
key, a key in upper case, or a key that is not below the header of its
own section stops the start. The error names the line or the key, never
a value. Paths are absolute. Only `${CREDENTIALS_DIRECTORY}/` and `~/` at
the start of a path are expanded.

Write the file as root, and make it owned by root, so that only root can
change it:

```sh
chown root:root /etc/nodkey/broker.toml
chmod 0644 /etc/nodkey/broker.toml
```

The file holds no secret, but it lists your secret names, hosts and item
IDs. To hide it from other users, use group `nodkey` and mode `0640`
instead.

## 8. The systemd unit

Copy the example unit
[contrib/systemd/nodkey.service](../contrib/systemd/nodkey.service), of
the same version as your nodkey, to `/etc/systemd/system/nodkey.service`.
Never copy it through an agent machine: whoever can change the unit can
run a program as root on the broker host. After a build from the source,
the unit is in your copy of the repository. The release tarball does not
hold it. Take it from the tag of your version in the repository, such as
[v0.1.0](https://github.com/code6x/nodkey/blob/refs/tags/v0.1.0/contrib/systemd/nodkey.service),
on the broker host or on the trusted machine. For 0.1.0, on the broker
host:

```sh
curl -fL -o /etc/systemd/system/nodkey.service https://raw.githubusercontent.com/code6x/nodkey/refs/tags/v0.1.0/contrib/systemd/nodkey.service
```

Then change it to fit your setup:

- Keep one `LoadCredentialEncrypted=` line for each credential that you
  made, and remove the others. systemd does not start the unit when one
  of these files is missing.
- Change the paths if yours are different.
- If the broker must reach Telegram through a proxy, set it as the
  comments in the unit say. Never use a proxy that inspects TLS: it sees
  the bot token. The check for a newer release
  ([section 7](#7-the-config-file), `[updates]`) uses the same proxy to
  reach `api.github.com`.

Check the unit. No output means no problem:

```sh
systemd-analyze verify /etc/systemd/system/nodkey.service
```

systemd older than 253 warns that it does not know `MemoryZSwapMax=`.
You can ignore that: `MemorySwapMax=0` alone is enough.

What the settings do:

| setting | what it does |
|---|---|
| `Wants=` and `After=network-online.target` | Start the broker after the network is up. |
| `Type=exec` | systemd sees a failure when the program cannot start. |
| `User=nodkey`, `Group=nodkey` | Run as the user of the broker, not as root. |
| `ExecStart=` | The program and the config file. |
| `LoadCredentialEncrypted=NAME:FILE` | Decrypt one credential at each start. The broker reads it as `${CREDENTIALS_DIRECTORY}/NAME`. |
| `StateDirectory=nodkey nodkey/stores`, `StateDirectoryMode=0700` | Make `/var/lib/nodkey` (the audit log) and `/var/lib/nodkey/stores` (the home directories of the stores), owned by `nodkey`, with mode `0700`. The broker refuses a store directory with another mode or owner. |
| `UMask=0077` | New files of the broker and of the store programs are private. |
| `Restart=on-failure`, `RestartSec=5s` | Start the broker again 5 seconds after a crash or an error. |
| `RestartPreventExitStatus=64 76 77` | Do not start it again after wrong usage (64), a polling conflict at Telegram (76) or a bot token that Telegram refuses (77). Only a person can fix these. |
| `TimeoutStopSec=90s`, `KillMode=control-group` | The broker stops in at most 80 seconds. After 90 seconds, systemd kills it and every process of the unit, also a store program that left its process group. |
| `LimitCORE=1` | No core dumps. A crashed `bws` or `bw` starts no core handler that could copy its token into the journal ([section 9](#core-dumps)). The broker sets this limit itself too. |
| `MemoryMax=1G` | A memory limit for the broker and its store programs. |
| `MemorySwapMax=0`, `MemoryZSwapMax=0` | The memory of the broker, with keys and tokens, never goes to swap. |
| `LogRateLimitIntervalSec=0` | journald never drops a line of the broker. The anchors of the audit log are in these lines ([section 12](#12-check-the-audit-log)). The broker limits its own lines. |
| `Environment=`, `EnvironmentFile=` (as comments) | An optional proxy for Telegram, and for the check for a newer release at GitHub. A proxy with a password goes into a file that only root can read. |
| `NoNewPrivileges=yes` and the lines after it | The sandbox: no new privileges or capabilities, a read-only system, no access to `/home`, a private `/tmp`, no devices, kernel settings, other namespaces or raw sockets, and only the system calls of a normal service. |
| `WantedBy=multi-user.target` | `systemctl enable` starts the broker at boot. |

What the unit leaves out on purpose:

- `MemoryDenyWriteExecute=yes`: bw runs on Node.js, which needs memory
  that is writable and executable.
- `PrivateUsers=yes`: the credentials and the config, owned by root,
  would look owned by `nobody`, and the broker would refuse them.
- `PrivateNetwork=`, `IPAddressDeny=` and the like: the broker must
  reach Telegram, and GitHub for the check for a newer release, and
  `bws` and `bw` must reach Bitwarden. Do not add them.

After `systemctl daemon-reload`, `systemd-analyze security nodkey` shows
how much the sandbox limits the broker.

## 9. Account and host safety

### The approver's Telegram account

Anyone who can use your Telegram account can approve
([THREAT-MODEL.md T7](../THREAT-MODEL.md#6-threats-and-answers)).

- **Never log in to the approving Telegram account on a machine where an
  agent runs**: no Telegram Desktop, and no Telegram Web in a browser
  there. The agent could tap **Approve** itself, or copy the session and
  use it from anywhere. The same holds for any other way to control the
  phone from that machine, such as `adb` or KDE Connect.
- In Telegram, open **Settings → Devices**, and end every session that
  you do not need. Better: use an account that is logged in only on the
  phone.
- Turn on two-step verification (**Settings → Privacy and Security**),
  and a passcode for the app.

### The Bitwarden accounts that can read the secrets

Anyone who can use a Bitwarden account that can read the secrets can
read them in Bitwarden's own apps, with no tap and no entry in the audit
log ([THREAT-MODEL.md T32](../THREAT-MODEL.md#6-threats-and-answers)).
For `bws`, these are at least the owners and admins of the organization,
and the members with access to the project. For `bw`, it is at least the
separate account. T32 has the full lists.

- **Never log in to such an account on a machine where an agent runs**:
  no web app in a browser, no browser extension, no desktop app and no
  CLI there. The agent could read the secrets itself, or record the
  master password when you type it. The same holds for a phone that the
  agent machine can control, such as through `adb` or KDE Connect.
- Do not save the master password, the API key or the key of the
  two-step login of these accounts in a password manager that is open on
  an agent machine, such as your main Bitwarden account. With them, the
  agent could log in to the account from anywhere.
- If your main Bitwarden account is logged in on an agent machine, it
  must not be able to read the secrets. Make the organization for Secrets
  Manager with a separate account, and do not add your main account to it
  ([section 5](#bws-bitwarden-secrets-manager)).
- After each change to the organization, check who is an owner or an
  admin, and who is on the People tab of the project, its secrets and its
  machine accounts.
- Turn on two-step login for these accounts, with an authenticator app or
  a security key
  ([Bitwarden's guide](https://bitwarden.com/help/setup-two-step-login/)).
  A code by email does not help if you read that email on an agent
  machine.

### Swap and hibernation

The memory of the broker holds the keys, the tokens and, for a moment,
the secret values. Swap and hibernation write memory to the disk, where
a copy of the disk can give them.

- Check for swap with `swapon --show`. Use no swap, or encrypted swap,
  such as a swap device in `/etc/crypttab` with a new random key at each
  boot. zram keeps its swap in memory, which is fine. The unit also
  keeps the memory of the broker out of swap (`MemorySwapMax=0`).
- Turn off hibernation:

  ```sh
  systemctl mask hibernate.target hybrid-sleep.target suspend-then-hibernate.target
  ```

### Core dumps

A core dump of a crashed `bws` or `bw` would hold its environment, with
the token or the session key. The unit sets `LimitCORE=1`, and the
broker sets the same limit for itself and its store programs. With a
limit of exactly 1, the kernel writes no core file and starts no core
handler, but only when `kernel.core_pattern` is a pipe (`|`) or a file
name. The newer socket form (`@`) passes the dump to a program whatever
the limit
([DESIGN.md section 16](../DESIGN.md#16-implementation-rules)).

```sh
sysctl kernel.core_pattern
```

- `kernel.core_pattern = |/usr/lib/systemd/systemd-coredump ...` (the
  default of systemd), `|/usr/share/apport/apport ...` or `core`: good.
- A value that starts with `@`: change it. Find the file that sets it
  with `grep -rs core_pattern /etc/sysctl.conf /etc/sysctl.d
  /usr/lib/sysctl.d /run/sysctl.d`. Remove that line, or override it
  with a file such as `/etc/sysctl.d/90-nodkey-core-pattern.conf` that
  sets a pipe or the plain `kernel.core_pattern = core`. Then run
  `sysctl --system`, and check again.

### A firewall for the broker port

Only the agent machines should reach the broker port. Any other machine
can at least make the broker do TLS handshakes
([THREAT-MODEL.md T28](../THREAT-MODEL.md#6-threats-and-answers)). An
example with nftables, with the agent machines `192.0.2.21` and
`192.0.2.22`. It only adds rules for port 7743, and leaves your other
rules as they are. Save it as `/etc/nodkey/firewall.nft`:

```text
# The first two lines remove the old version of this table, if there is one.
table inet nodkey
delete table inet nodkey

table inet nodkey {
  set agents {
    type ipv4_addr
    elements = { 192.0.2.21, 192.0.2.22 }
  }
  chain input {
    type filter hook input priority filter; policy accept;
    tcp dport 7743 ip saddr @agents accept
    tcp dport 7743 drop
  }
}
```

Load it with `nft -f /etc/nodkey/firewall.nft`. To load it at boot,
for example with the `nftables` service of Debian and Ubuntu, add the
line `include "/etc/nodkey/firewall.nft"` at the end of
`/etc/nftables.conf`. With ufw, allow the port for each agent machine
only, for example
`ufw allow proto tcp from 192.0.2.21 to any port 7743`.

### The journal

The broker writes a hash of each audit entry to its log, which systemd
keeps in the journal. These anchors find changes to the audit log
([section 12](#12-check-the-audit-log)), but only while the journal
keeps them.

- Keep the journal on the disk: the directory `/var/log/journal` must
  exist, or set `Storage=persistent` in `/etc/systemd/journald.conf`.
- Keep it long enough. journald removes old entries when it uses more
  than `SystemMaxUse=`: by default 10 % of the file system, at most
  4 GiB.
- Better: send the journal to another machine, for example with
  `systemd-journal-upload`. Then not even root on the broker host can
  change the copies later.

## 10. Start the broker

Write the config file first ([section 7](#7-the-config-file)), with at
least one client ([section 11](#11-a-client-on-the-agent-machine)).
Then:

```sh
systemctl daemon-reload
systemctl enable --now nodkey
journalctl -u nodkey -f
```

A good start looks like this. Here, the `time=` at the start of each
line, and some lines, are left out:

```text
level=INFO msg="nodkey broker: starting" version=0.1.0 config=/etc/nodkey/broker.toml
level=INFO msg="nodkey broker: the config and the files it names passed their checks"
level=INFO msg="nodkey broker: core dumps are off: the soft and the hard limit of core dumps are 1, and the process is not dumpable"
level=INFO msg="nodkey broker: the TLS key is loaded" pin=sha256:Q2b9...
level=INFO msg="nodkey broker: an SSH key is loaded and can sign" key=deploy fingerprint=SHA256:3SMw...
level=INFO msg="nodkey broker: the audit log is open" path=/var/lib/nodkey/audit.jsonl
level=INFO msg="nodkey broker: a store started" store=main
level=INFO msg="nodkey broker: the listen address is open; nothing reads from it yet" address=192.0.2.10:7743
audit anchor 1:8318bd865cb1923faea0c3a1837f636ad1f8781898606701949120d612c85da0
level=INFO msg="nodkey broker: the approver runs: it polls Telegram for the answers"
level=INFO msg="nodkey broker: listening; the broker is ready" address=192.0.2.10:7743
```

The lines `audit anchor SEQ:HASH` are the anchors of the audit log
([section 12](#12-check-the-audit-log)). When something is wrong, the
broker logs why ([section 14](#14-when-something-does-not-work)).

A restart of the broker ends all grants, and denies the requests that
wait for a tap. The config is read only at the start, so restart the
broker after each change of the config or of `known_hosts`:

```sh
systemctl restart nodkey
```

## 11. A client on the agent machine

### The key and the config of the client

On the agent machine, as the user who runs the agent, make the TLS key
of the client:

```sh
install -d -m 0700 ~/.config/nodkey
nodkey keygen --out ~/.config/nodkey/client.key
```

`nodkey keygen` prints the pin of the new key. On the broker host, add a
section for the client to `/etc/nodkey/broker.toml`, add its name to the
`clients` lists of the secrets and keys that it may use, and restart the
broker:

```toml
[client.laptop]
pin = "sha256:Yf3c...base64..."
```

The agent can copy this key. With it, someone can only ask, like the
agent (THREAT-MODEL.md T11). They get what this client gets: what needs
a tap still needs your tap, but a grant or a "never ask" rule of this
client works for them too. To block a stolen key, remove its pin from
the broker config, and restart the broker. Each machine needs its own
key: the broker refuses two clients with the same pin.

Write the client config, `~/.config/nodkey/client.toml`, with the
address of the broker and the pin of the broker's key
([section 3](#the-tls-key-of-the-broker)):

```toml
broker = "192.0.2.10:7743"
broker_pin = "sha256:Q2b9...base64..."
tls_key = "~/.config/nodkey/client.key"
```

The pin is the only trust of the client in the broker, so other users
must not be able to change the file. The client refuses it then:

```sh
chmod 0600 ~/.config/nodkey/client.toml
```

### The first request

```sh
nodkey run --secret GH_TOKEN=github-token --reason "test the setup" -- \
  sh -c 'echo "the command got ${#GH_TOKEN} characters"'
```

The client prints `nodkey: waiting for approval (request 7qd2)`. On the
phone, a message comes from your bot with the same short code. Check the
lines with ✅: they come from the broker. The lines below
"claimed by the agent" come from the agent machine. Tap **Approve once**.
The command prints how many characters the secret has, never the value.

nodkey never prints a value. The value goes only into the environment of
the one command. For real work, the agent runs, for example:

```sh
nodkey run --secret GH_TOKEN=github-token --reason "publish the release the user asked for" \
  -- gh release create v1.2.0
```

Tell the agent about it, for example in its instructions for a project:
"For a command that needs a secret, use
`nodkey run --secret VAR=NAME --reason TEXT -- COMMAND`." Some variable
names are refused, because programs print or run their values
([DESIGN.md section 5](../DESIGN.md#variable-names-that-the-broker-refuses)).

`nodkey run` exits with the exit code of the command. When nodkey
itself stops, its last line on stderr is
`nodkey: <reason> (exit <code>)`: 77 when the request was denied or
expired, 69 when the broker cannot be reached, 64 for wrong usage
([DESIGN.md section 15](../DESIGN.md#15-commands-and-exit-codes)).

### SSH: nodkey ssh-agent

`nodkey ssh-agent` is an SSH agent without keys. For each login, it asks
the broker for a signature. Start it in a terminal of its own. It
prints the short code of each request there:

```sh
nodkey ssh-agent
```

Or run it as a user service. Save this as
`~/.config/systemd/user/nodkey-ssh-agent.service`:

```ini
[Unit]
Description=nodkey ssh-agent: SSH logins with the keys of the broker

[Service]
ExecStart=/usr/local/bin/nodkey ssh-agent

[Install]
WantedBy=default.target
```

Then run `systemctl --user enable --now nodkey-ssh-agent`. The short
codes are in `journalctl --user -u nodkey-ssh-agent -f`.

In the shell of the agent, for example in `~/.profile`:

```sh
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/nodkey/agent.sock"
```

Check it:

```sh
ssh-add -l                # the keys that this client may use, with their names
ssh deploy@web-1 true     # a message comes for the login
```

`ssh`, `git` and Ansible work through it with no changes. Some things to
know:

- ssh must send `session-bind@openssh.com`: OpenSSH 8.9 or newer.
  Paramiko and Go's own SSH client do not, so the broker refuses them.
  For Ansible, use its default `ssh` connection.
- The broker refuses host certificates. If a host offers one, ssh may
  use it. Then allow only plain host keys for that host in
  `~/.ssh/config`:

  ```text
  Host web-1 web-2
      HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256
  ```

- The message shows `NODKEY_REASON` from the environment of `ssh` as the
  reason.
- An approved login is one SSH session. That session can stay open, and
  ssh can share it with later commands (`ControlMaster`,
  `ControlPersist`), without a new tap.

### Many hosts at once: nodkey ssh-grant

One Ansible run logs in to each host, so it needs one tap for each host.
`nodkey ssh-grant` asks once for a list of hosts. The key needs
`ask = "window"`:

```sh
nodkey ssh-grant --key deploy --user deploy --host web-1 --host web-2 \
  --for 15m --reason "apply the nginx fix"
ansible-playbook site.yml
```

The message lists the key, the remote user, each host and the end of
the grants. After **Approve**, logins as `deploy` to these hosts need no
tap until that time. Other hosts and users still ask. A **Deny** for
the key ends its grants at once.

### A job that runs later: nodkey preapprove

A timer or a job runner cannot tap a button at 03:00. Ask for the grant
when the job is planned, while you are awake. Then the job gets what it
needs without a tap, inside the time you approved, and the grant ends by
itself. First turn it on for the secret or key, in `broker.toml`. It is
off by default:

```toml
[secret.backup-token]
# ...
ask = "always"
preapprove = true
```

Then, when the job is planned (for example in the script that sets up
tomorrow's job):

```sh
nodkey preapprove --secret backup-token \
  --from 2026-10-28T03:00 --until 2026-10-28T04:00 --uses 1 \
  --reason "job nightly-backup"
```

The message shows the secret, the uses and the time, in the broker's
local time. After **Approve**, the command prints the ID of the grant and
ends. The message keeps one **Revoke** button. At 03:00 the job runs
`nodkey run` as usual, and gets the secret without a tap. Each use sends
a silent notice to the notice chat. When the uses are gone, or at 04:00,
the grant is gone, and the message shows how and when it ended. If the
job did not run, or ran late, and a use is left at 04:00, a silent notice
says `not used`. To end the grant earlier, tap **Revoke** on the phone.
The client can also cancel it, for example when the job is removed:

```sh
nodkey preapprove --cancel ID
```

Things to know:

- Anything on that machine can use the grant inside its time, not only
  the job. Keep the span short and the uses few. If something else uses
  the grant up, the real job fails, and that shows it.
- If you use a token file (`--grant-token`), keep it in a private folder,
  such as the home folder of the job user. Do not put it in a shared
  folder like `/tmp`: another user there could delete the file or block
  its update.
- For a key, use `--key`, `--user` and `--host` as for `nodkey ssh-grant`.
  **Each SSH connection takes one use.** A tool that opens many
  connections, such as Ansible, needs more uses, or `ControlPersist` in
  the ssh config so that the connections are shared.
- A time without an offset is read in the broker's local time. Near the
  change to summer time, write the offset
  (`2026-10-28T03:00:00+02:00`). The broker refuses a local time that the
  clock skips or shows twice.
- The `window` of the rule does not cap a grant. The limits are in
  `[preapprove]`: how far ahead it may start (`max_ahead`, 7 days), how
  long it is open (`max_open`, 8 hours), how many uses (`max_uses`, 10)
  and how many grants a machine holds (`max_grants`, 5).
- A broker restart drops all grants. The job then asks as usual. When
  the broker stops, one notice lists the grants that it dropped: the ID,
  the machine, the secret or key, and the uses left. A **Deny** for the
  same secret or key ends the grant, also before its start; the message
  of the grant says so.

## 12. Check the audit log

The broker writes each request and each decision to the audit log,
`/var/lib/nodkey/audit.jsonl`. Each entry holds the hash of the entry
before it, and the broker writes the hash of each entry to the journal:
`audit anchor SEQ:HASH`
([DESIGN.md section 9](../DESIGN.md#9-audit-log)). Check the log with
every anchor since the log began, as root:

```sh
journalctl -u nodkey -o cat | nodkey audit verify /var/lib/nodkey/audit.jsonl --anchors -
```

A good log gives:

```text
ok: 1234 entries (torn lines: 0)
anchors: 1234 checked, all match; the newest is entry 1234
last entry: 1234:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

It exits with 0 when the log passed, and with 65 when it found a
problem. Then it prints the line number, never the text of the line. A
changed entry shows as an anchor that does not match. A log that someone
cut shows as an anchor whose entry is missing.

- Entries after the newest anchor are not proven.
- If you moved the log away, the broker starts a new log at entry 1.
  Check the new log only with the anchors since then, such as
  `journalctl -u nodkey -o cat --since "2026-10-20 10:00"`, and keep
  the old file.
- `jq` shows the entries in short, for example the last ten:

  ```sh
  tail -n 10 /var/lib/nodkey/audit.jsonl |
    jq -c '{seq, event, client, secrets, key, hosts, answer, cause, code} | with_entries(select(.value != null))'
  ```

## 13. Upgrades and key changes

### A new version of nodkey

The broker tells you when a newer release is out, unless `[updates]`
says `check = false` ([section 7](#7-the-config-file)). It asks GitHub 10
minutes after its start, and then once a day. For each newer release, it
writes a line in its journal, and sends you one silent notice in each
start:

```text
ℹ️ nodkey: A newer release is out: nodkey 0.3.0. The broker runs nodkey 0.2.0. To update the broker, run as root on the broker host: nodkey update. Then restart it: systemctl restart nodkey. The restart ends all grants. Update the agent machines too: sudo nodkey update. Release notes: https://github.com/code6x/nodkey/releases/tag/v0.3.0
```

If the check or the notice fails, the journal says why, and the broker
tries again after 1 hour. On a terminal, `nodkey version` says it too, on
each machine. A build from the source never asks.

1. Read the release notes.
2. On the broker host, as root, set `VERSION` to the new version, such
   as `0.2.0`, and install it:

   ```sh
   VERSION=0.2.0
   nodkey update --version "$VERSION"
   ```

   It runs the installer that is built into the installed nodkey, and
   checks the new release in the same way ([section 2](#2-get-nodkey)).
   It also takes an older version. nodkey 0.1.0 has no `nodkey update`:
   update it with the installer of section 2, with
   `--version "$VERSION"`. Or get the new version by hand, check it, and
   install it with
   `install -o root -g root -m 0755 nodkey /usr/local/bin/nodkey`.
3. Get the example unit of the same version from its tag, as in
   [section 8](#8-the-systemd-unit), but save it as `nodkey.service`, not
   over your unit. After a build from the source, use the unit in your
   copy of the repository instead. Compare it with your unit, and take
   over the changes:

   ```sh
   curl -fL -o nodkey.service "https://raw.githubusercontent.com/code6x/nodkey/refs/tags/v$VERSION/contrib/systemd/nodkey.service"
   diff -u /etc/systemd/system/nodkey.service nodkey.service
   ```
4. Restart the broker:

   ```sh
   systemctl daemon-reload
   systemctl restart nodkey
   journalctl -u nodkey -n 30
   ```

5. On each agent machine, in a root shell as in
   [section 2](#2-get-nodkey), install the same version, such as with
   `nodkey update --version 0.2.0`. Then restart `nodkey ssh-agent`
   there.

A restart ends all grants. Rarely, right after a restart, Telegram
reports a polling conflict, and the broker stops with exit code 76: a
poll of the old broker was still on its way
([DESIGN.md section 7](../DESIGN.md#telegram-details)). If no other
program uses the token, start the broker again with
`systemctl start nodkey`.

Until every machine runs the new version, nodkey tells you. Each client
sends its version to the broker, and the broker sends its own back.
nodkey 0.1 sends no version.

- On the agent machine, `nodkey run`, `nodkey ssh-grant` and
  `nodkey ssh-agent` print a warning on stderr. It says which side is
  older, and what to do there:

  ```text
  nodkey: warning: the broker runs nodkey 0.2.0, which is older than nodkey 0.3.0 on this machine; to update the broker, run "nodkey update" as root on the broker host
  ```

  With a broker of nodkey 0.1, the warning says that the broker runs an
  older nodkey that does not send its version, and points to this
  section: nodkey 0.1 has no `nodkey update`.
- The broker writes a line in its journal, once in each start for each
  client that runs another version, or that sends none. It also sends
  you one silent notice for such a client:

  ```text
  ℹ️ nodkey: The client laptop says that it runs nodkey 0.2.0, which is older than nodkey 0.3.0 on the broker. To update it, run there: sudo nodkey update
  ```

  For a client of nodkey 0.1, the notice points to this section too. If
  the notice cannot go out, such as while Telegram cannot be reached
  after a power cut, the journal says so, and the next request of that
  client a minute later or more tries again. Rarely, the same notice
  comes more than once.

The steps above make both go away. A machine that still runs another
version works as before, unless the two versions do not understand each
other's requests: then the request fails, for example with
`the answer of the broker is not valid`. The version of a client is only
what the client says: the broker allows and denies nothing because of
it. A build from the source, such as one with the version `dev` or a
commit, gets no warning and no notice.

### New versions of bws and bw

Install them in the same way as the first time
([section 5](#where-bws-and-bw-come-from)): from the official release,
checked, owned by root. Then check that the next request for a secret
works. The login of bw stays in the home directory of the store.

### A new TLS key for the broker

Make a new key and its credential as in
[section 3](#the-tls-key-of-the-broker), and restart the broker. Then
put the new pin into `broker_pin` on each client, and restart
`nodkey ssh-agent` there. Until then, the clients refuse the broker.

### A new key for a client, or a client that must go

To give a client a new key, make it with `nodkey keygen` in a new file,
put its pin into the `[client.NAME]` section, restart the broker, and
change `tls_key` in the client config. Remove the old key file. Restart
`nodkey ssh-agent` too: it reads the config and the key only when it
starts.

To block a client, for example after a strange request, remove its
`[client.NAME]` section, and its name from every `clients` list, and
restart the broker. Its key no longer works.

### A new bot token

Make a new token with `/revoke` in BotFather. If BotFather says the bot
is invalid, send its user name with the `@`, for example
`@my_nodkey_bot`, or use `/mybots`, choose the bot, then **API Token**,
then **Revoke current token**. Then make the credential again as in
[section 4](#4-the-telegram-bot), and restart the broker. Do this
at once when the token may have leaked. When Telegram no longer takes
the old token, the broker stops with exit code 77, and systemd does not
start it again until you do.

### A new bws token or bw master password

For bws, make a new access token for the machine account, make the
credential again, restart the broker, and then revoke the old token in
Secrets Manager.

For bw, change the master password of the separate account, make the
credential again, and restart the broker. If bw is logged out after the
change, log in again as in [section 5](#bw-a-separate-bitwarden-account),
step 5.

### A new SSH key

Make a new key and its credential as in
[section 6](#the-ssh-keys-of-the-broker), with a new name, such as
`ssh-deploy-2`. Add its public key to the target hosts. Change `file`
of the `[key.NAME]` section and the `LoadCredentialEncrypted=` line of
the unit. Then run `systemctl daemon-reload`, so that systemd reads the
changed unit, and restart the broker. At the end, remove the old public
key from the target hosts.

## 14. When something does not work

The broker logs each problem in the journal: `journalctl -u nodkey`. An
error names the file, the section or the key, never a secret value.

| what you see | what it means, and what to do |
|---|---|
| The broker stopped with exit code 76, and an alert says that another program reads the updates of the bot. | Another program polls with the bot token, or a webhook is set. The token may be stolen. Make a new token ([section 13](#a-new-bot-token)), then start the broker. Right after a restart, see [section 13](#a-new-version-of-nodkey). |
| The broker stopped with exit code 77. | Telegram does not take the bot token, such as after `/revoke`. Make the credential with the new token, then start the broker. |
| The installer or `nodkey update` ends with `nothing was installed (exit 1)`. | The last line says which step failed. After a network error, try again later. After a failed SHA-256, attestation or version check, do not install that release in another way: someone may have changed it. Report it ([SECURITY.md](../SECURITY.md)). |
| The installer says that `group or others can write to` a directory or a file, or that a path `is owned by user`. | As root, the installer runs programs from these places, so only root may be able to change them, and each directory above them. Fix the owner or the mode, such as with `chmod go-w /usr/local/bin`, or choose another place with `--bin-dir`, `--gh` or `TMPDIR`. A Debian system that was set up long ago may still have `/usr/local/bin` writable by the group `staff`. |
| systemd does not start the broker: `systemctl status nodkey` shows `status=243/CREDENTIALS`. | systemd cannot decrypt a credential, so the broker does not run, and nothing is handed out. Check that each file of a `LoadCredentialEncrypted=` line is there, and was made with that name. After a firmware update or a change of the Secure Boot settings, the TPM2 chip may refuse credentials that are bound to PCR 7 ([section 3](#encrypted-credentials)). If you did not update the firmware or change Secure Boot, find out why first: someone may have changed how the machine starts. Then make each credential again, as in [section 13](#13-upgrades-and-key-changes): a new TLS key (and its pin on each client), the bot token, a new `bws` token, the `bw` master password, and new SSH keys. |
| The journal says that the bot may not send to this chat. | You did not tap **Start** in the chat with the bot, or you blocked it. |
| The client prints `nodkey: warning: ...` with the versions of this machine and the broker. | They run different versions of nodkey. Update the older side, as the line says ([section 13](#a-new-version-of-nodkey)). Requests can fail until then, for example with `the answer of the broker is not valid`. |
| A silent notice says that a client runs another version of nodkey, or sent no version. | Update nodkey on the older side, as the notice says ([section 13](#a-new-version-of-nodkey)). The broker sends one such notice for each client in each start, rarely more than one, and the journal has a line about it. |
| `a store could not start` | The broker runs without that store, denies requests for its secrets, and tries again with each request. The error names the store and the step. For bw: check the login ([section 5](#bw-a-separate-bitwarden-account)). |
| The broker refuses a file: the owner, the mode, or a directory that group or others can write to. | The broker checks every file that it reads, and every directory on the way ([DESIGN.md section 14](../DESIGN.md#14-configuration)). Fix the owner or the mode that the error names. |
| `cannot listen on ...` | The `listen` address is not on the broker host yet, such as before the VPN is up. systemd tries again every 5 seconds. |
| The client says `the broker's TLS key is not the pinned key` (exit 69). | `broker_pin` in the client config is not the pin of the broker's key. The broker logs its pin at each start. |
| The client says that the broker `refused the TLS connection` (exit 69). | The broker does not know the key of this client. The broker logs `refused a client key that no [client.*] section pins`, with the pin. Put the pin into a `[client.NAME]` section, and restart the broker. |
| The client says `cannot connect to the broker` (exit 69). | Check the address in the client config, the firewall, and that the broker runs. |
| The client says `the broker answered 503 Service Unavailable` (exit 69). | The broker could not finish the request: Telegram, a store or the audit log failed, or the broker was starting or stopping. Its journal says why. |
| The client says `denied` or `denied by a limit of the broker` (exit 77) at once, without a message. | A check or a limit denied the request: a secret or key that this client may not use, or the pause of 60 seconds after a Deny. The journal of the broker says which. |
| ssh asks for a password, or says `agent refused operation`. | `nodkey ssh-agent` prints why. Check `SSH_AUTH_SOCK`, that the host is in the broker's `known_hosts`, and that ssh does not use a host certificate ([section 11](#ssh-nodkey-ssh-agent)). |
