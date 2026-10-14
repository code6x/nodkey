# nodkey design

Status: accepted for version 1 on 2026-10-12.

nodkey lets an AI coding agent use a secret or an SSH key only after a
person approves that one request on a phone.

The keys and the access to the secret stores live on a trusted machine. The
agent never holds them. When the agent needs one, it asks. The person gets a
Telegram message with buttons. Nothing happens until the person taps
**Approve**. No answer means **no**.

This file says how version 1 works. [THREAT-MODEL.md](THREAT-MODEL.md) says
what it protects against, and what it does not.

## 1. Words

| word | meaning |
|---|---|
| agent | An AI coding agent, for example Claude Code. |
| agent machine | The machine where the agent runs. We do not trust it. The agent may be effectively root there, for example through the `docker` group. |
| broker | The `nodkey broker` daemon. It runs on a trusted, always-on machine that is not the agent machine. It holds the SSH keys and the secret-store access. |
| client | The `nodkey` command on the agent machine: `nodkey run`, `nodkey ssh-agent` and `nodkey ssh-grant`. |
| approver | The person who taps the buttons. Version 1 has exactly one. |
| request | One ask: a set of secrets for one command, one SSH signature, or one SSH pre-approval. |
| grant | A short permission. It comes from an "Approve N min" tap. |
| rule | The setting per secret or key: always ask, ask with a time window, or never ask. |
| store | Where secret values live: Bitwarden Secrets Manager (`bws`) or the Bitwarden Password Manager (`bw`). |
| verified | Shown in a message and checked by the broker. The agent cannot fake it. |
| claimed | Shown in a message but sent by the client. The agent can write anything there. |

## 2. Goals

1. The agent can use a secret or an SSH key only when the approver tapped
   **Approve** for that request, or a grant or a rule the approver wrote
   allows it.
2. An SSH private key never leaves the broker. The broker signs; the client
   only forwards.
3. nodkey never prints a secret value. A value goes only into the
   environment of the one command that asked for it.
4. Each message shows what the broker checked (verified) apart from what the
   agent says (claimed).
5. Plain `ssh`, `git` and Ansible work through `nodkey ssh-agent` with no
   changes, only `SSH_AUTH_SOCK`.
6. Every request and every decision goes into an audit log. The broker only
   appends to it. Each entry holds the hash of the entry before it.
7. Fail closed. An error, a timeout, a restart or an unclear answer all mean
   **deny**.

## 3. Not in version 1

- ntfy, a passkey web page, a phone app.
- An HTTP proxy that injects credentials.
- An MCP server.
- Windows and macOS. Version 1 is Linux only.
- Signing anything that is not an SSH login (for example git commit signing).
- SSH agent forwarding.
- SSH clients that do not send `session-bind@openssh.com` (OpenSSH older
  than 8.9, Paramiko, Go's own SSH client).
- SSH certificates, for hosts and for users. The broker's `known_hosts`
  holds plain host keys, and the broker signs only with plain keys.
- Keys in hardware (TPM or YubiKey) through an upstream agent.
- Filtering secrets out of the command's output.
- More than one approver.

Each of these can become a GitHub issue later.

## 4. The parts

```
 agent machine (not trusted)                trusted machine
┌────────────────────────────┐            ┌──────────────────────────────┐
│ agent                       │            │ nodkey broker                │
│  ├─ nodkey run ... -- cmd   │  mTLS      │  ├─ SSH private keys (memory) │
│  └─ ssh / git / ansible     │ ─────────▶ │  ├─ runs bws / bw             │
│       │ SSH_AUTH_SOCK       │            │  ├─ audit log                 │
│       ▼                     │            │  └─ Telegram long polling ───┼──▶ Telegram ──▶ phone
│  nodkey ssh-agent           │            │                              │
└────────────────────────────┘            └──────────────────────────────┘
```

One static Go binary holds all parts. The subcommand picks the role:

| command | runs on | job |
|---|---|---|
| `nodkey broker` | trusted machine | The daemon. |
| `nodkey run` | agent machine | Get secrets, then start one command with them. |
| `nodkey ssh-agent` | agent machine | Serve an SSH agent socket. Send each signature request to the broker. |
| `nodkey ssh-grant` | agent machine | Ask once for SSH logins to a list of hosts for N minutes (see [decision 4](#13-decision-4-ssh-approval-scope)). |
| `nodkey keygen` | both | Make a TLS key pair for the broker or a client. Print its pin. |
| `nodkey audit verify` | trusted machine | Check the hash chain of an audit log. |
| `nodkey version` | both | Print the version. |

Inside the broker, the approver and the stores sit behind small Go
interfaces. Version 1 has one approver (Telegram) and two stores (`bws`,
`bw`). Others, such as ntfy or `sops`, can be added later without changing
the rest.

Dependencies are kept small on purpose: the Go standard library,
`golang.org/x/crypto` (`ssh`, `ssh/agent`) and one TOML parser. The
Telegram client is our own small HTTP code. We do not link the Bitwarden
SDK; its license is not a standard open-source license. We run the `bws`
and `bw` programs instead.

## 5. Flow: secrets for one command

```
nodkey run --secret GH_TOKEN=github-token \
           --reason "publish the release the user asked for" \
           -- gh release create v1.2.0
```

1. The client reads its config, then connects to the broker over mutual TLS
   (see [section 10](#10-decision-1-how-client-and-broker-connect)).
2. The client sends: the secret names, the environment variable names, the
   command line, the working directory, the local user name and the reason.
   The reason comes from `--reason`, or else from the `NODKEY_REASON`
   environment variable. Section 10 limits their size.
3. The broker checks that the client is known (its TLS key is pinned in the
   broker config), that each name exists in the broker config, that this
   client may use it, and that each variable name matches
   `[A-Z_][A-Z0-9_]{0,63}`. If any check fails, the answer is **deny**. No
   message is sent for a name the client may not use. (The client checks
   the variable names too, but only to give a quick error. The broker does
   not trust the client's checks.)
4. The broker checks the rules and grants. If a grant or a "never ask" rule
   covers every name, it skips to step 6.
5. Otherwise the broker sends one Telegram message for the whole request and
   waits. See [section 7](#7-approval-messages). The client prints
   `nodkey: waiting for approval (request 7qd2)` to stderr, so a person at
   the terminal can match it with the message on the phone.
6. On approval, the broker first writes the decision to the audit log and
   syncs it to disk. Then it gets each value from its store and sends the
   values back over the same TLS connection.
7. The client adds `GH_TOKEN=<value>` to its own environment and replaces
   itself with the command (`execve`). The command's exit code is the exit
   code of `nodkey run`.
8. On deny, timeout or error, the client prints one line to stderr, without
   any value, and exits with code 77.

There is no command that prints a secret. This is on purpose: the agent
should never see the value in its own output.

The broker fetches a value only after approval, and fetches it again on
every request. Version 1 keeps no cache of values.

## 6. Flow: an SSH login

```
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/nodkey/agent.sock
NODKEY_REASON="apply the nginx fix" ansible-playbook site.yml
```

1. `ssh` connects to `web-1` and finishes the key exchange.
2. OpenSSH 8.9 and newer then sends the agent a `session-bind@openssh.com`
   message. It holds the server's host key, the session identifier, the
   server's signature over the session identifier, and an `is_forwarding`
   flag. The client keeps these for that agent connection.
3. `ssh` asks the agent for its keys. The client asks the broker. The broker
   returns the public keys this client may use.
4. The server accepts one key. `ssh` asks the agent to sign the
   authentication request.
5. The client sends the broker: the key, the data to sign, the flags, the
   session-bind messages of this connection, and some claimed context: the
   command lines of the `ssh` process and of at most 3 of its parent
   processes (from `/proc`), and `NODKEY_REASON` from the environment of
   the `ssh` process, if set. Section 10 limits their size.
6. The broker checks, and denies on any failure:
   - The data is an SSH authentication request (RFC 4252 section 7): the
     message `SSH_MSG_USERAUTH_REQUEST`, the service `ssh-connection`, the
     method `publickey` or `publickey-hostbound-v00@openssh.com`, and the
     flag that says the request has a signature. Nothing may come after
     the last field. The public key in the data is the key asked for, and
     it is the broker's plain key, not a certificate.
   - The sign flags fit the key. For RSA, the flags ask for SHA-256 or
     SHA-512, and the algorithm in the data is the same one. An RSA
     signature with SHA-1 (no flag) is refused, and so are unknown flags.
     Ed25519 and ECDSA keys take no flags.
   - The remote user name in the data matches
     `[A-Za-z0-9._][A-Za-z0-9._-]{0,31}`.
   - There is exactly one session-bind, and its `is_forwarding` flag is
     0. Version 1 does not support agent forwarding.
   - The session identifier is 32, 48 or 64 bytes long: the output of
     SHA-256, SHA-384 or SHA-512. So a key exchange with SHA-1 is refused.
     OpenSSH 8.9 and newer do not use one by default.
   - The session identifier in the data is the one in the session-bind. For
     `publickey-hostbound-v00@openssh.com`, the host key in the data is the
     one in the session-bind too.
   - The host key is a plain Ed25519, ECDSA or RSA key, in the form that
     OpenSSH writes. A host certificate is refused. If a host offers one,
     ssh may use it; then set `HostKeyAlgorithms` in the ssh config on the
     agent machine to plain key types only.
   - The host key is in the broker's own `known_hosts` file. That gives the
     host name in the message.
   - If the key's section has a `hosts` list, the host is in that list.
     Without a list, the key may log in to any host in `known_hosts`.
   - The host key's signature over the session identifier is valid, and
     its algorithm matches the host key's type. For RSA, it must use
     SHA-256 or SHA-512.
   - A session-bind and the data to sign are each at most 8 KiB. Valid
     ones have less than 5 KiB, even with RSA keys of 16384 bits.
7. The broker checks the rules and grants for (client, key, host key,
   remote user), and asks the approver if needed.
8. On approval, the broker writes and syncs the decision, then signs and
   returns the signature. It signs exactly the data that it checked, with
   the checked algorithm (for RSA, the hash that the flags ask for). It
   checks the new signature before it returns it.

The checks and the signing are in `internal/sshauth`. Signing takes the
result of the checks, not raw bytes, so the broker cannot sign data that
it did not check.

Why this matters: the signature covers the session identifier. The session
identifier only exists in that one session with that one host. So an
approved signature for `web-1` cannot log in to `db-1`, and it cannot be
used again in a later session. The agent cannot lie about the target host,
because the broker checks the host key against its own list, not a list on
the agent machine. The remote user name is inside the signed data, so the
signature works only for that user.

Two limits, said plainly:

- **One login can last long.** An approved session can stay open, and
  OpenSSH can share it with later commands (`ControlMaster` and
  `ControlPersist`). Ansible keeps each connection open for 60 seconds after
  its last use. A hostile agent can keep a connection open much longer and
  use it without new taps. The approval is for a session, not for one
  command.
- **The forwarding flag comes from the agent machine.** Refusing forwarded
  binds stops honest mistakes. It does not stop a hostile agent, which can
  send any flag it wants.

**Time limit.** `sshd` drops a login that does not finish within
`LoginGraceTime` (120 seconds by default). So SSH requests expire after
90 seconds by default.

**Ansible** opens one SSH connection per host, with up to 5 hosts at the
same time by default (`forks`). One run makes at least one signature per
host. See [decision 4](#13-decision-4-ssh-approval-scope).

## 7. Approval messages

### What a message shows

```
🔐 SSH login · request k3f9
✅ machine: laptop
✅ key: deploy
✅ host: web-1 (host key SHA256:pX2c…)
✅ remote user: deploy
— claimed by the agent —
command: ssh deploy@web-1 ← ansible-playbook site.yml
reason: apply the nginx fix
expires 14:03:10 (90 s)
[ Approve once ] [ Approve 15 min ] [ Deny ]
```

```
🔑 Secrets · request 7qd2
✅ machine: laptop
✅ secrets: github-token
— claimed by the agent —
as: GH_TOKEN
command: gh release create v1.2.0
in: /home/dev/src/app
reason: publish the release the user asked for
expires 14:05:40 (120 s)
[ Approve once ] [ Approve 15 min ] [ Deny ]
```

An SSH grant (`nodkey ssh-grant`, section 13) shows every host and the
time when its grants end. It has only "Approve" (until that time) and
"Deny":

```
🔐 SSH grant · request m4k2
✅ machine: laptop
✅ key: deploy
✅ hosts: web-1, web-2
✅ remote user: deploy
✅ grants end: 14:20:00 (15 min)
— claimed by the agent —
reason: apply the nginx fix
expires 14:07:00 (120 s)
[ Approve ] [ Deny ]
```

A notice of a "never ask" use (section 12) has no buttons and no expiry.
It goes to the notice chat without a sound:

```
🔔 Secrets · request 7qd2
allowed by a "never ask" rule, without a tap
✅ machine: ci
✅ secrets: backup-token
— claimed by the agent —
command: restic backup /srv
```

- The host key shows only `SHA256:` and its first 4 characters. The
  broker has checked the key against its own `known_hosts`, and the host
  name is what the person reads.
- Times are in the broker's local time zone. "(120 s)" is the time that
  was left when the message was made.
- A claimed field that is empty has no line. Without any claimed field,
  the "claimed by the agent" line is left out too.
- The `message` of the `request` audit entry (section 9) is the text that
  the person sees, as above, with the buttons as its last line.

The verified part holds only text from the broker's own config and from
checked data: client and secret names from the config, the host name from
the broker's `known_hosts`, and the remote user name after the strict check
in section 6.

Rules for the claimed part, because the agent writes it:

- One line per field. Newlines and other control characters become spaces.
  So do the other space characters, and symbols that draw nothing, such as
  U+2800 BRAILLE PATTERN BLANK. Runs of spaces become one space. So long
  runs of blank symbols are not possible. A long line still wraps on the
  phone, and the agent can choose its text so that a fake line starts a
  new row. The `<code>` font and the place under the "claimed by the
  agent" line still mark that text as claimed.
- Unicode direction marks (for example U+202E) and other invisible
  formatting characters are removed.
- At most 4 combining marks (such as accents) are kept in a row. Real text
  needs few: Vietnamese uses 2, Thai 3. Many stacked marks can draw over
  the lines above and below. A field never starts with a combining mark,
  because the mark would draw on the text before the field.
- Values that look like secrets are masked before they are shown or
  logged. Each becomes `***`. The broker does the masking, because it does
  not trust the client. The next section lists what is masked.
- A field longer than 64 KiB is not shown at all: the message shows
  `[hidden: too long]`. For a command line, all the arguments count
  together. The broker never cuts a field before it masks it, because a
  secret that was cut may no longer look like a secret.
- A command line shows the program and at most 8 arguments. Each field is
  cut to a fixed length, with `…` at the end.
- A Telegram message holds at most 4096 characters. So the Telegram code
  cuts each claimed field again, to 200 UTF-16 code units for `as`, 1000
  for `command`, 300 for `in` and 500 for `reason`. This keeps room for
  the result line that replaces the expiry when the request ends. If the
  message is still too long, it halves these lengths, down to 62 for
  `command`. It never cuts a verified line: the person must see every
  name they approve. If the verified lines alone do not fit, the message
  is not sent, and the request is denied.
- All text is HTML-escaped and put inside `<code>`. Link previews are turned
  off, so a URL from the agent does not become a preview card. The
  Telegram code does two steps again, as a cheap extra check: it masks
  each claimed field (`claim.Mask`, section "What is masked"), and makes
  it one clean line (`claim.Line`: the rules above for control and
  invisible characters, spaces and combining marks). It does not apply
  the other rules, such as the 8 arguments of a command line: those stay
  the caller's job. It escapes all text it puts into a message, also the
  verified text.
- The claimed part always comes after the verified part, under the
  "claimed by the agent" line. So the agent cannot make text that looks
  like a verified line.
- The approval core checks that each claimed field is one clean line, as
  the rules above make it, and denies the request if a field is not. So
  text that missed the cleaning cannot reach a message or the audit log.
  The core cannot check the masking.

### What is masked

Masking is best effort. It finds the common forms below, and nothing
else. A secret in another form is shown as it is. Masking is there to
catch accidents. A hostile agent can always get a secret past it, for
example by encoding the secret. So the claimed part stays a claim: read
it, and deny a request that looks strange (THREAT-MODEL.md T2 and T15).

These rules apply to the command line and to the other claimed fields:

- **Options with a secret name.** The value of an option whose name
  contains `pass`, `pwd`, `token`, `secret`, `auth`, `credential`, `cookie`
  or `key`, for example `--password`, `--api-key` or `-token`. The value
  is hidden as the next word and attached (`--password=VALUE`). If the
  hidden word is itself such an option, the word after it is hidden too.
  A few of these options take no value, for example `--password-stdin` and
  `--ask-become-pass`; the word after them stays.
- **`-p`.** The attached value (`-pVALUE`, as `mysql` uses). The word after
  a bare `-p`, unless that word starts with `-`. So the port in
  `ssh -p 2222` is hidden too. The word after `-pw` is hidden too, as
  PuTTY tools use it for the password. An option in quotes counts too, as
  in `"-p" VALUE` in a script.
- **User and password.** The part after `:` in the word after `-u`, `-U`,
  `--user` and `--proxy-user`, as in `curl -u deploy:VALUE`.
- **Options of some programs**, whose names do not say "secret":
  - `curl`: `-u`, `-U`, `-E` and `--cert` (the part after `:`), and `-b`.
    Grouped letters count too, as in `curl -su deploy:VALUE` or
    `curl -sudeploy:VALUE`.
  - `gh secret set`: `--body` and `-b`.
  - `kubectl`: `--from-literal` (the part after `=`).
  - `vault kv put`, `vault kv patch` and `vault write`: each `KEY=VALUE`
    argument (the part after `=`).
  - `openssl`: `-k` and `-K`, and the arguments of `openssl passwd`.
  - `ssh-keygen`: `-N` and `-P`, also grouped, as in `ssh-keygen -pP VALUE`.
  - `redis-cli`: `-a`.
  - `ldapsearch` and the other OpenLDAP tools: `-w`. `ldappasswd` also
    `-a` and `-s`. Grouped letters count too, as in `ldapsearch -xw VALUE`.
  - `sqlcmd` and `bcp`: `-P`.
  - `mysqladmin`: the word after `password` and `old-password`.
  - `putty`, `plink`, `pscp` and `psftp`: `-pw`.

  The program may come after another word, as in `sudo redis-cli -a VALUE`
  or `ssh web-1 redis-cli -a VALUE`. The rules of all these programs count
  together. So a word that only looks like a program, such as the host in
  `redis-cli -h vault -a VALUE`, does not end the rules of `redis-cli`.
  When it is not clear whether a separator ends the command, the rules
  stay. That may hide more, but never less:
  - In a command line, nothing ends the rules. The shell has already split
    the words, so a `;` in an argument is text, as in
    `curl -H "Cookie: a=1;" -E client.pem:VALUE`.
  - In a script or other free text, a shell separator ends the rules: `;`,
    `&&`, `||`, `|`, `&` or `|&` as a word of its own, or `;` at the end of
    a word. It counts only outside quotes and when it is not escaped. So
    in `sqlcmd -Q "SELECT 1; SELECT 2" -P VALUE` or after `\;` (as in
    `find -exec`), the rules stay. If a quote in the text is never closed,
    no separator counts, because the quotes may be apostrophes, as in
    "don't". After a command substitution (`$(` or a backtick) or a
    process substitution (`<(` or `>(`), no separator counts either. The
    `;` in `curl -d $(date; hostname) -E client.pem:VALUE` ends a command
    inside the substitution, not `curl`.
  - A separator glued to the next word, as in `cd /tmp&&redis-cli -a VALUE`,
    does not end the rules before it, but the program after it counts too.
    A `&` inside a word may be part of a URL, as in
    `curl "https://example.com/?a=1&b=2" -E client.pem:VALUE`.
- **Keys and values.** The value after a key whose name contains
  `password`, `passwd`, `pwd`, `pass`, `token`, `secret`, `apikey`,
  `api_key`, `api-key`, `access_key`, `auth`, `credential`, `private_key`
  or `cookie`, in any case and inside longer names such as `GITHUB_TOKEN`
  or `db.password`. Key and value may be joined by `=`, `:=`, `?=`, `+=`,
  `=>` or `: `, or by a quoted key and `:` as in JSON. The quotes may be
  escaped, as in `{\"password\":\"VALUE\"}`.
  - The name may hold brackets, as in `user[password]=VALUE`,
    `params[:password] = "VALUE"` or `$config['password'] = 'VALUE'`.
  - `name:VALUE` without a space counts only when a part of the name is a
    secret word or ends in one, as in `X-Api-Key:VALUE`,
    `Cookie:sid=VALUE` or `accessToken:VALUE`, and the value does not
    start with `/`. So `auth-1:/srv/app` and
    `https://auth.example.com:8443` stay readable.
  - The value is a whole shell word. So `password=''VALUE` and
    `password='it'\''s VALUE'` hide all of the value.
  - A key inside quotes takes the value up to the closing quote, as in
    `"PASSWORD=two words"`.
  - An object or a list is hidden whole, as in
    `{"auth": {"user": "dev", "pass": "VALUE"}}`.
  - An authentication scheme takes the next word too, as in
    `HTTP_AUTHORIZATION=Bearer VALUE`. After `Authorization:` and
    `Proxy-Authorization:`, any scheme counts.
  - A Cookie value goes on over `; `, as in `Cookie: a=1; b=2`.
- **Whole values of arguments.** In a command line, an argument that is a
  header with a secret name, as in `curl -H "Cookie: a=1; b=2"` or
  `curl -H X-Api-Key:VALUE`, or that is `KEY=VALUE` with a secret name, as
  in `env "DB_PASSWORD=two words"`: all of its value is hidden.
- **Bearer and Basic.** The word after `Bearer` and `Basic`.
- **Passwords in URLs.** The password in `USER:PASSWORD@HOST`, with or
  without a scheme such as `https://`. It goes on to the last `@` of the
  word, so it may hold `@`, `:`, `/`, `?` and `#`. Not hidden: a port with
  an `@` later in the path, as in `https://example.com:8443/?to=dev@example.com`,
  and an image digest, as in `app:1.2@sha256:...`.
- **PEM blocks**, between the `BEGIN` and `END` lines.
- **Known token shapes:** `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`,
  `github_pat_`, `glpat-`, `xoxa-`, `xoxb-`, `xoxp-`, `xoxr-`, `sk-`, AWS
  key IDs (`AKIA`, `ASIA`) and JWTs.
- **Long random-looking words**: 20 or more letters, digits, `_`, `+`,
  `-` and `/`, where letters and digits are mixed and the characters vary
  enough. This finds most generated keys in hex, base62, base64 and
  base64url. A path such as `/srv/k8s/manifests/app` stays readable. A
  random part of a path or URL is hidden on its own, as the key in
  `https://hooks.example.com/services/T0ABCDEFG/B0HIJKLMN/VALUE`. We
  measured random keys on 2026-10-14. Of keys with 32 characters, about 1
  in 100 in base64 stays visible, fewer in base62, and almost none in hex.
  Of keys with 20 characters, up to 7 in 100 stay visible. For hex, base62
  and base64url keys, this is the same alone and inside a URL path.
  Standard base64 inside a long URL path is the exception: the `/` of the
  key splits it into shorter parts, and up to 14 in 100 keys of 32
  characters stay visible. Such keys are rare in URLs, because `/` ends a
  part of the path.

Masking also hides some text that is not secret, for example the port in
`ssh -p 2222`, a full git commit ID (40 hex characters), and a value that
only looks like a key. That is the safe side.

Not masked, for example:

- A secret as a plain word, without a key or an option before it:
  `htpasswd -b users.txt dev VALUE`, a `.netrc` line `password VALUE`, or
  a value sent in with `echo VALUE |`.
- An option of a program that is not in the list above, when its name does
  not say "secret", for example `az keyvault secret set --value VALUE`.
- A key whose name holds none of the words above, for example
  `ENCRYPTION_KEY=VALUE` or `SESSION=VALUE`, unless the value looks
  random.
- A key inside `${…}`, as in `${PASSWORD}=VALUE`. The shell expands
  `${PASSWORD}`, and `=VALUE` is plain text after it.
- A secret with fewer than 20 characters that is not in one of the forms
  above, even if it looks random.

### How an answer is bound to one request

- Each request gets a new random ID: 16 bytes from `crypto/rand`, written
  as base64url. The short code in the message ("k3f9") is only for people.
  It is 4 random characters from `23456789abcdefghjkmnpqrstuvwxyz` (no 0,
  1, i, l or o, which people mix up). No two requests in progress share an
  ID or a short code.
- The button data is `o:<id>` (once), `w:<id>` (window) or `d:<id>` (deny).
  That fits Telegram's 64-byte limit. The Telegram code reads it strictly:
  exactly one of these three prefixes and an ID of 22 base64url
  characters in its one canonical form. Anything else does not count.
- The broker names a message by its chat ID and its message number
  (`CHAT:MESSAGE`). So the same message number in another chat is another
  message.
- The broker accepts a button press only when **all** of these are true:
  - it comes from the configured Telegram user ID;
  - it comes from the private chat with that user, on a message there
    (a button of an inline message has no chat, so it never counts);
  - it is on the message the broker sent for that request (same message
    ID);
  - that message is as the broker sent it: nobody edited it, and it has
    the same buttons (see below);
  - the ID belongs to a request that is still waiting;
  - the request has not expired;
  - the action is allowed for that request.
- The first valid answer wins. Taking a request out of the waiting list and
  deciding it is one step under one lock, so two taps cannot both count.
- The Telegram code checks the user, the chat, and that the message is
  as the broker sent it. Then the approval core checks the user, the
  message, the request, the time and the button again. A tap that fails
  a check changes nothing: the request still waits, or it had already
  ended.
- The broker never edits a message while its request waits. With the bot
  token, someone else can: for example, they can make the message show a
  harmless secret name and keep the buttons, or swap the labels of the
  buttons. So a tap never counts when Telegram says that its message was
  edited (`edit_date`), or when the message's buttons differ from the
  ones the broker sent, in their labels or their data. If the request of
  that message may still wait, the broker writes a `foreign_tap` entry
  with cause `edited_message`, logs an alert, and sends an alert message:
  the bot token may be stolen. It sends at most one such alert in 10
  minutes. No tap on that message counts any more, so the request
  expires. When it ends, the broker writes the whole message again, with
  the result. Otherwise the broker itself edited the message after its
  request ended, or the message is from before a restart. Then the tap
  is only a late tap (below), and no alert goes out. This check needs
  the buttons that Telegram sends with each tap (`reply_markup` of the
  message). Without them, no tap would count, and the broker would
  alert: that fails closed. The manual test of issue #17 checks that
  Telegram sends them.
- A request is answered once. The broker then forgets its ID. A second tap,
  a late tap, or a tap on a message from before a restart finds no waiting
  request. The broker refuses it and updates that message:
  - If this broker sent the message, it keeps its result. The second tap
    of a double tap must not change "approved" to "expired". If the
    result is not on the message yet, the update that ends the request
    puts it there. If it is, the broker sends it again, in case that
    update failed.
  - Otherwise, such as for a message from before a restart, the broker
    only removes the buttons (`editMessageReplyMarkup` with an empty
    keyboard). The text stays: it may show a result from before the
    restart, such as "approved", and the tap may be one that Telegram
    sends again after the restart, because the old broker could not
    confirm it. Replacing that text would hide that a secret may already
    be out.
- A tap can also come too early: while the broker still waits for Telegram
  to confirm that it sent the message. The broker refuses that tap too,
  but it leaves the message as it is, so the person can tap again. It
  changes a message only when no request with that ID is in progress.
  The phone shows "Not ready yet. Tap again in a moment."
- The broker answers every button press (`answerCallbackQuery`), so the
  phone never shows a spinning button. The phone shows a short text, such
  as "Approved." or "This request has ended.", except for a tap from
  another user, which gets no text.
- When a request ends, the broker edits the message: it removes the buttons
  (by sending an empty keyboard, not by leaving it out; Telegram probably
  removes them also when the keyboard is left out, but that is not sure,
  and the manual test of issue #17 checks it), and the result replaces
  the expiry line: "👍 approved once by you at 14:02:41",
  "👍 approved for 15 min by you at 14:02:41", "👍 approved by you at
  14:05:12, until 14:20:00" (an SSH grant), "⛔ denied by you at
  14:02:41", "⌛ expired — denied", "⛔ cancelled by the client" or
  "⛔ denied: the broker stopped taking answers".
- Typed replies never count. Only buttons do. Every tap that does not
  count is written to the audit log as a `foreign_tap` entry, with a
  fixed `cause`: `other_user`, `other_chat`, `inline_message`,
  `no_message`, `bad_data`, `edited_message`, `unknown_request` (a late
  or second tap, or one from before a restart), `expired`,
  `wrong_message` (such as a copy of the message), `not_allowed` (a
  button that the request does not offer) or `refused`. So a forged
  button can be told from a person's second tap. The Telegram code logs
  each one, and passes it to the broker, which writes the entry. A tap
  that came too early is not written: it is the person's own tap, and
  they can tap again.
- The Telegram code logs and reports at most 20 such taps in a minute.
  It counts the others and logs how many it dropped, also when no later
  tap comes. So someone with the bot token cannot fill the journal or the
  disk with forged buttons. Every tap still gets its answer.
- If the client hangs up while waiting (for example `ssh` was killed), the
  request is cancelled. (Section 10 has one exception, which the client
  never uses: HTTP pipelining.)

### Telegram details

- Long polling with `getUpdates` (timeout 50 s, at most 10 updates in one
  answer). There is no webhook, so the broker needs no open port to the
  internet. The next call confirms the updates of the call before, so
  Telegram forgets them. After a crash, Telegram sends the updates that
  were not confirmed again; their taps find no waiting request.
- Only `callback_query` updates are read. Text sent to the bot is ignored.
- If `getUpdates` fails with a conflict (another program polls with the same
  token, or a webhook was set), the broker logs an alert and sends a
  message: the bot token may be stolen. Then the Telegram code stops
  taking answers, so the polling stops for good (below), and the broker
  writes an `error` entry with code `poll_conflict` to the audit log. A
  conflict says that someone else may read the answers, so the broker
  does not go on.
- If Telegram refuses `getUpdates` in another way, with a code from 400
  to 499 other than 409 and 429, such as 401 for a token that was
  revoked, the polling stops for good too.
- The bot token is in the request URL, and Go's HTTP errors include the
  URL. So no error and no log line of the Telegram code holds Go's error
  text: an error names the Bot API method and a fixed reason, and at most
  a number such as Telegram's error code. Telegram's own description of
  an error is never shown either, because it can quote the message text.
- The Telegram code speaks only HTTP/1.1, because Go's HTTP/2 debug
  output (`GODEBUG=http2debug`) prints the path of each request, with the
  token. It follows no redirect. Each try of a call takes at most 15
  seconds (65 seconds for `getUpdates`), and an answer is at most 4 MiB.
- It uses a proxy from the environment, as Go reads it: `HTTPS_PROXY` or
  `https_proxy`, except for the hosts in `NO_PROXY` or `no_proxy`. A
  normal proxy sees only the host name, because the URL with the token is
  inside TLS. A proxy that inspects TLS, with its own certificate
  authority in the system's store, sees the token, and it can fake the
  answers of Telegram, so also taps. Do not use such a proxy for the
  broker. At start, the broker logs one line when it uses a proxy: the
  proxy's host, never a user name or a password from the setting.
- The token file must hold one bot token: the bot's ID in digits, `:`,
  and 30 to 64 letters, digits, `_` or `-`. Space around it, such as a
  newline at the end, is fine.
- If Telegram cannot be reached, a message cannot be sent or answered. The
  Telegram code may try to send a message again until its request
  expires. If it cannot send it, the request is denied. A request whose
  message was sent waits until it expires, then it is denied.
  - A call is tried at most 5 times. Before the next try, it waits 0.5
    seconds, then twice as long each time, at most 8 seconds, but never
    less than Telegram asks for with code 429 (`retry_after`). It takes
    that wait as 1 second to 10 minutes; a 429 without the JSON of the
    Bot API, such as the page of a proxy, counts as 1 second. It never
    waits past the end of the request. An alert waits at most 30
    seconds in all, also when the broker gives it no time limit.
  - A network error can come after Telegram sent the message. Then the
    message can come twice. Only the message that Telegram confirmed
    counts; a tap on the other one is refused.
  - The polling does not stop for such errors. It waits 1 second, then
    twice as long each time, at most 30 seconds, but never less than
    Telegram asks for. So it never calls again at once.
- If the polling stops for good, no answer can come any more. Then every
  request that waits for the person is denied at once, and so is every new
  request that needs a message. A message or a notice that is still being
  sent stops too, and no new notice goes out, so a "never ask" use that
  needs a notice is denied as well. Grants still work, and so do "never
  ask" rules with `notify = false`. The broker should stop then.
- Messages about "never ask" uses can go to a second chat
  (`notice_chat_id`), so the approval chat stays for approvals only.
  They are silent (`disable_notification`). At most 20 notices go out in
  any 60 seconds, for all clients together, because Telegram allows
  about 20 messages per minute in a group. A notice that could not be
  sent counts too. A use that would need one more notice is denied, but
  not as for the limit per client in section 8: it is denied as when a
  notice cannot be sent (cause `error`, code `approver_failed`), and it
  still counts for `max_per_day`, because the core counts a use before
  it sends the notice. So with `max_per_day = 1`, a burst of notices of
  other clients can use up the one use of a night; then the next use asks
  the person.

## 8. Rules and grants

Each secret and each key has a rule:

| `ask` | meaning | buttons |
|---|---|---|
| `always` | Ask for every request. | Approve once · Deny |
| `window` | Ask; the approver may also allow the next N minutes. | Approve once · Approve N min · Deny |
| `never` | Do not ask. See [decision 3](#12-decision-3-unattended-runs). | none |

Any other `ask` value, also an empty one, denies the request. So does a
`never` rule for a key without `hosts`, and a `never` rule that does not
name exactly one client. The config check refuses all of these (section
14); the approval core denies them again.

- A grant covers (client, secret) for secrets, and (client, key, host key,
  remote user) for SSH keys, until it ends. The host is matched by its host
  key, not by its name. A host can have several host keys, one of each key
  type, and a grant from a login covers only the host key of that login. A
  grant for `deploy@web-1` does not allow `root@web-1`. Using a grant does
  not make it longer. A second "Approve N min" for the same scope keeps the
  end that is later.
- A request with several secrets needs one approval for all of them. The
  "Approve N min" button shows only if every secret in the request has the
  `window` rule. N is then the shortest window among them, in whole
  minutes, rounded down, so a grant is never longer than a window. The tap
  makes one grant for each secret.
- A grant ends N minutes after the tap. It starts only once the `decision`
  entry of the tap is on disk (section 9). If that entry cannot be written,
  the grant never starts.
- A Deny ends the grants of that client for each secret or key of the
  denied request, at once. For a key, that is every grant of the client
  for the key: at every host key and for every remote user, as wide as the
  pause below. A Deny says that something looks wrong, so it ends more
  than the one host. It also stops a grant from an earlier tap that has
  not started yet. Grants of other clients stay.
- A window is 1 minute to 8 hours. A shorter one would give grants of 0
  whole minutes, so the rule would quietly act like `always`.
- Grants live only in memory. A broker restart removes them all.
- A secret or key that is not in the broker config does not exist for the
  client. The client sends names, never store IDs. So the agent cannot ask
  for any other item in the store.

**Limits per client**, so a broken or hostile agent cannot flood the phone:

- At most 5 messages waiting for an answer, and at most 6 new messages in
  any 60 seconds. A message counts as waiting from just before it is sent
  until its request ends. A message that could not be sent still counts
  toward the 6.
- Other requests wait in a queue of up to 10, without a message, until
  both limits allow a new message. The oldest request leaves first. A
  request leaves the queue only if at least 30 seconds of its time are
  left. As soon as less is left, it is denied, so the person never gets a
  message they cannot answer in time. If the queue is full, the request is
  denied at once. So is a request that would have to wait, but has less
  than 30 seconds left.
- After the person taps Deny, new requests from the same client for any
  secret or key of the denied request are denied without a message, for 60
  seconds from the tap. Requests for them that already wait in the queue
  are denied too, because their messages would come during the pause.
  Messages that are already shown stay. A request that expired starts no
  pause.
- Requests covered by a grant or a "never ask" rule do not count, and no
  limit or pause applies to them. A request that is covered only in part
  needs a message, so it counts.
- One limit applies to them: at most 6 notices of "never ask" uses in any
  60 seconds, for all secrets and keys of the client together. A use that
  would need one more notice is denied, without a notice, and does not
  count for `max_per_day`. Without this limit, one client could fill the
  phone with notices and use up Telegram's limits for the chat, so that
  messages for other clients could not be sent. A "never ask" rule with
  `notify = false` sends no notice and has no such limit. The Telegram
  code also sends at most 20 notices in any 60 seconds for all clients
  together (section 7).

## 9. Audit log

- One file, JSON Lines: one entry per line. The broker opens it once, at
  start, with `O_WRONLY`, `O_APPEND`, `O_CREAT`, `O_NOFOLLOW` and
  `O_CLOEXEC`, and mode `0600` for a new file. (It also uses `O_NONBLOCK`
  for the open, so a FIFO put there cannot make it wait.) It never changes
  or removes a line. Each entry is written with one `write` call and then
  synced to disk. When the file is new, the broker syncs its directory
  too.
- The broker checks the open file again: a regular file, owned by the
  broker user, with only read and write for the owner. The directories on
  the way must pass the checks of section 14.
- The broker takes an exclusive lock (`flock`) on the open file, without
  waiting. If another process holds it, such as a second broker, the
  broker does not start. So only one broker writes to one log.
- Every entry has `seq`, `time` (UTC), `event` and `prev`, in this order,
  and then the fields of its event (below). `seq` is 1 in the first entry
  and counts up by one. `prev` is the SHA-256 of the previous line, as
  written and without its newline, in hex. The first entry has 64 zeros.
- A line is at most 64 KiB. The broker refuses a longer entry, so the
  request is denied.
- Events: `broker_started`, `request`, `decision`, `grant_used`,
  `secret_sent`, `signed`, `denied`, `foreign_tap`, `error`,
  `log_recovered`, `broker_stopped`. Each event about a request holds the
  request ID, the client, the names, the verified host if any, and the
  claimed command and reason (masked as in section 7).
- The `request` entry holds the exact message text the approver saw. The
  `decision` entry holds the Telegram user ID that answered.
- No entry ever holds a secret value, a signature, or the data that was
  signed. `cause` and `code` hold fixed codes, never an error message,
  because an error message can hold text from a store program or from the
  client.
- If an entry cannot be written, the request is denied. Nothing is approved
  without a record. The `decision` entry is on disk before the broker
  fetches a value or signs. But a `decision` entry does not show that
  anything was handed out: the request is still denied if a later step
  fails, even the sync or the journal write of that entry itself. Only a
  `secret_sent` or `signed` entry shows that the broker handed something
  out.
- After a failed write or sync, every later entry fails too, so every
  request is denied until the broker starts again. The file may now end in
  a torn line, and the broker records it at the next start (below).
- After an entry is on disk, the broker writes `audit anchor SEQ:HASH` to
  stderr: the entry's number and the hash of its line. It never writes the
  content of an entry there. If this write fails, it counts as a failed
  write too.
- `nodkey audit verify FILE` checks every line and prints the first
  problem. With anchors (`--anchor SEQ:HASH`, or `--anchors FILE` for a
  copy of the journal), it also checks that each entry `SEQ` has that
  hash. The rules are below. The output and the exit codes are in section
  15.

The fields of each event, after `seq`, `time`, `event` and `prev`:

| event | fields |
|---|---|
| `broker_started` | `version` |
| `broker_stopped` | none |
| `request` | the request fields; `message`: the exact text the approver saw, if a message was sent |
| `decision` | the request fields; `user_id`: the Telegram user that answered; `answer`: `approve_once`, `approve_window` or `deny`; `window_minutes` for `approve_window` |
| `grant_used` | the request fields; `via`: `grant` or `never_rule` |
| `secret_sent`, `signed` | the request fields |
| `denied` | the request fields; `cause`: `approver`, `expired`, `cancelled`, `not_allowed`, `limit` or `error` |
| `foreign_tap` | `user_id`, `chat_id`, `message_id`, `data`: the button data, at most 64 bytes, and `cause`: why it did not count (section 7) |
| `error` | the request fields, if the failure is about one request; `code`: `store_failed`, `sign_failed`, `approver_failed` or `poll_conflict` |
| `log_recovered` | `torn_length` and `torn_sha256`: the length and the SHA-256 of the torn line |

The request fields are `request_id`, `client`, `kind` (`secrets`,
`ssh_login` or `ssh_grant`), `secrets`, `key`, `hosts`, `host_key` (a
SHA256 fingerprint), `remote_user`, and the claimed `command` and
`reason`.

For each request, the broker writes its entries in this order. First
`request`. Then one of these: `decision` (and `denied` with cause
`approver` after a Deny); `grant_used`; or `denied` (with an `error` entry
before it when the cause is `error`). After an approval, `secret_sent` or
`signed` follows once the broker has handed something out. When grants and
a "never ask" rule allow one request together, it gets two `grant_used`
entries, one for each, and each lists the secrets it covered.

The broker writes the `request` entry only when the request has ended,
together with the entries after it, because it holds the exact text of
the message. So a request that was still waiting when the broker stopped,
such as in a crash or a power cut, leaves no entry. Nothing was handed out
for it.

These fields hold text that the client, or someone else, chose:

- `command` and `reason`: from the client, cleaned and masked as in
  section 7.
- `message`: the broker builds it, but its claimed part comes from the
  client, cleaned and masked as in section 7.
- `remote_user`: the client chooses it, and the broker checks it against
  the pattern of section 6.
- `data` of `foreign_tap`: from whoever made the button. With the bot
  token, anyone can (THREAT-MODEL.md T6).

The other fields hold only checked names. A name that failed the broker's
checks is left out, so a denied request may have no names.

**What the chain can and cannot show.** The chain finds accidental damage
and simple edits. It does not stop a careful attacker who can write the
file: they can change a line and compute all the later hashes again.
Removing entries from the end of the file also leaves a chain that passes.
To catch both, a copy of the hashes must live somewhere the attacker cannot
reach. So the broker also writes each entry's number and hash to its
normal log (stderr, which systemd puts in the journal), as described above.
The broker's user cannot change the journal, so this already helps on one
machine, if the journal is kept on disk (`Storage=persistent`) long enough.
Better, send the journal to another machine; then not even root on the
broker host can change the copies later.

An anchor proves that the entries up to it have not changed since the
broker wrote that anchor. It proves nothing about a change made before
that: after a restart, the broker builds on the log as it finds it, so its
new anchors cover a change that was made while it was stopped. So the
newest anchor alone is not enough. Check with every anchor since the log
began:

```
journalctl -u nodkey -o cat | nodkey audit verify /var/lib/nodkey/audit.jsonl --anchors -
```

Then a changed entry shows as an anchor that does not match. A cut log
shows as an anchor whose entry is not there, or, if the broker wrote more
entries after the cut, as two anchors for one entry that differ. Entries
after the newest anchor are not proven.

What the anchors do not find:

- An entry that someone appends while the broker is stopped, with the
  right `seq` and `prev`. At the next start, the broker takes it as the
  last entry, and every later anchor covers it. Only the missing
  `audit anchor` line for that entry shows it.
- On Linux, `chattr +a` on the file stops anyone except root from changing
  old lines. It does not stop the broker user from appending. For example,
  it can append a `log_recovered` entry that names the last real entry as
  a torn line. The broker does not see this at the next start. The anchor
  of that last entry then does not match, so check with every anchor.
- If a person moves the log away, the broker starts a new log at entry 1.
  The journal then has anchors of both logs, and they differ. Use only the
  anchors since the new log began, and keep the old file.

THREAT-MODEL.md T17 lists the risk that remains.

**A torn last line.** A power cut can leave a half-written last line: bytes
after the last newline. At start, the broker reads only the end of the
file, not the whole file. If it finds a torn line, it appends, with one
`write` call, a newline and a `log_recovered` entry. That entry has the
`seq` and `prev` that the torn line would have had: its `prev` is the hash
of the last complete line. So the torn line is not part of the chain. But
the entry records the length and SHA-256 of the torn bytes, so a change to
the torn line, or its removal, is still found. The broker also sends an
alert message. So the broker still starts on its own after a power cut.

The broker does not start, and a person must look, when the end of the
file has more than 64 KiB without a newline, or when the last complete line
is not a valid entry or is longer than 64 KiB. Something other than a
power cut changed the file then. A second power cut during the recovery
write itself can also leave the file like this. Then run
`nodkey audit verify` to see where. Keep the file, move it away, and let
the broker start a new log. Check the new log only with the anchors since
it began.

**What `nodkey audit verify` checks.** It reads the file line by line, so
the file can be large.

- Each line is at most 64 KiB, and the last line ends in a newline.
- Objects and arrays nest at most 16 levels deep in a line. An entry uses
  two: the object, and an array of names in it. Verify counts the levels
  itself, before it reads the JSON, so the result is the same on every Go
  version. (Go's JSON reader has its own limit, and it changed between
  versions.)
- Each line is one JSON object with `seq`, `time`, `event` and `prev`. A
  field name must match exactly, and none of these fields may be there
  twice, so every reader sees the same values. A name that differs only in
  case, such as `SEQ` or `ſeq` (with a long s), is refused too, because
  Go's JSON reader would take it for the same field.
- `seq` counts up by one from 1. `prev` is the hash of the entry before it.
  `time` is an RFC 3339 time in UTC.
- A torn line is allowed only right before a `log_recovered` entry whose
  `torn_length` and `torn_sha256` match it. A `log_recovered` entry must
  come right after its torn line.
- A file with no entry fails: an emptied log looks the same.
- It does not check that `time` goes forward. The clock can go back, for
  example after an NTP correction, or after a power cut on a machine
  without a clock battery. `seq` and `prev` prove the order, and an
  attacker who can compute the chain again can fix the times too.
- It checks the fields above and the fields of `log_recovered`, not the
  fields of the other events. So a log from a newer nodkey, with new
  events or fields, still passes.
- A problem names the line number and what is wrong, never the text of the
  line, because a line can hold a secret that the masking missed.

## 10. Decision 1: how client and broker connect

**Decided 2026-10-12: A.**

**A. Mutual TLS with pinned keys.**
The broker listens on one TCP port on the private network. Each side has
its own key pair, made with `nodkey keygen`. Each side pins the other side's
public key (SHA-256 of the SubjectPublicKeyInfo). There is no certificate
authority. TLS 1.3 only.
- Good: one binary, no other service to set up. Each client has its own
  name, so the message shows which machine asks. Easy to test in CI. Go's
  TLS code is well reviewed.
- Bad: one more listening port. It must be reachable only from the private
  network (for example a VPN), and a firewall should limit it.
- Details: the broker asks every client for a certificate and checks the
  pin in `VerifyConnection`, which runs on every connection. Session
  tickets are off, so no connection skips the check. The client name comes
  only from the pinned key, never from the request.

**B. A Unix socket on the broker host, reached over SSH.**
The client runs `ssh broker-host` with its own SSH key. On the broker host,
`authorized_keys` forces a command (`command="nodkey relay --client
laptop",restrict`). That relay passes the request to the broker's local
socket.
- Good: no new port; it uses OpenSSH, which most people already trust.
- Bad: it opens SSH logins to the most trusted host from untrusted machines.
  One mistake in the forced command or the `sshd` settings gives the agent
  a shell on the broker host. It also needs a user account, `sshd` settings
  and a relay process, and each request starts an SSH connection.

**Why A:** fewer parts to set up, no login from untrusted machines to the
broker host, and easier to test. B can come later if someone needs it.

With either option, the client's key is on the agent machine, so the agent
can copy it. That is fine: the key only lets it *ask*. Every answer still
needs the approver.

### How A works

**The key file.** `nodkey keygen --out FILE` makes a new Ed25519 key and a
self-signed certificate for it. It writes both to FILE as two PEM blocks:
`PRIVATE KEY` (PKCS #8) and `CERTIFICATE`. The broker's `tls_key` and the
client's `tls_key` are such files.

- keygen never overwrites a file. It makes FILE with `O_CREAT`, `O_EXCL`
  and `O_NOFOLLOW`, so it refuses a file or a symbolic link at that path.
  The new file has mode `0600`, whatever the umask.
- Before it writes the key, keygen checks the directories on the way to
  FILE, and the new empty file, as the broker checks a key file (section
  14). If a check fails, keygen removes the new file. So it does not leave
  a key where others can read it, for example on NFS.
- keygen prints the pin on stdout, and nothing else: `sha256:` and the
  SHA-256 of the key's SubjectPublicKeyInfo in base64, without padding.
  Put it into the config of the other side. If the pin cannot be printed,
  keygen removes the new file.
- The certificate only carries the key. Neither side checks its names or
  its dates, and it never ends (`9999-12-31`). To retire a key, remove its
  pin from the other side's config.
- The broker and the client read a key file only through the checked
  reader of section 14. They accept only the form above: one Ed25519
  private key and one certificate for that key, and nothing else. No other
  block, no PEM headers (so no encrypted key), no other text.

**Each connection.**

- TLS 1.3 only. Each side checks the other side's pin in
  `VerifyConnection`. Go runs it on every connection, also on a resumed
  session.
- No session is resumed. The broker sends no session tickets, and the
  client keeps no sessions (no session cache, session tickets off).
  `VerifyConnection` also refuses a resumed session. So each connection
  makes a full handshake, with the certificate and the pin check.
- Each side must send exactly one certificate. There is no certificate
  authority, so there is no chain.
- A copy of a certificate is not enough: TLS checks that the other side
  holds the private key of its certificate.
- The client turns off Go's usual check of the broker's certificate
  (`InsecureSkipVerify`), because there is no certificate authority to
  check it against. The pin check in `VerifyConnection` replaces it.
- The broker refuses to start when a client's pin is the pin of the
  broker's own key, or when two clients have the same pin.

**The client name.** The broker finds the client name in the handshake: it
is the name of the `[client.*]` section that pins the client's key. The
TLS layer stores the name for that connection, and a handler reads it only
from there. The request cannot change it. Neither can the names in the
client's certificate, or the server name (SNI) that the client asks for.
The broker refuses a request without a stored name (403) before any
handler sees it.

**HTTP.** HTTP/1.1 inside the TLS connection. No HTTP/2.

- Request headers must arrive within 10 seconds, and the whole request
  within 30 seconds. The headers, with the request line, are at most
  12 KiB (net/http allows 4 KiB more than its limit of 8 KiB). The
  10 seconds also limit the TLS handshake.
- After the body is read, a request may wait for the approver as long as
  its timeout. It ends early when the client hangs up, with one
  exception: if the client has already sent its next request on the same
  connection (HTTP pipelining), net/http does not see the hang-up, and the
  request runs until its timeout. The client never does that.
- A client must take each answer within 30 seconds. An idle connection
  closes after 60 seconds.
- An error answer gives only the HTTP status, such as
  `{"error":"Bad Request"}`. It never says which key or value was wrong.
- If a handler panics, the broker logs where (function, file and line),
  but not the panic value, and drops the connection. The value could hold
  anything from the request.
- The client connects only to the `broker` address in its config, never
  through a proxy (it ignores `HTTPS_PROXY`). It follows no redirects.

**The request body.** It is JSON with the content type `application/json`,
at most 2 MiB (2,097,152 bytes). Every valid request fits:

- A claimed text field, such as the reason, is at most 64 KiB (65,536
  bytes). A command line has at most 4096 arguments, and at most 64 KiB
  in all. The client replaces a longer field, or a command line with more
  arguments, with the text `[hidden: too long]` before it sends the
  request (a command line becomes one argument with that text). The broker
  shows it like any claimed text. (A field over 64 KiB that reaches the
  broker anyway is not shown either; section 7.)
- An SSH request sends the command lines of `ssh` and of at most 3 of its
  parent processes (section 6): at most 4 command lines.
- In JSON, one byte of text takes at most 6 bytes (a control character
  becomes `\u0001`), and each argument adds 3 bytes (two quotes and a
  comma). So a text field takes at most 2 + 6 × 65,536 = 393,218 bytes,
  and a command line at most 1 + 3 × 4096 + 6 × 65,536 = 405,505 bytes.
- The largest request is an SSH request: 4 command lines and the reason
  take at most 2,015,238 bytes. A request for secrets has one command line
  and 3 text fields (the working directory, the local user name and the
  reason): at most 1,585,159 bytes. All other fields of a request, such as
  names, keys and the data to sign, must fit in 64 KiB. So every valid
  request is at most 2,080,774 bytes.

The broker checks the body in one pass over its bytes before it decodes
it:

- It must be one JSON object and nothing after it, in valid UTF-8.
- At most 16 levels of objects and arrays, at most 256 keys in one
  object, and at most 65,536 values in all. The largest valid request has
  about 16,400 values. Go's JSON decoder makes an error value for each
  value of the wrong type, so this limit keeps the cost of a hostile body
  small (T28).
- Each key may appear once in an object. Each key must be a lower-case
  name (`[a-z][a-z0-9_]*`, at most 64 characters), also after JSON
  unescaping. Go matches JSON keys to fields without regard to case, so
  this rule makes sure that a key matches only its exact field. Unknown
  keys are refused. So a request never uses data, such as a variable
  name, as a key; it uses a list of objects instead.

**The broker's log.** Any peer can open a connection, and the log goes to
the journal next to the audit anchors (section 9). So a log line about a
connection never holds text that the peer chose, such as its ALPN names,
a field of its certificate, or a line break:

- A refused TLS handshake gives one short line: the remote address and a
  fixed reason, such as "the client sent no certificate". The reason
  depends only on the start of Go's error text, which the peer cannot
  choose. The rest of that text is never logged.
- A client key that no `[client.*]` section pins is logged with its pin.
  That helps to add a new client.
- Any other line from Go's HTTP server is cut to 1 KiB of printable
  ASCII.
- The broker logs at most 60 such lines per minute. When it drops lines,
  it says how many in its next line.

## 11. Decision 2: loading keys after a restart

The broker must start on its own after a power cut. Nobody types a
passphrase on a host.

**Decided 2026-10-12: A now, B later.**

**A. Everything as systemd encrypted credentials.**
The broker runs as its own system user, from a systemd unit. The SSH
private keys, the broker's TLS key, the bot token, the `bws` token and the
`bw` master password are all systemd credentials
(`LoadCredentialEncrypted=`). They are encrypted with
`systemd-creds encrypt --with-key=host+tpm2`, so they can be opened only on
that machine, with its TPM2 chip. A copy of the disk or a backup alone does
not give them. The broker reads them from `$CREDENTIALS_DIRECTORY` at start.
An SSH key stored this way needs no passphrase.
- Without a TPM2 chip, encrypt with `--with-key=host` instead. Then anyone
  with a full copy of the disk can open them. The docs say this plainly.
- Plain files (mode `0600`, owned by the broker user) also work, for tests
  and for machines without systemd. The broker refuses to start if a key or
  secret file can be read by group or others.
- Root on the running broker host can still get everything. That is the
  trust we place in the broker host.

**The `bw` master password.** The Bitwarden Password Manager CLI must be
unlocked with the account's master password. An API key alone is not
enough. To restart on its own, the broker must keep that password, so
anyone who breaks into the broker host gets the whole vault. So nodkey
supports `bw` only with a separate Bitwarden account that holds nothing but
the items nodkey may hand out. A person logs in once on the broker host
with `bw login --apikey`; after that the broker unlocks on its own at each
start. If the CLI is ever logged out, every `bw` request is denied until a
person logs in again. Bitwarden Secrets Manager (`bws`) does not have these
problems: its machine-account token can see only the projects you give it.

**B. Keys inside hardware, through an upstream SSH agent.**
The broker sends signing to a local agent socket on the broker host, for
example a TPM-based agent or a YubiKey. Then nobody can copy the key, not
even root. Root on the broker host can still *use* the key while it has
access. This is a good next step, but not version 1.

**Not chosen:** typing the passphrase into Telegram. It would pass through
Telegram's servers and stay in the chat history.

## 12. Decision 3: unattended runs

A cron or timer job on the agent machine cannot tap a button.

**The honest limit:** if a job on the agent machine can get a secret
without a tap, the agent can too. The agent may be root there, and it can
read anything the job can read. There is no way around this on the same
machine.

**Decided 2026-10-12: A where possible, else B.**

**A. Run the job somewhere without an agent.**
Give that machine its own client identity. A "never ask" rule for that
client opens no hole on the agent machine.

**B. A "never ask" rule for one client and one secret or key.**
The hole: anything on that client can get that one secret (or log in to the
listed hosts with that key) without a tap. To keep it small:
- The rule names exactly one client.
- For SSH keys, it must list the hosts (`hosts = [...]`).
- It can be limited to a time of day (`hours = "03:00-03:20"`, broker
  local time: the time zone of the broker process). The end is not part of
  the hours: `03:20:00` is outside. Outside those hours, the broker asks as
  usual, with "Approve once" and "Deny".
- Hours are read on the local clock, so summer time changes them. On the
  day the clocks go back, the hour before the change comes twice, and
  hours in it, such as `03:00-03:20` in most of Europe, open twice. On the
  day the clocks go forward, an hour is skipped, and hours in it do not
  open at all. If your time zone has summer time, choose hours outside the
  change (often 01:00 to 04:00), or run the broker in UTC.
- An optional `max_per_day` limit. Over the limit, the broker asks again. If
  the agent used up the uses, the real job fails, and that is a visible sign.
  A day is a calendar day in broker local time. But when the hours go past
  midnight, such as `23:30-00:30`, the uses after midnight count for the
  day the hours began, so `max_per_day = 1` gives one use a night. On the
  day the clocks go back, hours that open twice still share one count. If
  the clock is set back to an earlier day, the uses of the later day still
  count, so a clock change cannot give more uses.
- Every use sends a silent Telegram message (`notify = true` by default) to
  the notice chat, so a strange use is seen. If that message cannot be
  sent, the request is denied. At most 6 notices go out in any 60 seconds
  for one client (section 8), and at most 20 for all clients together
  (section 7); a use over that is denied.
- Use a narrow secret: a secret that can do little, or a deploy key that
  can reach only one repository. For `bws`, the job's secret can live in its
  own project, read through its own store entry with its own machine
  account (see the two `bws` stores in section 14).

**Not chosen:** matching the command name ("only for `backup.sh`"). The
command is claimed. The agent can send any command line it wants.

## 13. Decision 4: SSH approval scope

One Ansible run makes at least one signature per host.

**Decided 2026-10-12: B, plus D.**

| option | taps for one Ansible run on 6 hosts | what a tap allows |
|---|---|---|
| A. Ask for every signature | 6, every run | one login |
| B. Once per N minutes per (client, key, host, user) | 6 on the first run, 0 on the next runs within N minutes | logins as that user to that one host, for N minutes |
| C. Once per N minutes per (client, key) | 1 | logins to **any** host, for N minutes |
| D. B, plus a pre-approval command | 1 | logins as that user to the hosts listed in the message, for N minutes |

**D, the pre-approval command:**

```
nodkey ssh-grant --key deploy --user deploy --host web-1 --host web-2 \
                 --for 15m --reason "apply the nginx fix"
ansible-playbook site.yml
```

`ssh-grant` sends one request. The message lists the key, the remote user,
every host by its name in the broker's `known_hosts`, and the time the
grant ends. That time is fixed when the request comes: its time plus
`--for`, in whole minutes, rounded down. A late tap does not move it. The
message has only "Approve" (until that time) and "Deny". It waits for an
answer as long as a request for secrets (`timeout`), because it is not an
SSH login, but never past the time the grants end: after that, an
approval would grant nothing. One tap makes a grant for each host key of
each listed host (a host can have one host key of each key type), exactly
as in B.
Then the playbook runs without more taps. A host that is not in the list
still asks. A host that is listed twice counts once. The broker refuses
an `ssh-grant` when:
- the remote user name does not match the pattern in section 6;
- the key's rule is not `window`;
- `--for` is longer than the key's window, or shorter than one minute;
- a host is not in the broker's `known_hosts`, or not in the key's `hosts`
  list when it has one;
- it lists no host, or more than 20 hosts.

**Why B and D:** the host is the most useful thing a person checks, and both
keep it in every grant. C is too wide: approving `web-1` would silently allow
`db-1`. D turns the six taps of B into one, without making the scope wider.
It also avoids the queue: the playbook does not start 5 requests at the
same time. D is small to build because it reuses the same message and grant
code.

**Not chosen for now:** merging requests that arrive at the same time into
one message. D gives the same result with less risk: the list in the
message cannot change while the person reads it.

## 14. Configuration

Broker, `/etc/nodkey/broker.toml`:

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

[key.deploy]
file = "${CREDENTIALS_DIRECTORY}/ssh-deploy"
clients = ["laptop"]
ask = "window"
window = "15m"
hosts = ["web-1", "web-2"]          # optional; empty means any known host
```

The broker's `known_hosts` uses the OpenSSH format with stricter rules: one
plain host name per line, no wildcards, no hashed names, no `@` markers, and
each host key only once. A name may be on several lines, with at most one
key of each key type, because a host often has several host keys (for
example ed25519 and ECDSA). The broker refuses to start if any rule is
broken.
Cloned machines often share a host key. Then the broker cannot tell them
apart, so it refuses that file until each host has its own key.

Client, `~/.config/nodkey/client.toml`:

```toml
broker = "192.0.2.10:7743"
broker_pin = "sha256:Q2b9...base64..."
tls_key = "~/.config/nodkey/client.key"
```

Config files are strict: an unknown key is an error, so a typo cannot turn
a rule off. Keys must be written exactly as above, in lower case: `ASK`
is an unknown key. Each key must be below the header of its own section,
such as `ask` below `[secret.github-token]`. A dotted key such as
`secret.github-token.ask = "never"` and an inline table (`{ ... }`) are
errors, because a reader of the section would not see that key.

An error may show a file path, and a section name or key name that looks
normal, such as `[secret.github-token] window`. It never shows a secret
value. A key name is shown only if each part is 1 to 16 lower case
letters, digits and `_`, and starts with a letter. A section name is shown
only if it follows the name rule below. Otherwise the error does not show
the name, because it may be a secret that was pasted by mistake. An error
can show a path, so do not paste a secret into a path setting. A TOML
syntax error gives only the line and the column, because the text there
can be a secret that was pasted by mistake.

More rules:

- `listen` is one IP address and a port from 1 to 65535, such as
  `192.0.2.10:7743` or `[2001:db8::10]:7743`. A host name, a missing
  address, and `0.0.0.0` or `::` are errors: they would make the broker
  listen on every network, not only on your private network. A multicast
  address (such as `224.0.0.1` or `ff02::1`) and the broadcast address
  `255.255.255.255` are errors too: they are not the address of one
  machine. An IPv6 zone (the part after `%`, such as `%eth0`) is an error,
  and so is an IPv6 link-local address (`fe80::/10`), which works only
  with a zone. A zone is the name of a network interface, and nodkey does
  not check those names. An IPv4 link-local address (`169.254.0.0/16`) is
  allowed.
- Names of clients, stores, secrets, keys and known hosts are 1 to 64
  letters, digits, `.`, `_` or `-`, and start with a letter or digit.
- Paths must be absolute. Only `${CREDENTIALS_DIRECTORY}/` and `~/` at the
  start of a path are expanded; any other `$` is an error.
- A secret's `id` is the item's UUID in the store, so `bw` never searches
  items by name.
- `clients` and `hosts` list each name once. `notice_chat_id` is not 0.
  A `window` is 1 minute to 8 hours.
  `timeout` is 15 s to 10 min. `ssh_timeout` is 15 s to 110 s, below
  `sshd`'s `LoginGraceTime`.
- `max_per_day`, if present, is 1 or more. For no limit, leave it out.
  So `0` cannot mean "no uses" to a person and "no limit" to the broker.
- Two secrets with `ask = "never"` must not have the same `id`, also not
  through two `[store.*]` sections. Otherwise two clients could get one
  item without a tap.
- In `known_hosts`, the key type must match the key, and certificates are
  not allowed.
- An SSH key of a `[key.*]` section must be Ed25519, ECDSA on P-256, P-384
  or P-521, or RSA with at least 2048 bits. At start, the broker signs a
  fixed text with each key and checks the signature, so a broken key
  stops the start and not a login after the tap. These signatures never
  leave the broker.

At start, the broker checks the files it reads, and refuses to start on
any problem:

- Key, token and password files must be regular files, not symbolic links,
  and at most 1 MiB. They must be owned by the broker user or root, and
  group and others must have no access. systemd gives a credential to the
  service as a file owned by root, with an ACL entry that lets the service
  user read it. That ACL entry is accepted. An ACL entry for any other user
  or group is not, and neither is an ACL that cannot be read.
- Key, token and password files must be on a local file system that
  nodkey knows: ext2, ext3, ext4, xfs, btrfs, zfs, tmpfs, ramfs, f2fs,
  bcachefs, overlayfs or ecryptfs. overlayfs and ecryptfs are layers over
  another file system, and the kernel still checks the mode bits and the
  ACL of the file you name. Every other file system is refused, such as
  NFS, SMB/CIFS, 9p, Ceph or FUSE, because there the mode bits may not show
  who can read a file. The error names the file system, such as `nfs`, or
  gives its number if nodkey has no name for it. The credentials directory
  of a systemd service is on ramfs or tmpfs.
- On overlayfs, nodkey sees only the top copy of a file. A lower copy can
  have other mode bits: a key can be `0644` in the lower layer and `0600`
  in the overlay after a `chmod`. Other users who can reach the lower layer
  can read it there, for example below a read-only root such as
  `/media/root-ro`, or in an overlay made by hand. With `metacopy=on`, the
  data stays in the lower file. So keep keys and tokens out of lower layers
  and image layers. Docker keeps its layers where only root can read them,
  so on the host, only root can read a lower copy.
- The config file and `known_hosts` must be owned by the broker user or
  root, and group and others must not be able to write to them. They may
  be symbolic links.
- A store's `program` gets a token from the broker, so it must be owned by
  the broker user or root, and group and others must not be able to write
  to it. It may be a symbolic link.
- The audit log may be missing; then the broker makes it. If it is there,
  it must be a regular file, not a symbolic link, owned by the broker user.
  Its mode may give only read and write to the owner, such as `0600`: an
  execute bit, or any bit for group or others, is refused. It must not be
  another file that the broker reads or runs: a key, token or password
  file, a store's `program`, the config file or `known_hosts`, also not
  through a hard link or a linked directory. The broker adds a line to the
  log for each request, and people read and copy the log. This is a check
  at start. The broker still opens the file with `O_NOFOLLOW` and checks
  the open file, so a link that is put there later is refused too.
- Every directory on the way to any of these files must be owned by the
  broker user or root, and group and others must not be able to write to
  it. Otherwise someone else could swap the file. This includes each
  directory that holds a symbolic link on the way.
- nodkey opens each file once, checks the open file, and reads from that
  same open file. So the file cannot be swapped between the check and the
  read.
- Two `[key.*]` sections must not name the same file, also not through two
  paths (a hard link or a linked directory). A copy of a key in a second
  file passes this check. So when the broker loads the keys, it also
  refuses two `[key.*]` sections with the same public key.

The client checks its `tls_key` file in the same way as the broker checks
a key file.

## 15. Commands and exit codes

```
nodkey broker [--config FILE]
nodkey run [--secret VAR=NAME]... [--reason TEXT] -- COMMAND [ARGS...]
nodkey ssh-agent [--socket PATH]
nodkey ssh-grant --key NAME --user USER --host NAME... --for DURATION [--reason TEXT]
nodkey keygen --out FILE
nodkey audit verify FILE [--anchor SEQ:HASH]... [--anchors FILE|-]
nodkey version
```

`nodkey run` exits with the command's own code, or:

| code | meaning |
|---|---|
| 64 | wrong usage |
| 69 | the broker cannot be reached |
| 77 | denied, expired or not allowed |
| 126 | the command was found but cannot be run |
| 127 | the command was not found |

The command itself may also exit with one of these codes. To tell them
apart, look at the last line on stderr. Only when nodkey itself exits, its
last line is `nodkey: <reason> (exit <code>)`, for example
`nodkey: denied (exit 77)`. When the command runs, nodkey prints nothing
after it.

`nodkey keygen` prints the pin on stdout, and nothing else. It exits with
0, with 64 on wrong usage, and with 1 on any other error. Then its last
line on stderr is `nodkey: <reason> (exit 1)`.

`nodkey ssh-agent` creates its socket in a `0700` directory with mode
`0600`. It refuses connections from other users. It refuses `ssh-add`
(adding, removing, locking keys).

`nodkey audit verify FILE [--anchor SEQ:HASH]... [--anchors FILE|-]`
takes `FILE` before or after the options.

- `--anchor SEQ:HASH` may repeat.
- `--anchors FILE` reads anchors from a file, or from stdin for `-`. It
  uses every line that is exactly `audit anchor SEQ:HASH`, and skips the
  other lines, so it takes the output of `journalctl -u nodkey -o cat`.
  If no line is an anchor, that is wrong usage: a check with no anchor
  must not pass by mistake.
- Two anchors for one entry must not differ.

Check with every anchor since the log began (section 9). When the log
passes, it prints to stdout:

```
ok: 1234 entries (torn lines: 0)
anchors: 1234 checked, all match; the newest is entry 1234
last entry: 1234:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

Without anchors, the middle line is `anchors: none checked`. Entries after
the newest anchor are not proven. When the log fails, it prints the first
problem to stderr, with the line number, for example
`nodkey: audit log FILE: line 57: has seq 58, want 57`. It never prints the
text of a line. It exits with:

| code | meaning |
|---|---|
| 0 | the log passed |
| 1 | the result cannot be printed |
| 64 | wrong usage, such as an anchor that is not `SEQ:HASH`, or an anchors file without an anchor |
| 65 | the log failed: a broken link, a line that is not a valid entry, a torn line without its `log_recovered` entry, an anchor that does not match or whose entry is not in the log, or two anchors for one entry that differ |
| 66 | the log or the anchors file cannot be opened or read |

## 16. Implementation rules

- No secret value in any log, error text, audit entry or Telegram message.
- The broker runs store programs by absolute path, with no shell, with only
  the environment they need (tokens and the `bw` session go in environment
  variables, never in arguments), with a timeout and a cap on output size.
  Their output is never logged.
- `bw` keeps a local copy of the vault. The broker runs `bw sync` before each
  fetch, so a changed or removed item is not handed out from an old copy.
- `bws` and `bw` write state files in their home directory. The systemd unit
  gives the broker a private, writable home under its state directory.
- Limits on every input: request size (2 MiB, see section 10), number of
  secrets per request, field lengths. JSON decoding rejects unknown and
  repeated keys.
- The broker turns off core dumps and marks itself not dumpable
  (`PR_SET_DUMPABLE`).
- Time limits use Go's monotonic clock, so setting the wall clock does not
  move them. The monotonic clock stops while the host sleeps (suspend), so
  a request and a grant also end when the wall clock reaches their end:
  they end at whichever clock gets there first. A grant from 11:55 for 15
  minutes ends at 12:10 on the wall clock, also if the host slept from
  12:00 to 20:00. A request whose end the wall clock has passed takes no
  answer.
- A systemd unit with sandbox settings ships as an example.

## 17. Testing

- **Unit tests** for each package: config, rules and grants (with a fake
  clock), limits and the queue, audit chain, tamper checks and torn-line
  recovery, session-bind and authentication request parsing, masking, message
  text and escaping, and the Telegram client against a fake Telegram server
  (wrong user, wrong chat, inline message, wrong message, bad button data,
  unknown ID, early tap, late tap, double tap, a tap sent again after a
  restart, a message that someone else edited, polling conflict, code 429
  and server errors, and a canary bot token that must not appear in any
  error or log line). A child process checks the HTTP client with
  `GODEBUG=http2debug=2` and a proxy. The SSH checks also use real data:
  from an in-process SSH server and client, and from the OpenSSH client
  and, when it is installed, `sshd`.
- **Fake approver**: a test approver that says yes, no, nothing, or answers
  late, on command. It and a fake clock are in
  `internal/approval/approvaltest`, for the tests of the broker too.
- **Fake store**: a small test program that acts like `bws`.
- **End-to-end test**: a throwaway key, `sshd` in a container, the broker and
  the client on the test machine, and the fake approver. It checks that
  `ssh` and `git` over SSH work, that a deny blocks the login, that an
  unknown host key is refused, that `ssh-grant` covers exactly the listed
  hosts, and that `nodkey run` passes a secret into a command without
  printing it. It needs Docker, so it has its own build tag and its own CI
  job.
- **Canary test**: the end-to-end test uses a planted secret value and then
  searches every log, the audit log, every message sent to the fake
  Telegram server, and the client's output for it. A second canary sits in
  a parent process's command line, to test the masking. Any hit fails the
  test.
- **One manual test with a real Telegram bot**, written down in
  `docs/manual-telegram-test.md`. The token comes from a local file and is
  never committed.

## 18. Build, CI and releases

- CI on every pull request: `go test -race`, `go vet`, `golangci-lint`,
  `govulncheck`, and the end-to-end job.
- GitHub Actions are pinned to a commit SHA.
- Pull request titles follow Conventional Commits. Pull requests are squash
  merged.
- release-please keeps a release pull request open. Merging it tags the
  version and creates the GitHub Release. A job then builds static Linux
  binaries (`CGO_ENABLED=0`, amd64 and arm64, `-trimpath`), a
  `SHA256SUMS` file, and a build provenance attestation.

## 19. How the work is done

- One GitHub issue per piece of work, each with a "Done when" checklist.
- One feature branch and one pull request per issue.
- Each change gets a review from the security reviewer agent in
  `.claude/agents/security-reviewer.md` before it is committed.

## 20. Prior art

We read these projects on 2026-10-12 for ideas. We copy no code from them.

| project | license | what we take as an idea |
|---|---|---|
| [Ladulås](https://github.com/hugowetterberg/ladulas) | MIT | Mutual TLS with pinned keys. The broker parses the signed bytes again and denies what it cannot classify. Host taken from the session-bind and the "hostbound" auth bytes. Grants scoped by key, host key and user. 90 seconds for SSH requests. A pre-approval command. |
| [secret-gate](https://github.com/johnuopini/secret-gate) | MIT | Telegram long polling; the value only in the child's environment. Also what to avoid: it does not check who pressed the button, and its CLI prints values. |
| [agentbell](https://github.com/MoodTechBasti/agentbell) | MIT | Only an explicit yes counts. The request ID is in the button. Stale and foreign answers are refused and logged. Buttons are cleared after an answer. |
| [agent-keyring](https://github.com/devonpmack/agent-keyring) | Apache-2.0 | Strip control characters from the agent's reason and label it unverified. One-time use with one atomic step. Flood limits. A canary leak test. |

We also looked at [Bitwarden Agent Access](https://github.com/bitwarden/agent-access)
and [opaque](https://github.com/opaque-dev/opaque) and chose not to fork
them. Agent Access has no SSH support, ties approval to a terminal screen,
and would need protocol changes that break compatibility with Bitwarden's
own clients. opaque is very large, has a different focus (it never returns
values), and has no SSH agent or phone approval.

Standards we use or borrow names from:
[OpenSSH agent restrictions and `session-bind@openssh.com`](https://www.openssh.com/agent-restrict.html),
[OpenSSH PROTOCOL (`publickey-hostbound-v00@openssh.com`)](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL),
[OpenID CIBA](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
(a request ID, a short code shown on both sides, an expiry), and
[RFC 4252](https://www.rfc-editor.org/rfc/rfc4252) (the SSH authentication
request).
