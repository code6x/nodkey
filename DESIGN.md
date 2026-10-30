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
| `nodkey update` | both, as root | Install a release in place of this binary, with the install script that is built into it (section 18). |
| `nodkey version` | both | Print the version. On a terminal, also say if a newer release is out. |

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

1. The client checks its arguments: 1 to 32 `--secret` options, each
   variable name valid, not on the deny list (see "Variable names that the
   broker refuses" below) and there only once, and the command after `--`.
   It looks for the command in `PATH`, as a shell does, and takes the
   absolute path of the file that it found: a relative path starts from
   the real working directory, not from `$PWD`, and the path is not
   cleaned, so `..` stays and names the same file as for the shell. A
   name without `/` that `PATH` finds only through a relative directory,
   such as `.`, is refused. A program that is a symbolic link shows as the
   link, and the kernel follows the link at `execve`: if the link changes
   while the request waits, its new target runs. Whoever can change the
   link, its directory or the file already controls that program (for
   `/usr/bin`, only root). If the command is not there, or cannot be
   run, the client exits at once (127 or 126, section 15), and nobody is
   asked. Then it reads its config (`~/.config/nodkey/client.toml`,
   section 14) and its TLS key, and connects to the broker over mutual
   TLS (see [section 10](#10-decision-1-how-client-and-broker-connect)).
2. The client sends `POST /v1/secrets` (section 10): for each variable, its
   name and the name of the secret, and the command line, the working
   directory and the reason. In the command line, the program is the
   absolute path of step 1, the file that will run, and the arguments are
   as the agent gave them. So a `gh` that `PATH` finds in another
   directory first, such as `node_modules/.bin`, shows as that path. The
   reason comes from `--reason`, or else from the `NODKEY_REASON`
   environment variable. Section 10 limits their size: a longer field
   becomes `[hidden: too long]`. The client does not send the local user
   name: no message (section 7) and no audit entry (section 9) has a
   place for it. Before it sends the request, the client marks itself as
   not dumpable (section 16). The request has a deadline of 15 minutes:
   the longest `timeout` of the broker (10 minutes, section 14), and 5
   minutes for the rest, such as the fetch of the values. That is usually
   enough: one fetch takes a few seconds. But a fetch can take up to 130
   seconds when a store is slow (with `bw`, up to 4 runs of 30 seconds,
   section 16), and the broker fetches the secrets one after the other.
   After a late tap, 3 or more such fetches can pass the deadline. Then
   the client exits with 69 after the approval, and the command does not
   run: it fails closed. There is no other time limit on the wait for the
   person. The client sends the request once, on a connection of its own,
   and never again.
3. The broker takes the client name only from the pinned TLS key (section
   10). It refuses a body that is not a valid request (400). Then it checks
   that there are 1 to 32 variables, that each variable name matches
   `[A-Z_][A-Z0-9_]{0,63}`, is not on the deny list below and is there
   only once, that each secret name exists in the broker config, and that
   this client may use it. If any check fails, the answer is **deny**
   (403), and the audit log gets the request with only the names that
   passed. No message is sent for a name the client may not use, or for a
   variable on the deny list, and no grant or rule covers it. (The client
   checks the variable names too, but only to give a quick error. The
   broker does not trust the client's checks.)
4. The broker makes the claimed text safe (section 7), and checks the rules
   and grants. If a grant or a "never ask" rule covers every name, it skips
   to step 6.
5. Otherwise the broker sends one Telegram message for the whole request and
   waits. See [section 7](#7-approval-messages). First it tells the client
   the short code (`102 Processing`, section 10). The client prints
   `nodkey: waiting for approval (request 7qd2)` to stderr, so a person at
   the terminal can match it with the message on the phone. It takes the
   code only from that answer, and prints it once, only when it has the
   form of a short code. It prints no other header, except the broker's
   version in one warning, when the two versions differ (section 10).
6. On approval, the broker first writes the `request` entry and the
   `decision` (or `grant_used`) entry to the audit log; each one is synced
   to disk. Only then do the grants of an "Approve N min" tap start, and
   only then does the broker get the values: each secret once, from its
   store, by running the store's program (section 16). If one value cannot
   be fetched, the whole request is denied, and no value is sent. So is a
   request with a value longer than 64 KiB, or with values longer than
   1 MiB together: the environment of a command could not hold them.
   Then the broker writes the `secret_sent` entry, and only then sends the
   values back over the same TLS connection. If that entry cannot be
   written, no value is sent. The broker writes the answer by hand into one
   buffer of its own, not with Go's JSON encoder, which would keep a copy
   of the values in a buffer that it uses again. It clears that buffer and
   the values in its memory after the answer, and on every other way out.
7. Only a final `200` whose body passes the strict decoding of section 10
   counts: at most 2 MiB, every field there, and no other field. The
   client checks that the answer has exactly one value for each variable,
   in the order of the request and with the same names, each 1 byte to
   64 KiB and without a NUL byte. Otherwise the command does not run, and
   the client exits with 69. Then the client adds `GH_TOKEN=<value>` to
   its own environment, in place of a variable of the same name, and
   replaces itself with the command (`execve`): the path of step 1, with
   the arguments as the agent gave them. So no nodkey process stays in
   memory with the values. The command's exit code is the exit code of
   `nodkey run`. The client never ignores `SIGPIPE`: an ignored signal
   stays ignored after `execve`, so the command would run with it ignored.
8. On deny, timeout or error, the client prints one line to stderr, without
   any value, and exits: with 77 when the broker denies the request, and
   with 69 when it cannot reach the broker or gets another answer
   (section 15). Right before that line, it may print one warning about
   the version of the broker (section 10). It never prints an answer
   body. If the person stops `nodkey run` with Ctrl-C (`SIGINT`) or with
   `SIGTERM` while it waits, the client closes the connection, so the
   broker cancels the request. Then it prints its last line and ends
   itself with the same signal (section 15).

There is no command that prints a secret. This is on purpose: the agent
should never see the value in its own output.

The broker fetches a value only after approval, and fetches it again on
every request. Version 1 keeps no cache of values. For `bw`, it first
runs `bw sync --force`, which downloads the whole vault, so it never hands
out a value from an old copy of the vault. A sync without `--force` would
depend on the broker's clock (section 16).

### Variable names that the broker refuses

The variable name decides what the command does with the value. With some
names, common programs print the value, write it into a file or a file
name, send it to a server, or run it: as a command, as code or as options.
The person sees the name in the message (`as:`), but may not know what it
means. So the broker refuses these names in step 3: before any message,
grant or rule, as for any other check. The audit log gets the `request`
entry and a `denied` entry with cause `not_allowed`. The broker's log says
why, with a fixed text and the entry of the list, such as `PATH` or
`LD_*`, never with the name that the client sent. The client refuses
these names too, before it asks anyone: it prints a usage error of one
line (section 15) and exits with 64.

The broker refuses each name in the first column below. `LD_*` means
every name that starts with `LD_`. The match is exact, on the name in
upper case: `LD_*` refuses `LD_PRELOAD`, but not `LDAP_PASSWORD`. Each
entry was checked on 2026-10-15 on Ubuntu 24.04, with a made-up value,
unless the table says otherwise. A test checks that this table and the
list in the code (`api.DeniedVar`) are the same.

| name | what programs do with the value |
|---|---|
| `LD_*` | The dynamic loader prints a library in `LD_PRELOAD` or `LD_AUDIT` that it cannot load, and an `LD_DEBUG` option that it does not know. It writes a file named after `LD_DEBUG_OUTPUT`, and loads code from `LD_PRELOAD` and `LD_LIBRARY_PATH`. |
| `DYLD_*` | The same for the dynamic loader of macOS. Not checked; no use on Linux. |
| `GCONV_*` | glibc loads character set modules, which are code, from the directories in `GCONV_PATH`. Not checked. |
| `GLIBC_TUNABLES` | The dynamic loader prints a value that it does not know. |
| `RESOLV_*` | glibc prints a `RESOLV_MULTI` or `RESOLV_REORDER` that is not `on` or `off`, when a program looks up a host name. |
| `LANG`, `LANGUAGE`, `LC_*` | bash prints an `LC_ALL` that is not a locale. perl prints all of them when the locale is not valid. ssh sends `LANG` and the `LC_` names to the server: Debian and Ubuntu set `SendEnv LANG LC_*`. |
| `TZ` | `date` prints the leading letters of the value as the name of the time zone, when the rest reads as an offset from UTC. |
| `TERM` | `tput` and `clear` print a terminal that they do not know. |
| `PATH` | It decides which programs run. GNU `which` prints it when it does not find a program. (Not checked: Ubuntu has another `which`.) |
| `HOME` | Programs make their files under it: npm makes `<value>/.npm` in the working directory. git and bash print paths under it in errors. |
| `TMPDIR`, `TMP`, `TEMP` | Node.js programs print them when they cannot make a temporary file there. Node.js reads `TMP` and `TEMP` when `TMPDIR` is not set. `mktemp` prints `TMPDIR` too. |
| `SHELL` | ssh runs a `ProxyCommand` with it, and `script` runs it. Both print a shell that they cannot run. |
| `EDITOR`, `VISUAL` | `git commit` and `crontab -e` run the editor, and print an editor that they cannot run. |
| `PAGER` | git and man run it when they write to a terminal. |
| `MANPAGER` | man runs it, before `PAGER`, when it writes to a terminal. |
| `BROWSER` | `gh browse` and `sensible-browser` run it. |
| `EMAIL` | `git commit` writes it into the commit as the email address when `user.email` is not set. |
| `SSLKEYLOGFILE` | curl and Python write the keys of each TLS connection to a file named after the value. |
| `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` | curl and Python requests print the path of a CA file that they cannot load. |
| `WGETRC` | wget prints a config file that it cannot read. |
| `BASH_ENV`, `ENV` | bash for a script, and an interactive sh, expand the value, which can run commands, and run the file it names. |
| `SHELLOPTS`, `BASH_XTRACEFD`, `BASH_COMPAT` | bash prints a value that is not valid, every time it starts. |
| `PS0`, `PS1`, `PS2`, `PS3`, `PS4` | The shell prints them as prompts, most of them after an expansion that can run commands: `PS4` before each command that `set -x` traces, `PS3` for `select`, the others in an interactive shell. |
| `PROMPT_COMMAND` | An interactive bash runs it before each prompt. |
| `TIMEFORMAT` | bash prints it after `time`. |
| `HISTFILE` | An interactive bash writes its history to a file named after the value. |
| `GIT_*` | git runs `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`, `GIT_PAGER`, `GIT_ASKPASS`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND` and `GIT_EXTERNAL_DIFF`. It prints a `GIT_TRACE` or `GIT_TRACE2` name whose value is not a number, `true`, `false` or an absolute path. It stops and prints the value of `GIT_DIR`, `GIT_CONFIG_NOSYSTEM`, `GIT_AUTHOR_DATE` and many more names when the value is not valid. It writes `GIT_AUTHOR_NAME` and the other author and committer names into each commit, and makes files named after `GIT_INDEX_FILE`, `GIT_WORK_TREE` and others. In a test of everyday commands (`status`, `add`, `commit`, `log`, `fetch`, `push` and more), about 60 names of git 2.43 showed the value. New versions of git add names. |
| `SSH_ASKPASS` | ssh-add and git run it to ask for a passphrase or a password. |
| `SUDO_ASKPASS` | sudo runs it to ask for the password: with `-A`, and also without `-A` when there is no terminal and `DISPLAY` is set. It prints `unable to run` and the value when it cannot run it. The name also invites a mistake: the sudo password as the value. |
| `SSH_SK_HELPER`, `SSH_SK_PROVIDER` | ssh-keygen and ssh run the helper, or load the library, for a security key, and print a name that they cannot use. |
| `GNUPGHOME` | gpg prints paths under it. |
| `RSYNC_RSH`, `RSYNC_CONNECT_PROG` | rsync runs them, and prints a command that it cannot run. |
| `TIME_STYLE`, `QUOTING_STYLE` | ls prints a value that is not valid. |
| `GZIP`, `BZIP2`, `BZIP`, `ZSTD_CLEVEL` | gzip, bzip2 and zstd read them as options, also when tar runs them, and print a value that they cannot use. |
| `MAKEFLAGS`, `GNUMAKEFLAGS` | make reads each letter of the value as an option. With a `p` in it, make prints its database, with every variable of the environment and its value, so also the other secrets of the command. |
| `CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS`, `LDLIBS`, `TARGET_ARCH` | The built-in rules of make print them in each command that they run, and run `CC` and `CXX` as the compiler. |
| `GH_BROWSER`, `GH_EDITOR`, `GH_PAGER` | gh runs them. (`GH_EDITOR` and `GH_PAGER` not checked.) |
| `GH_REPO` | gh prints a value that is not `OWNER/REPO`. |
| `GH_HOST` | gh connects to the host that it names, and prints the name when it cannot. |
| `DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_API_VERSION` | docker prints a value that it cannot use. It connects to the host in `DOCKER_HOST`. |
| `COMPOSE_FILE`, `COMPOSE_ENV_FILES` | docker compose prints a file that it cannot open. |
| `TF_CLI_ARGS` | terraform reads it as options, and prints a value that it cannot use. Its forms for one command, such as `TF_CLI_ARGS_plan`, are lower case, so nodkey refuses them anyway. |
| `TF_CLI_CONFIG_FILE`, `TF_PLUGIN_CACHE_DIR` | terraform prints them. |
| `TF_WORKSPACE` | `terraform init` and `terraform plan` make a directory `terraform.tfstate.d/<value>`. |
| `TF_LOG_PATH` | terraform writes its log to a file named after the value. |
| `NPM_CONFIG_*` | npm reads its settings from them, also in upper case. `npm run` runs `NPM_CONFIG_SCRIPT_SHELL`. `NPM_CONFIG_CACHE` and `NPM_CONFIG_LOGS_DIR` make a directory named after the value. npm prints others, such as `NPM_CONFIG_PROXY`: `npm warn invalid config proxy="<value>"`. |
| `GOMEMLIMIT` | Every Go program, such as gh or docker, prints a value that is not valid, and stops. |
| `GOFLAGS`, `GOTOOLCHAIN`, `GOPATH`, `GOROOT`, `GOEXPERIMENT`, `GO111MODULE`, `GOOS`, `GOARCH`, `GOTMPDIR` | The go command prints a value that it cannot use, and stops. |
| `GOCACHEPROG` | The go command runs it. |
| `CGO_CFLAGS`, `CGO_CPPFLAGS`, `CGO_LDFLAGS` | `go build` with cgo passes them to the C compiler, which prints them. |
| `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `JDK_JAVA_OPTIONS` | java prints "Picked up" and the value every time it starts, and reads the value as options. |
| `JDK_ALTERNATE_VM` | java does not start, and prints the value. |
| `JAVA_HOME` | gradlew prints a value that is not a Java directory. |
| `JAVA_OPTS`, `GRADLE_OPTS`, `MAVEN_OPTS` | gradlew and mvn pass them to java as options, and java prints a value that is not an option. (`MAVEN_OPTS` not checked: mvn was not installed.) |
| `NODE_OPTIONS` | Node.js reads it as options, such as `--require`, which runs code. It prints a value that starts with `-` and is not an option that it allows. |
| `NODE_EXTRA_CA_CERTS` | Node.js prints the value when it cannot load the file, at its first TLS connection. |
| `NODE_V8_COVERAGE`, `NODE_COMPILE_CACHE`, `NODE_REDIRECT_WARNINGS` | Node.js makes a directory or a file named after the value. |
| `NODE_REPL_EXTERNAL_MODULE` | An interactive Node.js runs the module it names, and prints a module that is not there. |
| `PYTHONHOME`, `PYTHONPLATLIBDIR` | Python cannot start, and prints its path settings with the value. |
| `PYTHONEXECUTABLE`, `PYTHONIOENCODING`, `PYTHONWARNINGS` | Python prints the value: as the name of the program, or as a value that is not valid. |
| `PYTHONSTARTUP` | An interactive Python runs the file it names, and prints a name that it cannot open. |
| `PYTHONPYCACHEPREFIX` | Python makes a directory named after the value. |
| `PERL5OPT` | perl reads it as options, such as `-M`, which loads a module, and prints a module that it cannot find. |
| `PERL5LIB`, `PERLLIB` | perl prints them as part of its search path when a module is missing. |
| `PERLIO`, `PERL_SIGNALS`, `PERL_PERTURB_KEYS` | perl prints a value that it does not know (`PERLIO` only with `-w`). |
| `RUBYOPT` | ruby reads it as options, such as `-r`, which loads a library, and prints a library that it cannot find. Not checked: ruby was not installed. |
| `RUSTC_WRAPPER` | cargo runs it. Not checked: Rust was not installed. |
| `RUSTFLAGS` | cargo passes them to rustc, which prints a flag that it does not know. Not checked. |
| `RUSTUP_TOOLCHAIN` | rustup prints a toolchain that is not installed. Not checked. |
| `CARGO_TARGET_DIR` | cargo makes a directory named after the value. Not checked. |

Not on the list, on purpose:

- `NODE_PATH`, `PYTHONPATH` and `RUBYLIB`: the runtime skips a directory
  that is not there, quietly, and does not print it. (`RUBYLIB` was not
  checked: ruby was not installed.)
- `IFS`: bash, dash, zsh and busybox `sh` ignore it in the environment.
- `LESSOPEN`: less runs it only when it holds `%s` exactly once.
  Otherwise less says so, without the value.
- `GOPROXY`, `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY`: their URL can
  hold a password on purpose, and curl does not print the password.
- Names that hold a secret on purpose, such as `GH_TOKEN`,
  `NODE_AUTH_TOKEN`, `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`,
  `LDAP_PASSWORD`, `DOCKER_PASSWORD`, `CARGO_REGISTRY_TOKEN`, and
  Terraform's `TF_TOKEN_` and `TF_VAR_` names. So there is no `DOCKER_*`
  or `TF_*` prefix.

The prefixes also refuse some names that hold a secret on purpose:
`GIT_CONFIG_VALUE_0` (for example an `http.extraHeader` for git),
`GIT_CREDENTIALS` of semantic-release, `LD_ACCESS_TOKEN` and `LD_SDK_KEY`
of LaunchDarkly, and `NPM_CONFIG__AUTH` of npm. Give such a secret to the
program in another way, such as a git credential helper that reads
`GH_TOKEN`, or `NPM_TOKEN` in `.npmrc` for npm.

The list has limits:

- It covers the dynamic loader and the C library, the shells, git, ssh,
  sudo, make, gh, docker, terraform, npm, the runtimes and build tools of
  Go, Java, Node.js, Python, Perl, Ruby and Rust, and names that many
  programs use. It cannot hold every name of every program. Many other
  programs print a setting that is not valid, such as `UNZIP` for unzip
  or `COLUMNS` for `ls -C`, and some run a command from a name of their
  own. The person should deny a secret in a name that is not made for a
  secret.
- The agent sets the rest of the environment of the command, and the
  message does not show it. It can set `LD_PRELOAD` there itself. So the
  list stops mistakes, and simple tricks with the name that the person
  sees. It does not stop a hostile agent (THREAT-MODEL.md section 5,
  item 1).

## 6. Flow: an SSH login

```
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/nodkey/agent.sock
NODKEY_REASON="apply the nginx fix" ansible-playbook site.yml
```

1. `ssh` connects to `web-1` and finishes the key exchange.
2. OpenSSH 8.9 and newer then sends the agent a `session-bind@openssh.com`
   message. It holds the server's host key, the session identifier, the
   server's signature over the session identifier, and an `is_forwarding`
   flag. The client keeps these for that agent connection, and answers
   each with success, as OpenSSH's own agent does. It keeps at most 2,
   each at most 8 KiB: the most that the broker reads. It refuses more.
   Then that agent connection gets no signature, because the client could
   not send all of its session-binds; it asks the broker nothing for it.
3. `ssh` asks the agent for its keys. The client asks the broker
   (`POST /v1/keys`, section 10). The broker returns the public keys this
   client may use. The client gives `ssh` each key with its name as the
   comment, as `ssh-add -l` shows it. It asks the broker each time.
4. The server accepts one key. `ssh` asks the agent to sign the
   authentication request.
5. The client sends the broker (`POST /v1/sign`): the key, the data to
   sign and the flags, with exactly the bytes that `ssh` sent, the
   session-bind messages of this connection (at most 2), and some claimed
   context: the command lines of the `ssh` process and of at most 3 of its
   parent processes (from `/proc`), and `NODKEY_REASON` from the
   environment of the `ssh` process, if set. Section 10 limits their
   size. Apart from these limits, the client checks nothing in the
   request: the broker does all the checks.
   - The `ssh` process is the process that connected to the agent's
     socket. The kernel says which one (`SO_PEERCRED`). The client reads
     `/proc/PID/cmdline` of it, and the parents from `/proc/PID/stat`. The
     chain stops at a parent that cannot be read, has no command line
     (such as a kernel thread), or is there twice. The client opens the
     directory `/proc/PID` of a process once, and reads its files through
     it, so that they all come from that one process.
   - A read of `/proc` can block, such as on a stuck FUSE or NFS file
     system. The client waits for it at most 2 seconds, and runs at most
     4 such reads at the same time. Otherwise the request goes without
     the command lines and the reason, and a line says why.
   - The reason is the first `NODKEY_REASON` in `/proc/PID/environ` of the
     `ssh` process, as `getenv` finds it. The client keeps no other
     variable of that environment, and does not use its own environment.
   - All of this is claimed: the agent machine can change the command
     line and the environment of its own processes, and a process ID can
     be used again by a new process. A field that is too long becomes
     `[hidden: too long]`, as for `nodkey run`.
   - The request has a deadline of 115 seconds: the longest `ssh_timeout`
     of the broker (110 seconds, section 14), and 5 seconds for the rest.
     So a late tap still counts. It is below `sshd`'s `LoginGraceTime`
     (120 seconds by default): after that, a signature cannot log in. As
     for `nodkey run` (section 5), the client sends the request once, on
     a connection of its own, and never again.
   - When `ssh` closes its agent connection while the request waits, such
     as after Ctrl-C, the client closes its connection to the broker, so
     the broker cancels the request (section 7). It sees this also when
     `ssh` sent more bytes before: it asks the kernel whether the other
     side hung up (`poll` with `POLLRDHUP`), and does not read those
     bytes. After a hang-up, the client gives `ssh` no signature, also
     when an answer of the broker comes at that moment, and its line says
     that `ssh` closed its connection.
6. The broker checks, and denies on any failure. It makes these checks
   before any message or place in a queue (section 8). A request that fails
   them gets no message, and the audit log gets it with the key name, if
   the key was found, and no host. The broker's log gets the fixed text of
   the check that failed.
   - The key is one that this client may use: the broker compares the
     exact bytes of the public key with each of those keys.
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
   remote user), and asks the approver if needed. The message and the audit
   log name the host from the broker's own `known_hosts`, and the remote
   user after the check above.
8. On approval, the broker writes and syncs the decision, then signs. It
   signs exactly the data that it checked, with the checked algorithm (for
   RSA, the hash that the flags ask for), and checks the new signature.
   Then it writes the `signed` entry, and only then returns the signature.
   If the client has hung up before the broker signs, it does not sign.
9. Only a final `200` whose body passes the strict decoding of section 10
   counts. The client takes the short code only from the
   `102 Processing` answer, and prints it as in section 5. Before it gives
   the signature to `ssh`, it checks it: the format must be the one that
   the key and the flags ask for (for RSA, `rsa-sha2-256` or
   `rsa-sha2-512`, as the flags say; for Ed25519 and ECDSA, the key type,
   with no flags), and the signature must be valid for the data with that
   key. Every other answer, and every error, gives `ssh` a failure
   (`SSH_AGENT_FAILURE`), which says nothing about why. The client prints
   one line that says why (section 15).

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
command: /usr/bin/gh release create v1.2.0
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

A scheduled grant (`nodkey preapprove`, section 8) shows the secrets, or
the key, hosts and remote user, the number of uses and the start and the
end with the date and the zone. It has only "Approve" and "Deny"; the
message is in section 8. After "Approve", the message keeps one **Revoke**
button until the grant ends. Its data is `r:` and the request ID, as for
the other buttons. It passes the checks of "Telegram details" below:
the approver's user ID, the private chat, not an inline message, data of
the strict form, and in the core the grant of the request ID on that
message. It skips the check of a changed message, because a Revoke only
takes a right away. It never raises the alert about a changed message,
except on a message whose request may still wait: there it is refused
as a changed message, with the alert. The alert still comes from the
other taps.

The warning before the end of a standing grant (section 8) has one
**Renew** button. Its data is `n:` and the ID of the request that made
the grant. A Renew gives a right, so it passes every check of an Approve,
also the check of a changed message. A Renew on a warning that is already
the message of the new grant is refused as a late tap.

A notice of a "never ask" use (section 12) has no buttons and no expiry.
A notice of a use of a scheduled grant is the same, with the second line
`allowed by a scheduled grant, without a tap`. It goes to the notice chat
without a sound:

```
🔔 Secrets · request 7qd2
allowed by a "never ask" rule, without a tap
✅ machine: ci
✅ secrets: backup-token
— claimed by the agent —
command: restic backup /srv
```

A notice that a scheduled grant ended with uses left (section 8) is the
same, with the second line `not used: grant ID ended with 1 of 1 uses
left`. It goes to the notice chat without a sound:

```
🔔 Pre-approval · request m4k2
not used: grant 5Zq0v9xS3JkT1wYb7nQe2A ended with 1 of 1 uses left
✅ machine: laptop
✅ secrets: backup-token
✅ uses: 1
✅ from: 2026-10-28 03:00:00 UTC
✅ until: 2026-10-28 04:00:00 UTC
— claimed by the agent —
reason: job nightly-backup
```

A notice about the version of a client (section 10) has no buttons
either. It goes to the notice chat without a sound, once for each client
in each start of the broker, rarely more than once (see "Telegram
details" below), in one of these forms:

```
ℹ️ nodkey: The client laptop says that it runs nodkey 0.2.0, which is older than nodkey 0.3.0 on the broker. To update it, run there as root: nodkey update
ℹ️ nodkey: The client laptop says that it runs nodkey 0.4.0, which is newer than nodkey 0.3.0 on the broker. To update the broker, run as root on the broker host: nodkey update
ℹ️ nodkey: The client laptop sent no version of nodkey, so it may run an older nodkey. The broker runs nodkey 0.3.0. To update laptop, follow section 13 of docs/setup.md.
```

The name is the name of the `[client.*]` section, and the versions are
release versions: digits and dots only. "says that it runs" marks the
client's version as a claim. A client that sends no version runs nodkey
0.1, which has no `nodkey update`, so that notice points to the update
steps of [docs/setup.md](docs/setup.md#a-new-version-of-nodkey) instead.

A notice about a newer release of nodkey (section 15) has no buttons
either. It goes to the notice chat without a sound, once for each newer
release in each start of the broker, rarely more than once (see
"Telegram details" below). The first check comes 10 minutes after the
start, so a broker that ends sooner sends none. The notice of a
security release is different and follows below. The notice:

```
ℹ️ nodkey: A newer release is out: nodkey 0.3.0. The broker runs nodkey 0.2.0. To update the broker, run as root on the broker host: nodkey update. Then restart it: systemctl restart nodkey. The restart ends all grants. Update the agent machines too: run nodkey update as root. What is new: nodkey update --notes. Release notes: https://github.com/code6x/nodkey/releases/tag/v0.3.0
```

Both versions are release versions: digits and dots. The broker makes
the link from the version, and ends the text with it, so no dot follows
it. It takes no text and no link from the answer of GitHub.

A notice about a security release (section 15) has no buttons either,
but it makes a sound. It goes to the notice chat at each daily check,
until the broker runs that release or a newer one. It shares the limit of
3 notices a minute with the other notices. It starts with `SECURITY
UPDATE`, names the security releases that are newer than the broker,
lists at most 3 advisory IDs in the strict GHSA form, says that the flag
comes from GitHub's answer and is not checked, and points to the checked
notes. The link is made from the newest version and ends the text. A
try that times out after Telegram took the message is tried again 1 hour
later, so the phone rarely rings more than once in one daily check:

```
⚠️ SECURITY UPDATE: <security releases>. The broker runs nodkey 0.2.0. Advisories: GHSA-xxxx-xxxx-xxxx. This flag comes from GitHub's answer and is not checked: read the checked notes with nodkey update --notes. To update the broker, run as root on the broker host: nodkey update. Then restart it: systemctl restart nodkey. The restart ends all grants. Update the agent machines too: run nodkey update as root. This notice comes again each day until the broker runs nodkey 0.3.1 or newer. Release notes: https://github.com/code6x/nodkey/releases/tag/v0.3.1
```

When a client claims a release older than a security release that the
broker knows (section 10), the broker also sends a notice that names the
client. This notice is silent, so a false answer of GitHub still rings
the phone at most once a day. It comes at most once for each client in
each round. A round starts with each daily check, which comes at least 23
hours after the last one, or at once for a newer security release. A
client whose version is unknown (`dev`, or none) gets no such notice,
because its version cannot be compared. The name is the name of the
`[client.*]` section:

```
ℹ️ nodkey: SECURITY UPDATE: the client laptop says that it runs nodkey 0.2.0, which is older than nodkey 0.3.1, a security release. This flag comes from GitHub's answer and is not checked: read the checked notes with nodkey update --notes. To update laptop, run there as root: nodkey update. This notice comes again after the next daily check while laptop runs an older nodkey.
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
- A command line shows the program and at most 8 arguments. For
  `nodkey run`, the program is the absolute path of the file that the
  client will run, as `PATH` found it (section 5), such as `/usr/bin/gh`.
  The client sends it, so it is claimed too. Each field is
  cut to a fixed length, with `…` at the end. The broker keeps at most 2000
  characters of the command line, and at most 1000 of the working
  directory, of the reason, and of the variable names together (`as`). For
  an SSH login, it keeps at most 500 characters of each command line, and
  joins them with ` ← `, `ssh` first. So every audit entry fits in its line
  (section 9), also with the longest names and the characters that take
  the most bytes.
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
  - for an Approve, that message is as the broker sent it: nobody edited
    it, and it has the same buttons. A Deny counts on a changed message
    too (see below);
  - the ID belongs to a request that is still waiting;
  - the request has not expired;
  - the action is allowed for that request.
- The first valid answer wins. Taking a request out of the waiting list and
  deciding it is one step under one lock, so two taps cannot both count.
- The Telegram code checks the user, the chat, and that the message is
  as the broker sent it. For a Deny on a changed message, it checks that
  the broker sent this Deny button on that message. Then the approval
  core checks the user, the message, the request, the time and the
  button again. A tap that fails a check changes nothing: the request
  still waits, or it had already ended.
- The broker never edits a message while its request waits. With the bot
  token, someone else can: for example, they can make the message show a
  harmless secret name and keep the buttons, or swap the labels of the
  buttons. So an Approve never counts when Telegram says that its message
  was edited (`edit_date`), or when the message's buttons differ from the
  ones the broker sent, in their labels or their data. If the request of
  that message may still wait, the broker writes a `foreign_tap` entry
  with cause `edited_message`, logs an alert, and sends an alert message:
  the bot token may be stolen. It sends at most one such alert in 10
  minutes. No Approve on that message counts any more, so the request
  expires, unless the person taps Deny (below). When it ends, the broker
  writes the whole message again, with the result. Otherwise the broker
  itself edited the message after its request ended, or the message is
  from before a restart. Then the tap is only a late tap (below), and no
  alert goes out. This check needs the buttons that Telegram sends with
  each tap (`reply_markup` of the message). Without them, no Approve
  would count, and the broker would alert: that fails closed. The manual
  test of issue #17
  ([docs/manual-telegram-test.md](docs/manual-telegram-test.md)) showed
  on 2026-10-15 that Telegram sends them.
- A Deny is safe whatever the message shows. So when someone else changed
  a message while its request may still wait, a tap on the Deny button
  that the broker sent on it still goes to the approval core, as on any
  message. If it counts, it is a normal Deny: a `decision` entry, the
  pause, and the end of the client's grants (section 8). The phone shows
  "Denied. Someone else changed this message.", and the alert goes out as
  above. Like every tap on that message, the Deny is also written as a
  `foreign_tap` entry with cause `edited_message`, also when it counts.
  So the audit log shows the edit: that entry sits next to the
  `decision` entry of the Deny, and its `data` names the request. If the
  core refuses the Deny, such as after the request expired, only the
  `foreign_tap` entry is written. A Deny with the ID of another request
  does not count on that message. Only the button data says what a tap
  is, never the label. So if someone gives a button with the label
  "Deny" the data of an Approve, a tap on it does not count, and the
  request only expires. A tap on an "Approve" label with the data of a
  Deny denies.
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
  (by sending an empty keyboard, not by leaving it out), and the result
  replaces the expiry line: "👍 approved once by you at 14:02:41",
  "👍 approved for 15 min by you at 14:02:41", "👍 approved by you at
  14:05:12, until 14:20:00" (an SSH grant), "👍 approved by you at
  14:05:12, for 1 use(s) until 2026-10-28 04:00:00 UTC" (a scheduled
  grant), "⛔ denied by you at
  14:02:41", "⌛ expired — denied", "⛔ cancelled by the client" or
  "⛔ denied: the broker stopped taking answers". The message of a
  scheduled grant is edited twice more (section 8): when the grant
  starts, to add the Revoke button, and when the grant ends, to remove
  it and add a line that says how and when it ended, such as
  "⛔ revoked by you at 2026-10-28 03:10:00 UTC, with 1 use(s) left". A tap on
  the Approve or Deny button of that request on such a message is a late
  tap. A button of another request on it is refused as a changed message,
  with the alert. An edit without a
  keyboard (`reply_markup`) removes the buttons too: the manual test of
  issue #17 showed this on 2026-10-15
  ([docs/manual-telegram-test.md](docs/manual-telegram-test.md), check
  7). The broker still sends the empty keyboard, so that it does not
  depend on this behaviour of Telegram.
- Typed replies never count. Only buttons do. Every tap that does not
  count is written to the audit log as a `foreign_tap` entry, with a
  fixed `cause`: `other_user`, `other_chat`, `inline_message`,
  `no_message`, `bad_data`, `edited_message`, `unknown_request` (a late
  or second tap, or one from before a restart), `expired`,
  `wrong_message` (such as a copy of the message), `not_allowed` (a
  button that the request does not offer) or `refused`. So a forged
  button can be told from a person's second tap. The Telegram code logs
  each one, and passes it to the broker, which writes the entry. The
  broker only queues the entry there, and writes it in a goroutine of its
  own, so a slow disk never holds up the polling; when 64 entries wait, it
  drops more and logs how many. A tap
  that came too early is not written: it is the person's own tap, and
  they can tap again. But on a message that someone else changed, it is
  written, as `edited_message`. One tap that counts is written too: a
  Deny on a message that someone else changed (above).
- The Telegram code logs and reports at most 20 such taps in a minute
  from other users. The approver's own taps have a budget of their own,
  also 20 in a minute. Every tap on a message that someone else changed
  is the approver's. So forged buttons cannot crowd out the
  `edited_message` entry, or any other entry of the person's taps. The
  Telegram code counts the taps over a budget, and logs how many it
  dropped and from which budget, also when no later tap comes. So someone
  with the bot token cannot fill the journal or the disk with forged
  buttons. One person taps only a few times a minute. So the approver's
  budget is enough for the person, and someone who uses the approver's
  account (THREAT-MODEL.md T7) cannot fill the journal or the disk
  either. Every tap still gets its answer.
- If the client hangs up while waiting (for example `ssh` was killed), the
  request is cancelled. (Section 10 has one exception, which the client
  never uses: HTTP pipelining.)

### Telegram details

- Long polling with `getUpdates` (timeout 50 s, at most 10 updates in one
  answer). There is no webhook, so the broker needs no open port to the
  internet. The next call confirms the updates of the call before, so
  Telegram forgets them. After a crash, Telegram sends the updates that
  were not confirmed again; their taps find no waiting request.
- The broker asks only for `callback_query` and `message` updates. A
  `message` is read only for the command `/grants` (section 8): the text
  `/grants`, or `/grants@` and a name, with no space inside, from the
  approver in the private chat with the approver, at most 3 answers in
  any 60 seconds. Every other text sent to the bot is ignored, without an
  answer.
- If `getUpdates` fails with a conflict (another program polls with the same
  token, or a webhook was set), the broker logs an alert and sends a
  message: the bot token may be stolen. Then the Telegram code stops
  taking answers, so the polling stops for good (below), and the broker
  writes an `error` entry with code `poll_conflict` to the audit log. A
  conflict says that someone else may read the answers, so the broker
  does not go on: `nodkey broker` stops, and exits with code 76 (section
  15). The example systemd unit does not start it again after that code,
  so a stolen token does not bring a new alert at each restart.
- When the broker stops, it stops the polling first. It cancels the
  `getUpdates` call that waits, and closes its connection at once, with a
  TCP reset (`SO_LINGER` 0): the kernel drops a request that it has not
  sent yet. After that the broker sends no `getUpdates`. So after a
  restart, the new broker is the only one that polls. One case remains:
  a `getUpdates` request that was already on its way when the broker
  stopped. If it reaches Telegram after the new broker started to poll,
  Telegram ends the new poll with a conflict. Then the new broker sends
  the alert and stops, although no one else uses the token. This needs a
  stop at the moment when the old broker sends `getUpdates`, and a delay
  on the network that is longer than the time until the new broker
  polls. After a crash or an error, the example unit waits 5 seconds
  before it starts the broker again (`RestartSec=`). But `systemctl
  restart`, and a package upgrade that restarts the broker, start the
  new broker as soon as the old one has ended: then only the end of the
  stop and the start lie between them. A proxy (below) can also pass on
  a request after the broker closed its connection to the proxy. If this
  alert comes right after a restart, and no other program uses the
  token, start the broker again.
- If Telegram refuses `getUpdates` in another way, with a code from 400
  to 499 other than 409 and 429, such as 401 for a token that was
  revoked, the polling stops for good too. After 401 or 404, Telegram
  does not accept the bot token, and only a new token helps: `nodkey
  broker` exits with code 77, and the example unit does not start it
  again. After another code, it exits with 1 (section 15).
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
  proxy's host, never a user name or a password from the setting. Go
  also takes the certificate authorities from other places when
  `SSL_CERT_FILE` or `SSL_CERT_DIR` is set; a certificate authority there
  sees the token too, as such a proxy does. So the broker logs the name
  and the path of each one that is set. Only root can set these
  variables for the broker. Every user can read the `Environment=` lines
  of a unit (`systemctl show`), so a proxy setting with a password goes
  into an `EnvironmentFile=` that only root can read.
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
  needs a notice is denied as well. A notice about the version of a
  client (below) is different: no new try of it starts, but a try that is
  still being sent goes on until the service stops (section 15). The
  check for a newer release (section 15) goes on too, until the stop
  ends it first. The approval core would still let grants and "never
  ask" rules with `notify = false` allow requests, but the broker denies
  every request from then on (503), and `nodkey broker` stops (section
  15). On a
  polling conflict, the broker first writes the `error` entry with code
  `poll_conflict`.
- Messages about "never ask" uses can go to a second chat
  (`notice_chat_id`), so the approval chat stays for approvals only.
  They are silent (`disable_notification`). At most 20 notices go out in
  any 60 seconds, for all clients together, because Telegram allows
  about 20 messages per minute in a group. A notice that could not be
  sent counts too. A use that would need one more notice is denied as
  for the limit per client in section 8: with cause `limit`, and it does
  not count for `max_per_day`, because no notice went out. So a burst of
  notices of other clients cannot use up the one use of a night. Any
  other failure to send a notice denies the use with cause `error` (code
  `approver_failed`), and the use still counts, because the core cannot
  tell if the notice went out. That holds for Telegram's own code 429
  after the last try too: an earlier try may have sent the notice.
- A notice about the version of a client (section 10) goes to the same
  chat, also silent and with link previews off. It does not count toward
  the 20 notices above, nor toward the 6 of a client in section 8, so a
  "never ask" use right after it still gets its notice. It has its own
  limit: at most 3 in any 60 seconds, for all clients together, so it
  takes little of what Telegram allows in the chat. Telegram counts all
  the messages of the chat, though. With up to 3 notices about versions
  in a minute, such as right after a start, about 18 notices of "never
  ask" uses already pass the about 20 that Telegram allows. Then
  Telegram can refuse a notice of a "never ask" use with its code 429.
  If the tries of that notice do not get through in time, the use is
  denied, as for any other failure of its notice. This needs about 18
  such uses in one minute, so it is rare.
- A notice about a newer release (above) goes to the same chat, also
  silent and with link previews off. It shares the limit of 3 in any 60
  seconds with the notices about versions, so it takes nothing from the
  notices of "never ask" uses either. The check for a newer release
  sends it on its own, so it never delays or denies a request. Each try
  is one call. A try that fails, also one that the limit stops, is
  logged, and the next check, 1 hour later, tries again (section 15). A
  try can fail after Telegram took the message, such as on a time-out;
  then the next try sends it again. Once a notice went out, that release
  gets no more. A try that is still being sent when the broker stops is
  cancelled (section 15, step 1 of the stop).
- The broker sends a notice about a version in the background, so it
  never delays or denies a request. A client has at most one try at a
  time, and each try is one call. A try that fails, also one that its
  limit of 3 stops, is logged. Then the next request of that client that
  comes at least 60 seconds after the failure makes a new try; there is
  no timer. Once a notice went out, that client gets no more tries in
  this start. A try can fail after Telegram took the message, such as on
  a time-out; then the next try sends it again. Such a repeated notice
  is rare and does no harm. A try that is still being sent when the
  service stops is cancelled (section 15, step 3 of the stop), and a try
  that fails while the broker stops says that no new try comes. So each
  client gets one such notice in each start, rarely more than one, and
  at most one try a minute.

## 8. Rules and grants

Each secret and each key has a rule:

| `ask` | meaning | buttons |
|---|---|---|
| `always` | Ask for every request. | Approve once · Deny |
| `window` | Ask; the approver may also allow the next N minutes. | Approve once · Approve N min · Deny |
| `never` | Do not ask. See [decision 3](#12-decision-3-unattended-runs). | none |

A rule may also have `preapprove = true`, for scheduled grants (below). It
is off by default, and the config check refuses it with `ask = "never"`.
A rule may have `standing = true` too, for standing grants (below).

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
- A grant ends N minutes after the tap. A message shows the time of the
  tap to the second, and cuts the part of a second, so the end is cut to
  the start of its second too, on both clocks: a tap at 14:02:41.7 gives
  a grant until 14:17:41.0. It starts only once the `decision` entry of the
  tap is on disk (section 9). If that entry cannot be written, the grant
  never starts.
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
- One limit applies to them: at most 6 notices of "never ask" uses and of
  scheduled uses (below) in any 60 seconds, for all secrets and keys of
  the client together. A use that
  would need one more notice is denied, without a notice, and does not
  count for `max_per_day`. Without this limit, one client could fill the
  phone with notices and use up Telegram's limits for the chat, so that
  messages for other clients could not be sent. A "never ask" rule with
  `notify = false` sends no notice and has no such limit. A use of a
  scheduled grant always sends a notice, and is denied in the same way.
  The Telegram
  code also sends at most 20 notices in any 60 seconds for all clients
  together (section 7). A use that this limit stops is denied in the same
  way: cause `limit`, and it does not count for `max_per_day`. A notice
  that the Telegram code refused, or could not send, still counts toward
  the 6 of its client, so a client cannot try again and again within the
  minute. A notice about the version of a client (section 7) counts
  toward neither of these limits.

### The grant core

All grants share one record and one end path. A grant has a **kind**:

| kind | what it is | audit kind |
|---|---|---|
| window | "Approve N min" (above): from a tap on a request, for minutes | none |
| scheduled | a pre-approval, one time span, N uses (below) | `preapprove` |
| standing | a pre-approval with daily or weekly windows, for weeks (below) | `standing` |

A later fourth kind is planned in issue 103, step 9: a one-use
pre-approval of a login. It would use the same record.

The record has the client, the scope, the end, the uses left, and, for a
standing grant, a list of windows and the uses in the current window. A
grant is **live** before its end and, if it has windows, inside one of
them. Every end goes through one path, with one cause, one `grant_ended`
entry and one edit of the message.

### Scheduled grants

A job that runs later, such as a timer at night, cannot tap a button. A
scheduled grant lets the person approve it ahead, while awake: **this
client may use these secrets, or this key, in this time, N times.** It is
not a "never ask" rule: it needs a tap, it starts and ends at fixed times,
and its uses are counted. It hands out nothing by itself.

**The request.** `nodkey preapprove` (section 15) sends `POST
/v1/preapprove` (section 10), with the kind `preapprove` in the audit
log. It names secrets (`--secret`, up to 32), or a key with a remote user
and hosts (`--key`, `--user`, `--host`, checked as for `nodkey
ssh-grant`, section 13), the first moment (`--from`), the end (`--until`),
the number of uses (`--uses`) and a claimed reason. A time is RFC 3339
with a UTC offset (`2026-10-28T03:00:00+02:00`), or without an offset
(`2026-10-28T03:00`), which the broker reads as its local time. The
seconds may be left out; a part of a second is refused. A local time that
the clock skips or shows twice on a day of a change to summer time is
refused too: give an offset. Times are absolute, so summer time does not
move a grant.

**What the broker checks, before any message.** It denies the request
(cause `not_allowed`, or `limit` for the last item) unless all of this is
true:

- Each secret, or the key, is in the config, allowed for the client, and
  its rule has `preapprove = true`. The rule is `always` or `window`; a
  `never` rule cannot have it. For a key, the user is valid and each host
  is in `known_hosts` and in the key's `hosts`, if it has them.
- The `window` of the rule does not cap a scheduled grant. Only the
  limits below do.
- `--from` is before `--until`, the end is in the future, and the start is
  at most `max_ahead` from now (a start in the past is fine).
- The grant is open at most `max_open`, from its start to its end.
- The uses are 1 to `max_uses`.
- The client has fewer than `max_grants` scheduled grants: those that are
  approved and not ended, plus the requests that wait for a tap.

These limits are in `[preapprove]` (section 14). They have safe defaults:
`max_ahead` 7 days, `max_open` 8 hours, `max_uses` 10 and `max_grants` 5.
A config made without them allows no scheduled grant.

**The message** has the buttons **Approve** and **Deny** (section 7). It
shows the secrets, or the key, hosts and remote user, the uses, and the
start and the end in the broker's local time, with the date and the zone.
The reason is claimed:

```
🗓 Pre-approval · request m4k2
✅ machine: laptop
✅ secrets: backup-token
✅ uses: 1
✅ from: 2026-10-28 03:00:00 UTC
✅ until: 2026-10-28 04:00:00 UTC
— claimed by the agent —
reason: job nightly-backup
expires 14:07:00 (120 s)
[ Approve ] [ Deny ]
```

The request waits like any other, but never past the end of the grant.
The decision is `approve_once` or `deny` in the audit log. A tap at any
time before the end is good.

**What the broker keeps.** After **Approve**, one record in memory: an ID
(16 random bytes, as a request ID), the client, the scope, the start, the
end, the uses left, and the request it came from. The scope is a set of
secrets, or one key with the host keys of the listed hosts and one remote
user. The grant starts only after its `decision` entry is on disk, and not
if the client hung up, as for `nodkey ssh-grant`. The client gets the ID,
and the start and the end. A client has no way to read the grants.

**A grant that nobody can hold.** The broker looks once more at the
client after the grant started. If the client has hung up, or the answer
cannot be written or flushed, the broker cancels the grant at once and
writes `grant_ended` with cause `cancelled`. In the audit log this looks
the same as a `--cancel` of the client. If the approver stopped after the
tap and before the grant started, no grant starts, and the request ends
with an `error` entry (code `approver_failed`) and a `denied` entry with
cause `error`, answer 503. One window remains, as for `nodkey
ssh-grant` (section 13): the broker has started the grant and written the
answer, but the client does not read it, because a signal came, the
connection broke after the flush, or the wait ran out. Then the client has
no ID. After the short code was printed, it says for any such failure
(not for a final answer other than 200, such as a Deny; but also for a
200 whose answer cannot be read or is not valid) that a grant may have
started, and names the short code. The ID is in the audit log, in
the `grant_id` of the entries of the request whose message shows that
code. The person cancels the grant with
`nodkey preapprove --cancel ID`. If the whole answer was read before the
signal, and its ID is valid, the client cancels the grant itself. The flush of the answer is
done with `http.ResponseController`; a server that cannot flush is taken
as having written it.

**Use.** A request of the same client, inside `[start, end)`, takes one
use without a tap when one grant covers it fully:

- For secrets, every secret of the request is in the scope. A run with
  some of the secrets takes one use. One tap makes one grant for all the
  listed secrets, with one counter. A run that asks for any secret
  outside that grant is not covered by it at all: the whole request gets
  the normal approval. A scheduled grant is never mixed with a grant of
  "Approve N min" or a "never ask" rule in one request.
- For a key, each SSH login (each signature) takes one use, for a listed
  host (any of its host keys) and the remote user. `ssh` opens one
  connection for each login, unless it shares one (`ControlPersist`), so a
  tool with many connections needs more uses.
- Each use writes `grant_used` with `via` = `scheduled` and sends the
  silent notice, as a "never ask" use does (section 12). These notices
  count toward the limits of 6 for a client and 20 in all, in any 60
  seconds. If the notice cannot be sent, the use is denied. A use that a
  limit stops is not taken, as for a "never ask" rule. Any other failure
  of the notice keeps the use counted.
- The start is read on the wall clock. The end has come when either clock
  reaches it, as for other grants (section 8, above): a wall clock that
  is set back cannot make a grant last longer, and a host that slept
  cannot either. A grant is never used at or after its end.
- The uses already made still count when the wall clock is set back. The
  count is a plain counter; nothing resets it.

**End.** A grant ends when its uses reach 0, when its end time comes, when
the client cancels it, when a later Deny covers it, or when the broker
stops. Each end writes one `grant_ended` entry with the cause (`used_up`,
`ended`, `cancelled`, `denied`, `revoked` or `stopped`) and the uses left. A timer
ends a grant at its end time; a request never finds a grant that is past
its end.

- **Cancel by the client.** `nodkey preapprove --cancel ID` ends a grant
  at once, without a tap, because a cancel only takes a right away. Only
  the client that holds the grant may cancel it. An unknown ID, an ended
  grant and the ID of another client all get the same answer (403), so a
  client cannot test for the grants of others.
- **A later Deny.** A Deny for the same client and any secret or key of a
  grant ends it, also before its start (as the Deny of a grant of "Approve
  N min" does, above). A Deny that comes after the tap but before the
  grant starts stops it from starting; the message then keeps the
  approval line, as for every grant that did not start. The message of a
  grant that started says "ended by a later Deny", and the Revoke button
  goes.
- **Revoke on the phone.** After the grant started, its message has one
  **Revoke** button (section 7). A tap on it ends the grant at once, with
  cause `revoked`, through the same end path as the other causes, and the
  phone shows "Revoked." The tap counts only if the checks of section 7
  pass (a changed message does not matter for a Revoke), and then only if
  the grant is still open and the tap is on its own message. Any other Revoke changes nothing: the phone shows "This
  request has ended." (the grant is gone: ended, used up, cancelled or
  denied), "This button does not count." (the message is not the
  grant's); each
  is a `foreign_tap` entry with its cause (section 9), as for the other
  buttons. A Revoke only takes a right away, so a forged or replayed one
  can only end a grant; the data is still bound to the request ID and to
  the message, so it cannot name another grant. The grant can be revoked
  before its start too.
- **The message at the end.** At every end (`used_up`, `ended`,
  `cancelled`, `denied`, `revoked`, `stopped`) the broker edits the
  message of the grant: no button, and a line that says how and when it
  ended, with the uses left. The edits of one grant run one after the
  other, in the order of the events, in a goroutine of the core, so a
  slow Telegram never delays a request. A failed edit is logged; the
  audit log has the end anyway. The edit that adds the Revoke button is
  tried again after 10 and 20 seconds, while the grant lives (3 tries in
  all). A Revoke tap on a message whose request still waits is refused as a
  changed message, with the alert: such a message has no Revoke button.
- **Not used.** A grant that reaches its end time with uses left (cause
  `ended`, `uses_left` above 0) sends one silent notice to the notice chat
  (section 7). It does not count toward the limit of 6 per client, because
  no request caused it, but it obeys the limit of 20 in all in any 60
  seconds of the Telegram code (the limit of the notices of uses). A
  grant that was used up, cancelled, revoked, denied or dropped by a stop
  sends none. If the notice is over the limit or cannot be sent, the
  broker logs it. Nothing else changes: the `grant_ended` entry is
  written before.
- **A restart** drops all grants, as for every other grant. At a stop,
  the broker writes `grant_ended` with cause `stopped` for each grant that
  is open, edits their messages, and sends one **stop notice** (section
  15, step 2 of the stop). It lists each dropped grant: its ID, the
  client, the secrets or the key, and the uses left, in at most 20 lines.
  It is one `Inform` call to the notice chat, without a sound, with its
  own count (3 in any 60 seconds). It has a time limit of 5 seconds, so a
  stop never waits for a Telegram that does not answer. With no scheduled
  grant, nothing is sent.

**Answers to the open questions of issue 108.**

1. A broker restart drops the scheduled grants, so a job asks as usual.
   One notice lists the dropped grants (above). Keeping them across a
   restart is planned (issue 111).
2. Several secrets in one run: one tap makes one grant for all of them,
   as above. A run that asks for a secret outside it is not covered.
3. Cancel by the client: yes, as above.
4. The clock set back: the uses already made still count.
5. A later Deny cancels a scheduled grant, and the message of the grant
   says so (above).
6. The `window` of a rule does not cap a scheduled grant. Only the
   limits of `[preapprove]` do.

**The honest limit.** With the client as the only identity, anything on
that client can use the grant inside its time. This is decision 3 B
(section 12) again, but smaller: it needs a tap and not a config edit, it
ends by itself, and its uses are counted. If something else uses it up,
the real job fails, and that is a visible sign. The reason is claimed:
the person cannot check that "job nightly-backup" exists. A tap means
"this client may use this secret in this time", nothing more.

### Standing grants

A scheduled grant covers one time span. A job that runs every night for
weeks would need a tap each day. A standing grant lets the person approve
it once: **this client may use these secrets in these daily or weekly
windows, N times in each window, until this date.** It needs a tap, and it
is bound to a token that changes at each use. Secrets only; SSH keys are
planned for later.

**The request.** The same command and the same endpoint as a scheduled
grant, with the audit kind `standing`. `nodkey preapprove` takes one of
`--daily 03:00-05:00` or `--weekly mon,thu 03:00-05:00` (section 15), for
at most 7 windows. With one of them, `--until` is a must, `--uses` means
the uses in each window (default 1), and `--from` is optional (default:
now). A window does not pass midnight and is not longer than `max_window`.
Windows are in broker local time, with the summer-time rules of `hours`
(section 12): a window that opens twice on the day the clocks go back
still has one count, and a window in the skipped hour does not open. To
avoid this, run the broker in UTC.

**The rule.** A rule may have `standing = true`, off by default, only for
`always` and `window` rules. It is a flag apart from `preapprove`, because
a standing grant is a much wider right: one flag for both would widen every
config that has `preapprove = true`. The same checks as for a scheduled
grant run before any message (known secrets, allowed for the client, count
of grants), with the limits of `[standing]` (section 14):

| key | default | ceiling |
|---|---|---|
| `max_days` (from now to the end) | 90 | 366 |
| `max_window` (one window) | 8 h | 8 h |
| `max_uses` (per window) | 1 | 10 |
| `max_grants` (per client) | 3 | 20 |
| `warn_days` (warning before the end) | 7 | none |
| `summary` (weekly list, local time) | `"mon 09:00"` | none |

A config without `[standing]` allows no standing grant. The message is
that of a scheduled grant, with the windows, the uses per window and the
end date, and the buttons **Approve** and **Deny**. It says that a Deny of
other requests does not end the grant. The reason is the claimed job name.
For `nodkey preapprove --secret backup-token --daily 03:00-05:00 --until 2026-12-31 --reason "job nightly-backup"` it
is:

```
🗓 Standing grant · request m4k2
✅ machine: laptop
✅ secrets: backup-token
✅ window: daily 03:00-05:00
✅ uses in each window: 1
✅ from: 2026-10-28 03:00:00 UTC
✅ until: 2026-12-31 00:00:00 UTC
A Deny of other requests does not end this grant. Use Revoke to end it.
— claimed by the agent —
reason: job nightly-backup
expires 14:07:00 (120 s)
[ Approve ] [ Deny ]
```

The broker denies the request before any message when `[standing]` is
missing, when a secret has no `standing = true`, when the end is not set
or is more than `max_days` away, when a window is longer than
`max_window`, when the uses in a window are more than `max_uses`, when the
client already has `max_grants` live standing grants, or when a window is
not valid. Windows must not overlap. After **Approve** the broker makes the token and keeps its
hash only (`grant_id`, the windows and the uses in each window go with
it). The audit entry of the decision has the kind `standing`, with
`not_before`, `not_after`, `windows` and `uses`.

**The token.** After the tap, the broker makes a token: `nkg_`, 32 random
bytes in base62, and a CRC32 checksum, as GitHub does. The broker keeps
only its SHA-256 hash. The token is in the answer to `nodkey preapprove`
once, and nowhere else. The client writes it to the file of `--grant-token
FILE` and never prints it. It works only with the TLS key of its client.
The client refuses a token file that is not its own, or that other users
can read or write (mode 0600 at most).

**Use and rotation.** `nodkey run --grant-token FILE` sends the token in
the header `Nodkey-Grant-Token`. The broker, in this order:

1. Checks the hash and the client, that the grant covers the whole
   request, that now is inside a window, and that a use is left in it.
2. Makes a new token and writes `grant_used` (`via` = `standing`, with the
   hash of the new token) to disk.
3. Sends the silent notice, which counts toward the limits of 6 per client
   and 20 in all (as in a scheduled grant).
4. Answers with the secrets and the new token.

The client writes the new token to a temp file, syncs it, and renames it
over the old file. Only then does it use the secrets. If the write
fails, it does not run the command. It never retries a request that had a
token by itself. For each use, the broker keeps one 32-byte hash until the
grant ends, to know the old tokens.

**Alarms.** An alarm is a Telegram message with sound, and a `grant_alarm`
entry with a cause. It counts toward the limit of 20 notices in all. One
grant sends at most one alarm in a window. For a valid token outside the
windows (also before the start of the grant), the limit is one alarm in a
calendar day. The day counts only when the alarm was sent: after a failed
send, the next request tries again.

| case | request | grant | cause |
|---|---|---|---|
| an old token | denied | **ends** (`alarm`) | `old_token` |
| more uses in a window than allowed | denied | **ends** (`alarm`) | `over_uses` |
| a valid token outside the windows | denied | stays | `outside_window` |
| a token of another client's grant, current or old | denied | **ends that grant** (`alarm`) | `old_token`, with the ID of that grant; the message names the machine of that grant |
| an unknown token | denied | none | `unknown_token` (rate limited) |
| a window ended with no use | none | stays | `missed_window` |

An old token is taken as stolen. A retry after a lost answer looks the
same, and the broker cannot tell them apart. There is no pause and no
Resume: a new grant is one tap. A request without a token goes the
normal way, with a tap.

**On the phone.** The message of the grant has a **Revoke** button, as in
a scheduled grant. Within `warn_days` of the end, a warning comes with a
**Renew** button. The warning is sent `warn_days` before the end (default
7), once per grant, to the private chat with the approver, with sound. A
grant that is not longer than `warn_days` gets no warning. A warning that
cannot be sent is logged and not sent again. A tap on Renew, after the
full checks of section 7 (as for an Approve: the approver, the private
chat, the button data, the warning message as the broker sent it, and in
the core the grant of the request ID with this very warning), makes a new
grant: a new ID, a new request ID, a new end (the same length as the old
grant, counted from now, and not more than `max_days`), and the same
scope. The new grant takes the place of the old one: the two count as one
for `max_grants`, and a grant can be renewed once. Its `decision` entry,
with answer `renew` and `renew_of` (the old grant's ID), is on disk
before the new grant exists; if it cannot be written, the Renew does not
count. The warning message then becomes the message of the new grant, with
its Revoke button. The new grant has no token. The next use of the old
token gets the token of the new grant, and the old grant ends with cause
`renewed`. If the old grant reaches its end first, it ends with cause
`renewed` then, and its token passes to the new grant. The old tokens pass
too, so an old token is still an alarm. If the old grant ends in another
way before that (Revoke, an alarm, a cancel, a stop), the new grant ends
with it, with the same cause: it has no token of its own. Until the
handover, the list and `/grants` show the old grant only. Once a week (`summary`, broker local
time) a message lists each standing grant: the client, the secrets, the
windows, the last use and the end date. The bot command `/grants` from the
approver shows the same list. The list never shows a token or a hash.
With no standing grant, the weekly message says so, and `/grants` does too.
For `/grants` the bot also asks Telegram for `message` updates. Only the
text `/grants` (or `/grants@` and a name) from the approver in the
private chat with the approver gets an answer, at most 3 in a minute. A message from anyone or anywhere
else is ignored without an answer.

**Missed window.** When a window of a live grant ends with no use in it,
the broker sends the alarm `missed_window`. The grant stays. A window that
ended before the grant started does not count. A window in the hour that a
clock change skips does not open, so it also gives this alarm. Each grant
sends at most one alarm in a window. If the wall clock jumps ahead over
many windows, the grant sends one alarm for all of them.

**End.** A standing grant ends when its end date comes, on Revoke, on an
alarm that ends it, on a renewal, on a cancel by its own client (`nodkey
preapprove --cancel`, or the broker, when the answer with the token cannot
be written; cause `cancelled`), or at a broker stop. A **Deny** of
another request of the same client and secret does **not** end it: an
"Approve once" Deny at noon must not break the night job. The Deny message
says "standing grants stay; use Revoke to end them". At a stop the grants
are dropped, written as `stopped`, and listed in the stop notice. Keeping
them is issue 111.

**The honest limit.** The token finds a theft; it does not stop it. The
same user on the client can read and rewrite the token file, so a thief
can use the grant first. The real job then finds an old token and fails,
and the alarm comes. Run the job as its own system user (see
`docs/setup.md`). See T36 in THREAT-MODEL.md.

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
  `grant_ended`, `grant_alarm`, `secret_sent`, `signed`, `denied`, `foreign_tap`, `error`,
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
  request is denied until the broker starts again. The broker denies them
  at once, before any message (503), and sends one alert message. The file
  may now end in a torn line, and the broker records it at the next start
  (below).
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
| `decision` | the request fields; `user_id`: the Telegram user that answered; `answer`: `approve_once`, `approve_window`, `deny` or `renew`; `window_minutes` for `approve_window`; for `renew`, the fields of the new standing grant (a new `request_id` and `grant_id`, `not_before` the time of the tap) and `renew_of`, the ID of the grant it renews |
| `grant_used` | the request fields; `via`: `grant`, `never_rule`, `scheduled` or `standing` (then `grant_id` is in the request fields); for `standing` also `new_token_hash` |
| `grant_ended` | the request fields of the `preapprove` request that made the grant, with its `grant_id`; `cause`: `used_up`, `ended`, `cancelled`, `denied`, `revoked`, `stopped`, `alarm` or `renewed`; `uses_left` |
| `grant_alarm` | the request fields; `grant_id` (none for an unknown token); `cause`: `old_token`, `over_uses`, `outside_window`, `unknown_token` or `missed_window` |
| `secret_sent`, `signed` | the request fields |
| `denied` | the request fields; `cause`: `approver`, `expired`, `cancelled`, `not_allowed`, `limit` or `error` |
| `foreign_tap` | `user_id`, `chat_id`, `message_id`, `data`: the button data, at most 64 bytes, and `cause`: why it did not count (section 7). An entry with cause `edited_message` can belong to a Deny that counted: its `data` is `d:` and the request ID, and that request has a `decision` entry with `deny` |
| `error` | the request fields, if the failure is about one request; `code`: `store_failed`, `sign_failed`, `approver_failed` or `poll_conflict` |
| `log_recovered` | `torn_length` and `torn_sha256`: the length and the SHA-256 of the torn line |

The request fields are `request_id`, `client`, `kind` (`secrets`,
`ssh_login`, `ssh_grant`, `preapprove` or `standing`), `secrets`, `key`, `hosts`,
`host_key` (a SHA256 fingerprint), `remote_user`, and the claimed
`command` and `reason`. A `preapprove` request that was approved also has
`grant_id`, `uses`, `not_before` and `not_after` (UTC, RFC 3339). A
`standing` request that was approved also has `windows` (such as
`daily 03:00-05:00`), and its `uses` are the uses in each window; the
entries of a use and of an end have `grant_id`.

The broker writes `broker_started` when it has passed every check of its
start, just before it starts to poll Telegram and to take requests
(section 15). So it comes before every entry of that run, except a
`log_recovered` entry. It writes `broker_stopped` as the last entry of a
stop in order. A crash, a kill or a power cut leaves no
`broker_stopped`. A start that fails writes neither.

For each request, the broker writes its entries in this order. First
`request`. Then one of these: `decision` (and `denied` with cause
`approver` after a Deny); `grant_used`; or `denied` (with an `error` entry
before it when the cause is `error`). After an approval, `secret_sent` or
`signed` follows: the broker writes it just before the answer with the
values or the signature, and sends nothing if it cannot write it. If a
later step fails after the approval, such as a store or the signature, an
`error` entry and a `denied` entry with cause `error` follow instead. If
the client hangs up after the approval, before anything was handed out, a
`denied` entry with cause `cancelled` follows. An approved SSH grant hands
out nothing, so it ends with its `decision`, unless its client hung up
before the grants started: then a `denied` entry with cause `cancelled`
follows, and no grant starts (section 13). When grants and a "never ask"
rule allow one request together, it gets two `grant_used` entries, one for
each, and each lists the secrets it covered. A scheduled grant (section 8)
never joins them. An approved `preapprove` request hands out nothing, so it ends with its
`decision`, unless the broker cancels the grant it started because the
client hung up or the answer failed: then `grant_ended` with cause
`cancelled` follows. It can also end with `denied` and cause `cancelled`
(the client hung up before the grant started) or `limit` (the end came,
a Deny came, or the client has too many grants), or, if the approver
stopped, with `error` and `denied` with cause `error`. The `grant_ended` entry of a
grant comes when the grant ends. If a request ended it (the last use, or
a Deny), the entry comes after the entries of that request that the
approval writes (`request`, `decision`, `grant_used`, `denied`), and
before `secret_sent` or `signed`, which the broker writes later. It names
the request that made the grant, not the request that ended it. A Revoke
tap that counts writes only this entry, with cause `revoked`, and no
`decision` entry: the cause says who ended the grant, because only the
approver's tap can do it, and the tap passed the same checks as every
answer. A Revoke that does not count writes a `foreign_tap` entry, as for
the other buttons.

A request that the broker denies before the approval core sees it gets a
request ID from the broker, in the same form, and the entries `request`
and `denied`: with cause `not_allowed` for a body that is not a valid
request or a check of section 5 or 6 that failed; with cause `limit` when
the client has too many requests in progress, or waited too long for a
place to read its body (section 10); and with cause `error`, after an
`error` entry with code `approver_failed`, when the approver has stopped
(section 7). So does a request that panics before the core has given it
an ID: with cause `not_allowed` when the panic came before the core, and
with cause `error`, after an `error` entry with code `approver_failed`,
when it came inside the core, such as in the approver. A list of keys
(`/v1/keys`) is not a request for a secret or a signature, so it has no
entry.

A client can send requests that a limit denies, or that come after the
approver stopped, as fast as it wants: they cost it nothing. So the broker
writes the entries of at most 20 such requests of one client in a minute,
and only counts the others; the count goes to its log. Every other
request has its entries.

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
  a torn line. When that entry is the last one, the next start takes it
  as a torn line that a start before recorded, and sends one alert (see
  "A torn last line" below). But when more entries are appended after it,
  nothing alerts at the start. The anchor of that last real entry then
  does not match, so check with every anchor.
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
The alert goes out only once the start has written `broker_started`
(section 15). If that start stops before, such as when its listen address
is not there yet, the log ends in the `log_recovered` entry. The next
start finds it as the last entry, and sends the alert then. When Telegram
cannot be reached yet, the broker tries the alert again until it is out,
or until the broker stops.

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
  The client shows it as `the broker answered 503 Service Unavailable`. For
  `503` it adds a fixed hint: `; the broker could not finish the request;
  its journal says why (journalctl -u nodkey)`. This text is fixed in the
  client: it holds nothing that the broker sent.
- If a handler panics, the broker logs where (function, file and line),
  but not the panic value, and drops the connection. The value could hold
  anything from the request.
- The client connects only to the `broker` address in its config, never
  through a proxy (it ignores `HTTPS_PROXY`). It follows no redirects.
- The client sends each request once, on a connection of its own, with
  `Connection: close`. No other request goes on that connection, so there
  is no pipelining, and a request is never sent again. Each request has a
  deadline, and no other time limit on the wait for the person
  (section 5). The client takes at most 4 informational answers for one
  request, and only a final `200` with a valid answer counts.

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
  and 2 text fields (the working directory and the reason): at most
  1,191,941 bytes. All other fields of a request, such as names, keys and
  the data to sign, must fit in 64 KiB. So every valid request is at most
  2,080,774 bytes.

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

**The API.** Every request is a `POST` with a JSON object as its body, on
one of these paths. The broker compares the method and the request target
exactly, so another method gets 405, and another path, another spelling of
a path, a query, `OPTIONS *` or `PRI *` gets 404. The types are in
`internal/api`.

| path | client | request fields | answer fields |
|---|---|---|---|
| `/v1/keys` | `ssh-agent` | none: `{}` | `keys`: each with `name` and `public_key` (SSH wire form), sorted by name |
| `/v1/secrets` | `run` | `secrets` (each with `var` and `name`), `command`, `dir`, `reason` | `secrets`: each with `var` and `value`, in the order of the request |
| `/v1/sign` | `ssh-agent` | `public_key`, `data`, `flags`, `binds`, `commands`, `reason` | `format` and `blob` of the signature |
| `/v1/ssh-grant` | `ssh-grant` | `key`, `user`, `hosts`, `seconds` (`--for`), `reason` | `minutes`: how long the grants last |
| `/v1/preapprove` | `preapprove` | `secrets`, `key`, `user`, `hosts`, `from`, `until` (texts, read by the broker), `uses`, `reason`; for a standing grant also `windows` (list of day names and `HH:MM-HH:MM`) | `id` of the grant, `from` and `until` in RFC 3339, in the broker's local time; for a standing grant also `grant_token` |
| `/v1/preapprove/cancel` | `preapprove --cancel` | `id` | `id`; 403 for an ID that the client does not have |

- Each field must be there, none may be `null`, and no other field may be
  there, on both sides. Bytes, such as a key or a value, are in base64. A
  list is never `null`: an empty list is `[]`.
- When a request starts to wait for the person, in the queue or with a
  message, the broker first sends an informational answer:
  `102 Processing`, with the short code in the header `Nodkey-Short-Code`.
  It writes it with a deadline of 5 seconds, so a client that does not
  read cannot hold the request. The client prints the code (section 5).
  The final answer comes after the wait.
- The final answer is `200` with the answer fields, or an error status with
  only `{"error":"<status text>"}`:
  - `400`: the body is not a valid request, or it is over a cap. (`413` and
    `415` come from the checks of the body above.)
  - `403`: denied by the person, by a check or by a rule, or because
    nobody answered in time, or the client hung up.
  - `429`: denied by a limit: the limits per client of section 8, the
    limits of notices of "never ask" uses (sections 7 and 8), more than
    32 requests of this client in progress, or a wait of more than
    10 seconds for a place to read the body.
  - `503`: the broker could not finish: the approver, a store, the
    signature or the audit log failed, or the broker is starting or
    stopping. A request that is still in progress when the broker stops
    gets `503` too, also when the audit log says `cancelled`: the client
    did not get a deny.
- More caps, besides those above: at most 32 variables in a request; each
  name (of a variable, a secret, a key, a host or a remote user) at most 64
  bytes; a public key at most 4 KiB; the data to sign and each
  session-bind at most 8 KiB; at most 2 session-binds; at most 20 hosts in
  an SSH grant (a host listed twice counts twice here). The answer is at
  most 2 MiB: each value is at most 64 KiB, and the values of one request
  at most 1 MiB together (section 5).
- The broker works on at most 32 requests of one client at a time. More get
  `429` at once (THREAT-MODEL.md T28).
- The broker reads and decodes at most 4 bodies of one client, and at most
  16 in all, at the same time: the largest valid body takes about 20 MiB
  for a moment. Another request waits for a place, at most 10 seconds,
  and then gets `429`.

**Versions.** The JSON is strict on both sides, so a client and a broker
of different versions can fail with only "the answer of the broker is not
valid", or a `400`. So each side tells the other its version, and says
when they differ.

- `/v1/secrets` may have the header `Nodkey-Grant-Token` with the token of a
  standing grant (section 8). The answer then also has `grant_token`, the
  new token. Without the header, the request goes the normal way.
- Each request has the header `Nodkey-Version` with the client's version,
  as `nodkey version` prints it, such as `0.2.0` or `dev`. Each answer of
  the broker has it with the broker's version: with every status, also
  errors, `404`, `405` and the `102`. It is a header, not a JSON field,
  so versions with other fields still read it. Two kinds of answers come
  before the broker's code, and have no such header: the answers that
  net/http writes itself to a request that is not valid HTTP, such as
  headers over the limit, and the `403` for a request without a stored
  client name (above). The client never causes them.
- A side takes the other side's value only when it is one header that
  matches `^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`, the rule of the `version`
  of the `broker_started` entry (section 9). Any other value counts as no
  version, and is never printed or logged. A side whose own version does
  not match sends none.
- Only release versions are compared, as numbers: `X.Y.Z`, with numbers
  from 0 to 999999 and no leading zeros. Any other version, such as
  `dev`, a commit or `1.2.0-rc.1`, is a build from the source: when either
  side is one, neither side says anything.
- Each answer to a client that claims a release older than the newest
  security release that the broker knows has the header
  `Nodkey-Security-Update` with that release version. Other answers do
  not have it. The header comes from GitHub's answer and is not checked.
  The client takes it only when it is one header with a value that is a
  release version and newer than its own version. Anything else is
  ignored and never printed. Then the client prints one fixed line on
  stderr, once in each process. A client with an unknown version (`dev`)
  sends no claim to compare, so it gets no header:

  ```
  SECURITY UPDATE: nodkey 0.3.1 fixes a security problem. This is nodkey 0.2.0. Ask the owner of the broker host to update this host: run nodkey update as root.
  ```

- The client's version is a claim: anyone with the client's key can send
  any value (THREAT-MODEL.md T33). It changes no answer, no check and no
  audit entry, and the request never waits for what the broker does with
  it.
- The client compares after each final answer, whatever its status. When
  the two releases differ, or the client is a release and the broker
  sends no valid version, it prints one warning on stderr, before its
  last line or before the command starts. The line says which side is
  older, and what to do there, for example:

  ```
  nodkey: warning: the broker runs nodkey 0.2.0, which is older than nodkey 0.3.0 on this machine; to update the broker, run "nodkey update" as root on the broker host
  nodkey: warning: this machine runs nodkey 0.2.0, which is older than nodkey 0.3.0 on the broker; to update this machine, run "nodkey update" as root
  nodkey: warning: the broker runs an older nodkey that does not send its version, and this machine runs nodkey 0.3.0; to update the broker, follow section 13 of docs/setup.md
  ```

  Only a side that sends its version has `nodkey update`. A broker that
  sends none runs nodkey 0.1, so the last line points to the update steps
  of [docs/setup.md](docs/setup.md#a-new-version-of-nodkey) instead.
  The line holds only fixed text and release versions. It goes only to
  stderr, never into the environment or the output of the command.
  `nodkey run` and `nodkey ssh-grant` send one request, so they print it
  at most once. `nodkey ssh-agent` prints it once for each version that
  the broker sends, so an update of the broker gives one more line, and
  it stops after 16 lines.
- The broker compares when the TLS key has given the client's name. When
  the client's release is not the broker's, or the client sends no valid
  version while the broker is a release, the broker writes one line in
  the journal, once for each client in each start of the broker, however
  many versions the client claims. The line names the client, the
  client's release when it sent one, and the broker's version. It also
  sends one notice (section 7). A try of the notice that fails is tried
  again with a later request of the client, at least 60 seconds later,
  until one goes out. The request waits for neither.

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
- The broker logs at most 60 lines per minute in each of three parts:
  lines that any peer can cause, such as a refused handshake; lines with
  the pin of a key that no client has, which any peer can cause too, with
  a new key each time; and lines about the requests of the clients: a
  refused request and a handler that panicked. So other peers cannot crowd
  out the lines about the clients. When it drops lines, it says how many:
  in its next line, or at the end of the minute when no line comes.
- The broker's own lines come from slog's text handler: each line starts
  with `time=`, and a value with a line break is quoted and escaped. The
  broker never logs claimed text, except the version that a client claims
  when it is a release version, which is only digits and dots (see
  "Versions" above), and cuts each value to 1 KiB. So no line
  can start with `audit anchor ` (section 9), and none comes near the
  48 KiB at which journald splits a line. It logs at most 20 requests in
  a minute that a check refused, SSH logins (section 6) and variables on
  the deny list (section 5), and counts the others.

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
not give them. The broker reads them from `$CREDENTIALS_DIRECTORY` at start:
the config names each one as `${CREDENTIALS_DIRECTORY}/NAME` (section 14),
and the example unit (section 16) has a line for each.
An SSH key stored this way needs no passphrase; the broker refuses a key
with a passphrase.
- Without a TPM2 chip, encrypt with `--with-key=host` instead. Then anyone
  with a full copy of the disk can open them. The setup guide says this
  plainly ([docs/setup.md](docs/setup.md#encrypted-credentials)).
- Plain files (mode `0600`, owned by the broker user) also work, for tests
  and for machines without systemd. The broker refuses to start if a key or
  secret file can be read by group or others.
- Root on the running broker host can still get everything. That is the
  trust we place in the broker host.
- The keys and tokens are in the broker's memory, and secret values are
  there for a moment. Swap and hibernation write memory to disk, where a
  copy of the disk can give them. So use encrypted swap or none, and no
  hibernation, on the broker host. The example unit lets the broker use
  no swap (`MemorySwapMax=0`, `MemoryZSwapMax=0`).

**The `bw` master password.** The Bitwarden Password Manager CLI must be
unlocked with the account's master password. An API key alone is not
enough. To restart on its own, the broker must keep that password, so
anyone who breaks into the broker host gets the whole vault. So nodkey
supports `bw` only with a separate Bitwarden account that holds nothing but
the items nodkey may hand out. Bitwarden Secrets Manager (`bws`) does not
have these problems: its machine-account token can see only the projects
you give it. For both stores, some Bitwarden accounts can read the same
secrets in Bitwarden's own apps, without nodkey: for `bw` the separate
account, and for `bws` at least the owners and admins of the
organization. These accounts must never be logged in on an agent machine
(THREAT-MODEL.md T32).

How the broker uses `bw`:

- A person logs in once on the broker host, as the broker user, with the
  store's `program` and with the store's home directory (section 16) as
  `HOME` and as the working directory, for example:
  `sudo -u nodkey env -i -C /var/lib/nodkey/stores/vault HOME=/var/lib/nodkey/stores/vault PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/bw login --apikey`.
  For Bitwarden's EU cloud or your own server, run `bw config server URL`
  in the same way first. [docs/setup.md](docs/setup.md#bw-a-separate-bitwarden-account)
  has the steps.
- At start, the broker unlocks with
  `bw unlock --passwordfile FILE --raw --nointeraction`. bw reads the
  password file itself, so the password never passes through the broker,
  and it is never in an argument or a variable. Right before each unlock,
  the broker checks the file again as at start (section 14).
- bw prints a session key. The broker keeps it only in memory, and gives
  it to each later run of bw in the variable `BW_SESSION`.
- If bw is logged out, every request for that store is denied until a
  person logs in again. Each request tries to unlock again, so no restart
  is needed after the new login.
- If the session key stops working, for example because someone ran
  `bw lock` or `bw unlock` in the store's home directory, the request is
  denied. The broker forgets the key, and the next request unlocks again.
- Only one bw program runs at a time for one store. bw keeps the state of
  the account in one file, and each unlock ends the session key before it.
  A second request waits for its turn, or until it ends.

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
  (section 7). A use over that is denied with cause `limit`, and it does
  not count for `max_per_day`, because no message went out. A use whose
  message failed for another reason still counts, because the broker
  cannot tell if the message went out.
- Use a narrow secret: a secret that can do little, or a deploy key that
  can reach only one repository. For `bws`, the job's secret can live in its
  own project, read through its own store entry with its own machine
  account (see the two `bws` stores in section 14).

A standing grant (section 8) is the better form of this decision: it needs a
tap, it ends by itself, and its token finds a use by something else.

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
`--for`, in whole minutes, rounded down. The message shows it to the
second, so it is cut to the start of that second, on both clocks
(section 8): a request at 14:05:12.7 for 15 minutes gives grants until
14:20:12.0. A late tap does not move it. The message has only "Approve"
(until that time) and "Deny". It waits for an answer as long as a request
for secrets (`timeout`), because it is not an SSH login, but never past
the time the grants end: after that, an approval would grant nothing. One
tap makes a grant for each host key of each listed host (a host can have
one host key of each key type), exactly as in B.
Then the playbook runs without more taps. A host that is not in the list
still asks. A host that is listed twice counts once (but the list may have
at most 20 names, section 10). The client sends `--for` in seconds; the
broker rounds down to whole minutes. The broker refuses an `ssh-grant`
before any message when:
- the key is not in the broker config, or this client may not use it;
- the remote user name does not match the pattern in section 6;
- the key's rule is not `window`;
- `--for` is longer than the key's window, or shorter than one minute;
- a host is not in the broker's `known_hosts`, or not in the key's `hosts`
  list when it has one;
- it lists no host, or more than 20 hosts.

Each login under these grants still passes every check of section 6, and
gets its own audit entries (`request`, `grant_used`, `signed`). A Deny for
the key ends the grants at once (section 8).

The grants are all that an approval of `ssh-grant` gives. So when the
client hangs up after the tap, such as after `SIGINT`, the broker starts
no grant. It looks once more, after the `decision` entry is on disk and
just before it starts the grants. Then a `denied` entry with cause
`cancelled` follows, and the client says `cancelled`. One tiny window
remains: when the client stops so late that the broker does not see the
hang-up at that look, the grants start, but the client still says
`cancelled`. The audit log shows which case it was: a `decision` entry
without a `denied` entry after it means that the grants may have
started (a Deny for the key in between also leaves no `denied` entry,
and then no grant starts). The
message on the phone shows the approval in both cases. A Deny for the key
ends such grants.

The client checks its arguments first, to give a clear error, and exits
with 64 without a request: the key name and each host name follow the
name rule of section 14, the remote user name matches the pattern of
section 6, there are 1 to 20 hosts, each given once with its own
`--host`, and `--for` is a time in whole minutes, such as `15m` or `1h`,
from 1 minute to 8 hours, the longest window. The client cannot see the
key's rule, its window or the broker's `known_hosts`. The broker does not
rely on the client's checks: it makes its own checks, listed above. Two
checks of the client are no refusals on the broker: there, a host that is
listed twice counts once, and a time that is not whole minutes is rounded
down. The reason comes from `--reason`, or else from `NODKEY_REASON`, as
for `nodkey run`. The message shows it as claimed text. The client sends
no command line.

The client takes the answer as `nodkey run` does (sections 5 and 10). It
sends the request once, with a deadline of 15 minutes, and prints the
short code of the `102 Processing` answer. Only a final `200` that passes
the strict decoding counts. Its `minutes` is how long the grants last,
from the time of the request. The client takes it only from 1 to the
minutes of `--for`. Any other number is an error (69), and the client
does not print it. After an approval, the last line names the remote
user, the number of hosts, and the end of the grants on the clock of the
agent machine. It shows the end, not the minutes: after a late tap, less
time is left. For example:

```
nodkey: waiting for approval (request m4k2)
nodkey: SSH logins as deploy to 2 hosts allowed until 14:20 (exit 0)
```

That end is the time when the client sent the request, plus the minutes,
without the seconds. So, when the two clocks agree, it is not later than
the end that the message shows. Only the broker's clocks decide when the
grants end (section 16). The line also does not see a later Deny that
ends the grants.

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

[docs/setup.md](docs/setup.md#7-the-config-file) explains this config
part by part, and how to make the files that it names.

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

[updates]
check = true                        # optional; false: never ask GitHub for a newer release

[preapprove]                        # optional; the limits of scheduled grants (section 8)
max_ahead = "168h"                  # how far ahead a grant may start; default 7 days
max_open = "8h"                     # the longest time from start to end
max_uses = 10                       # the most uses of one grant
max_grants = 5                      # the most per client: approved, not ended, plus waiting

[standing]                          # optional; the limits of standing grants (section 8)
max_days = 90                       # from now to the end date; ceiling 366
max_window = "8h"                   # one window; ceiling 8h
max_uses = 1                        # per window; ceiling 10
max_grants = 3                      # per client; ceiling 20
warn_days = 7                       # warning before the end
summary = "mon 09:00"               # weekly list, broker local time

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
preapprove = true                   # optional; default false: `nodkey preapprove` may ask for it
standing = true                     # optional; default false: standing grants (only `always`, `window`)

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
is an unknown key. The error ends with `; this is nodkey VERSION, the key
may be from a newer release`. Each key must be below the header of its own section,
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
  start of a path are expanded; any other `$` is an error. A store's
  `program`, `token_file` and `password_file` must also be clean: no `//`,
  and no `.` or `..` parts.
- A secret's `id` is the item's UUID in the store, so `bw` never searches
  items by name. For `bws`, nodkey hands out the secret's value. For `bw`,
  the item must be a login item, and nodkey hands out its password. An
  item in the trash or in the archive is refused, because `bw` still
  returns such an item by its ID.
- `clients` and `hosts` list each name once. `notice_chat_id` is not 0.
  A `window` is 1 minute to 8 hours.
  `timeout` is 15 s to 10 min. `ssh_timeout` is 15 s to 110 s, below
  `sshd`'s `LoginGraceTime`.
- `preapprove` is `true` or `false`, and is not allowed with `ask =
  "never"`. In `[preapprove]`, `max_ahead` is 1 minute to 31 days,
  `max_open` is 1 minute to 24 hours, `max_uses` is 1 to 1000 and
  `max_grants` is 1 to 100. Each has the default of section 8.
- `standing` is `true` or `false`, and is not allowed with `ask =
  "never"`. In `[standing]`, `max_days` is 1 to 366, `max_window` is 1
  minute to 8 hours, `max_uses` is 1 to 10, `max_grants` is 1 to 20,
  `warn_days` is 1 or more, and `summary` is a day name and `HH:MM`.
  Each has the default of section 8.
- `max_per_day`, if present, is 1 or more. For no limit, leave it out.
  So `0` cannot mean "no uses" to a person and "no limit" to the broker.
- `check` in `[updates]` is `true` or `false`. Without it, and without
  `[updates]`, it is `true`: a release of the broker asks GitHub for a
  newer release (section 15). With `false`, the broker never asks.
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
- The `bws` token file is read once, at start; the broker keeps the token
  in memory. The `bw` password file is checked at start and again before
  each unlock, also that it holds 1 byte to 1 MiB; bw reads it itself
  (section 11).
- For a `bw` store, each directory in bw's `PATH` (section 16) must pass
  the same checks as the directories on the way to a key file, so that
  nobody else can put a program, such as `node`, there. A directory that
  is not there passes if the way to it passes. A `node` in one of those
  directories must pass the same checks as a store's `program`, also
  after its links, and so must every directory on the way to it: a bw
  script starts it, and it reads the master password and gets the session
  key. A `node` link whose target is missing is refused too. There must be
  no `bw-data` next to the store's `program`, next to the file that it
  links to, or next to `node` in one of those directories, also not after
  its links: bw would keep its state there, not in its home directory.
- Each store's program gets its own home directory, `NAME` in the store
  directory (section 16). The store directory is `stores` in the
  directory of `audit_log`, such as `/var/lib/nodkey/stores`. The broker
  makes the store directory and each home directory with mode `0700` if
  it is missing. If it is there, it must be a directory, not a symbolic
  link, owned by the broker user, with mode `0700`. The directories on
  the way must pass the same checks as those on the way to a key file.
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
a key file. It reads its config file as the broker reads its config file:
a regular file owned by the user or root, that group and others cannot
write to, below directories that pass the same checks. It may be a
symbolic link. `broker_pin` is the client's only trust in the broker, so
other users must not be able to change it.

## 15. Commands and exit codes

```
nodkey broker [--config FILE]
nodkey run [--secret VAR=NAME]... [--grant-token FILE] [--reason TEXT] -- COMMAND [ARGS...]
nodkey ssh-agent [--socket PATH]
nodkey ssh-grant --key NAME --user USER --host NAME... --for DURATION [--reason TEXT]
nodkey preapprove (--secret NAME... | --key NAME --user USER --host NAME...) --from TIME --until TIME --uses N [--reason TEXT]
nodkey preapprove --secret NAME... (--daily HH:MM-HH:MM | --weekly DAYS HH:MM-HH:MM) --until TIME [--from TIME] [--uses N] --grant-token FILE [--reason TEXT]
nodkey preapprove --cancel ID
nodkey keygen --out FILE
nodkey audit verify FILE [--anchor SEQ:HASH]... [--anchors FILE|-]
nodkey update [--version X.Y.Z] [--gh PATH] [--reinstall]
nodkey version [--offline]
nodkey --version [--offline]
nodkey help [COMMAND]
```

`nodkey --version` and `nodkey -version` do the same as `nodkey version`.
`nodkey help` prints the list of commands on stdout. `nodkey help
COMMAND` prints on stdout the same help as `nodkey COMMAND --help`. Both
exit with 0, with 64 on an unknown command or more than one argument,
and with 1 when they cannot write to stdout.

A usage error (exit 64) is one line on stderr, with no usage text:
`nodkey CMD: REASON; see "nodkey CMD --help" (exit 64)`. For nodkey itself
the line is `nodkey: REASON; see "nodkey --help" (exit 64)`. The reason is
fixed text, and it shows an argument of the user at most 64 bytes long,
quoted. `-h` or `--help` prints the usage and exits with 0.

`nodkey broker` runs the broker. The default config is
`/etc/nodkey/broker.toml`. Run it as its own user, from a systemd unit;
[contrib/systemd/nodkey.service](contrib/systemd/nodkey.service) is an
example (section 16), and [docs/setup.md](docs/setup.md) sets it up step
by step. It writes its log to stderr, which systemd keeps in
the journal, with the anchors of the audit log (section 9). All its
lines, also an error at start and a wrong argument, come from the logger
of section 10, so no line can look like an anchor.

It starts in this order. If a step fails, it stops there, and ends what
it started before.

1. It reads the config and checks the files that the config names
   (section 14).
2. It sets its soft and hard `RLIMIT_CORE` to 1 and marks itself not
   dumpable (section 16). If it cannot, it does not start.
3. It loads its TLS key, and each SSH key with the `hosts` of its
   section. It signs a fixed text with each SSH key and checks the
   signature. It refuses two `[key.*]` sections with the same public key.
4. It opens the audit log. Before this step it writes no entry. An alert
   about a torn last line (section 9) waits until step 9. So does the
   alert of an earlier start that recorded a torn line and stopped before
   step 8: the log then ends in its `log_recovered` entry.
5. It makes the store directory (section 14) and each store, then starts
   all stores at once, for at most 70 seconds. A store that does not
   start, such as a `bw` that cannot unlock, does not stop the broker:
   the broker denies the requests for its secrets until the store works
   (each request tries again), and the approver gets one alert for all
   such stores, at step 9.
6. It makes the broker's service, the Telegram approver (it reads the bot
   token) and the approval core. It checks the client pins.
7. It opens the `listen` address. Nothing reads from it yet: a client
   that connects waits. So an address that is not there yet, such as at
   boot before the private network is up, stops the start here: before
   any entry, any call to Telegram and any alert. systemd starts the
   broker again later, and no alert goes out each time.
8. It writes the `broker_started` entry. No later step of the start can
   fail.
9. It starts to poll Telegram, and sends the alerts that waited. It sends
   them at the same time, each on its own, so a slow try of one alert
   does not delay the others. They can reach the phone in any order.
   After a power cut, the host can be up before Telegram can be reached.
   So when an alert does not go out, the broker tries again: after 5
   seconds, then twice as long each time, at most 5 minutes, until the
   alert is out or the broker stops. Each alert has its own tries. Each
   failed try gets one log line, with the number of the alert, such as
   `alert=2` for the second one that waited.
10. It starts the check for a newer release, unless `[updates]` says
    `check = false` (section 14) or the broker is a build from the
    source. The log says whether it runs. The check runs on its own: it
    never delays the start or the stop, and never changes a request.
    - It waits 10 minutes, then asks GitHub, with the lookup of
      `nodkey version` (below), and then every 24 hours. After a failed
      lookup, or a notice that did not go out, it asks again after 1 hour
      instead. A broker that ends within 10 minutes of its start, such as
      one that systemd starts again and again after a failure, never
      asks GitHub, and sends no notice in each start.
    - When the newest release is newer than the broker's own version, it
      writes one line in the log, and sends one notice (section 7). A
      notice counts as sent only when Telegram took it. So in each
      start, each newer release gets one notice, rarely more than one. A
      release that is not newer than the broker, or than a release that
      got its notice, gets none: the notice never suggests a downgrade.
    - Each failed lookup and each failed try of the notice gets one line
      in the log, with a fixed reason, such as a rate limit of GitHub, a
      network error or an answer that is not valid. A lookup that fails
      sends no notice.
11. Only then does it read the connections on the `listen` address and
    take requests.

It stops on SIGTERM or SIGINT, also during the start, when the polling
stops for good (section 7), and when its server fails. It stops in this
order:

1. The check for a newer release: its wait, a lookup or a notice that
   is still running is cancelled, also the dial of a lookup. After this
   step, it sends no request and no notice.
2. The polling: the `getUpdates` call that waits is cancelled and its
   connection closed (section 7). From now on no answer counts: every
   request that waits for the person is denied. The scheduled grants are
   dropped, with their `grant_ended` entries and the edits of their
   messages (together at most 5 seconds). Then the broker sends the stop
   notice about them, if there are any (section 8), with a limit of 5
   seconds. The notice is sent after the polling stopped and before the
   service stops, so it never delays more than 10 seconds.
3. The service: new requests get `503`, and the requests in progress end
   and get `503` too (section 10). The broker waits for them, and writes
   the `foreign_tap` entries that still wait. A notice about the version
   of a client that is still being sent is cancelled (section 7).
4. The server: it closes the `listen` address and every connection.
5. The alerts of the start: each one gets its first try, also when the
   stop began right after the start, but no try again. The tries run at
   the same time, and a try takes at most 30 seconds. So they end at
   most 30 seconds after the stop began, however many alerts wait. An
   alert that did not go out is lost; the journal says so.
6. The stores: they clear their tokens and session keys.
7. The `broker_stopped` entry. Then the audit log is closed.

The stop takes at most 80 seconds. A request may need up to 30 seconds
to take its answer, and the alert about an audit log that cannot be
written up to 30 seconds more. The updates of the messages of scheduled
grants (5 seconds) and the stop notice (5 seconds) add up to 10 seconds
after the polling stopped. The tries of the alerts of the start run
at the same time as these steps, and end within 30 seconds. After 80
seconds the broker ends without the rest of the stop, and exits with 1.
The example unit gives it 90 seconds (`TimeoutStopSec=`); then systemd
kills it.

`nodkey broker` exits with:

| code | meaning |
|---|---|
| 0 | stopped by SIGTERM or SIGINT, and the stop was clean |
| 1 | any other end: the start failed, the polling stopped for another reason (such as another refusal of `getUpdates` than 401, 404 or 409), the server failed, or the stop was not clean, such as when the `broker_stopped` entry could not be written |
| 64 | wrong usage |
| 76 | Telegram reported a polling conflict (section 7): the bot token may be stolen. Make a new bot token, then start the broker. |
| 77 | Telegram does not accept the bot token: `getUpdates` got 401 or 404, such as for a revoked token or a bot that is gone. Put a new token into the token file, then start the broker. |

The example unit lists 64, 76 and 77 in `RestartPreventExitStatus=`:
only a person can fix these, and a new start with the same setup would
only fail again, or call Telegram with the same token, and write
`broker_started` and `broker_stopped`, every few seconds. After code 1,
or a crash, it starts the broker again after 5 seconds. If the cause
stays, such as a wrong config, this repeats until a person fixes it; the
journal says why. A start that fails before step 8 writes no entry and
calls no Telegram.

`nodkey run` exits with the command's own code, or:

| code | meaning |
|---|---|
| 64 | wrong usage |
| 69 | the broker cannot be reached |
| 77 | denied, expired or not allowed |
| 126 | the command was found but cannot be run |
| 127 | the command was not found |

`nodkey run` exits with 77 when the broker answers `403` or `429`. It
exits with 69 when it cannot reach the broker, and for every other answer
that is not `200`, such as `503` or a redirect (section 10). It never
tries again. More cases:

- 69: the client config or the TLS key cannot be read or is not valid
  (a client config that is missing points to `docs/setup.md`, section 11),
  as then the broker cannot be reached; nodkey cannot mark itself as not
  dumpable (section 16); the broker sends no answer within the deadline
  of 15 minutes (section 5); a `200` whose body is not a valid answer, or
  whose answer does not fit the request, such as a missing value, an
  empty one, or one with a NUL byte (section 5, step 7): the person
  approved, and the broker is at fault; more than 4 informational
  answers.
- 127: the command is not in `PATH`, or its path does not exist.
- 126: the command cannot be run: a directory, a file without execute
  permission, a file that `PATH` finds only through a relative directory
  such as `.` (also when `GODEBUG=execerrdot=0` turns off Go's own check),
  or a file that `execve` refuses after the approval, such as a file that
  is not a program.

`nodkey run` looks for the command before it asks anyone. So 126 and
127 come without a request, unless `execve` itself fails.

`SIGINT` (Ctrl-C) or `SIGTERM` while nodkey waits: it closes the
connection, so the broker cancels the request, and prints the last line
`nodkey: cancelled by SIGINT (exit 130)`, or `SIGTERM` and 143. Then it
ends itself with the same signal, as a program that does not catch it.
A shell then shows 130 or 143. A shell stops a loop or a script only when
a command dies of `SIGINT`; with a plain exit code, one Ctrl-C would end
only one `nodkey run`, and the next one would send its request to the
phone. Once the command starts, the signals are the command's.

`nodkey run -h` or `nodkey run --help` prints the usage and exits with 0,
but only as the only argument. With other arguments, `-h` and `--help`
are wrong usage (64), with the one line above: an exit with 0 that runs nothing would look like a
command that ran.

The command itself may also exit with one of these codes. To tell them
apart, look at the last line on stderr. Only when nodkey itself exits, its
last line is `nodkey: <reason> (exit <code>)`, for example
`nodkey: denied (exit 77)`. When the command runs, nodkey prints nothing
after it. Before its last line, or before the command starts, nodkey may
print one warning about the version of the broker (section 10).

`nodkey ssh-grant` exits with:

| code | meaning |
|---|---|
| 0 | the person approved: the grants are made |
| 64 | wrong usage |
| 69 | the broker cannot be reached |
| 77 | denied, expired or not allowed |

It reads the broker's answers as `nodkey run` does: 77 for `403` and
`429`, and 69 for every other answer that is not `200`, and when the
config, the TLS key or the deadline fails. It also exits with 69 for a
`200` that is not a valid answer, or whose `minutes` is not 1 to the
minutes of `--for` (section 13): the person approved, and the broker is
at fault. It never tries again. `SIGINT` and `SIGTERM` while it waits
cancel the request, as for `nodkey run`: the last line is `nodkey:
cancelled by SIGINT (exit 130)`, or `SIGTERM` and 143, and then nodkey
ends itself with the same signal. Also after the tap, the broker then
starts no grant, except in a tiny window: when the signal comes just as
the broker starts the grants, they start anyway (section 13). The audit
log shows it. A signal that comes after the answer was read changes
nothing: the grants are made, and the last line says so. `-h` and
`--help` work as for `nodkey run`. It prints nothing
on stdout. Its last line on stderr is always
`nodkey: <result> (exit <code>)`, also after an approval, for example
`nodkey: SSH logins as deploy to 2 hosts allowed until 14:20 (exit 0)`.
Before it, it may print one warning about the version of the broker
(section 10).

`nodkey preapprove` with `--daily` or `--weekly` asks for a standing grant
(section 8). `--weekly` takes day names (`mon,thu`) and one window.
`--grant-token FILE` is a must; the client writes the token there after the
tap (mode 0600, new file or its own file) and prints no token. `nodkey run
--grant-token FILE` uses it and rotates it, as section 8 says; if the
file cannot be saved, the command does not run (exit 77).

`nodkey preapprove` asks for a scheduled grant (section 8) and waits for
the tap, as `nodkey ssh-grant` does. The times are read as section 8
says; the client only checks their form. After an approval it prints the
ID of the grant alone on stdout, so a script can keep it for `--cancel`,
and its last line on stderr is `nodkey: grant ID: 2 uses from
2026-10-28T03:00:00+02:00 until 2026-10-28T04:00:00+02:00 (exit 0)`, with
the times in the broker's local time. `--cancel ID` ends a grant of this
machine without a tap; its last line is `nodkey: grant ID cancelled (exit
0)`. Its exit codes and its handling of answers, `SIGINT` and `SIGTERM`
are those of `nodkey ssh-grant`: 0, 64, 69 and 77. In one case it does
more: when a signal comes as the answer with the ID is read, it sends a
cancel for that grant (for at most 30 seconds), then says `cancelled`;
if the cancel fails, it first prints `nodkey: grant ID may be active;
cancel it with: nodkey preapprove --cancel ID`. When a request fails
after the short code was printed, without a final answer other than 200
(a signal, a broken connection, a timeout, or a 200 whose answer cannot be
read or is not valid), it prints `nodkey: a grant
may have started; its ID is in the audit log, in the grant_id of the
entries of the request whose message shows CODE; cancel it with: nodkey
preapprove --cancel ID`. These lines come before the last line, and the
exit code is the one of the failure (that of the signal, or 69). A cancel of a grant
that this machine does not have is 77. A job should ask when it is
planned, not when it runs.

`nodkey keygen` prints the pin on stdout, and nothing else. It exits with
0, with 64 on wrong usage (the one line of a usage error above), and with
1 on any other error. Then its last line on stderr is
`nodkey: <reason> (exit 1)`.

`nodkey version [--offline]` prints `nodkey <version>` on stdout, such as
`nodkey 0.2.0`, and nothing else there: scripts and the installer read
this line. Then, only when stdout is a terminal, the version is a
release (section 10) and `--offline` is not given, it asks GitHub for the
newest release, for at most 10 seconds, and prints one line on stderr:

```
nodkey: a newer release is out: nodkey 0.3.0; to update, run nodkey update as root; what is new: nodkey update --notes; release notes: https://github.com/code6x/nodkey/releases/tag/v0.3.0
nodkey: this is the newest release
nodkey: cannot check for a newer release: cannot reach GitHub: the lookup timed out
```

When a security release is newer than this nodkey, also one that is
older than the newest release, it prints this red line instead (no
colour when `NO_COLOR` is set and not empty):

```
SECURITY UPDATE: <security releases>. This is nodkey 0.3.0. Update now: run nodkey update as root. Checked notes: nodkey update --notes.
```

A newest release that is older than this nodkey gives "this is the
newest release" too: nodkey never suggests a downgrade. Only stdout
decides whether it asks: when stdout is not a terminal, such as a pipe,
a file or `$(...)` in the installer, it prints no such line and makes no
call to GitHub. A build from the source never asks either. It exits with
0, also when the check fails, with 64 on wrong usage, and with 1 when it
cannot write to stdout.

The lookup, of `nodkey version` and of the broker (step 10 of the start):

- `GET https://api.github.com/repos/code6x/nodkey/releases?per_page=20`:
  one call for the list of the last 20 releases, without a login, with
  the headers `Accept: application/vnd.github+json`,
  `X-GitHub-Api-Version: 2022-11-28` and `User-Agent: nodkey/<version>`.
  So GitHub learns the address and the version (THREAT-MODEL.md T34).
- It uses the proxy from the environment, as the Telegram code does
  (section 7): `HTTPS_PROXY` or `https_proxy`, except for the hosts in
  `NO_PROXY` or `no_proxy`. TLS 1.2 or newer, with the system's CA
  certificates, or those of `SSL_CERT_FILE` and `SSL_CERT_DIR`. HTTP/1.1
  only. It follows no redirect: a redirect is an error. It keeps no
  connection open.
- The TCP connection, the TLS handshake and the headers of the answer
  each have 10 seconds, and the whole lookup 30 seconds. The answer is
  at most 1 MiB; a larger one is an error.
- The answer must be a JSON list of at most 20 objects. Of each one it
  reads only `tag_name`, `draft`, `prerelease` and `body`, with exactly
  these names, and ignores the other keys. A missing key (other than `body`), or
  a key of a wrong type in any release, is an error. `body` may be a
  string, `null` or missing. Drafts, prereleases and tags that are not
  `v` and a release version, such as `v0.3.0`, do not count. The newest
  release is the highest version that counts; a list without one is an
  error.
- A release that counts is a security release when its notes have the
  line `### Security` (trailing spaces and `\r` do not matter). Only the
  first 64 KiB of the notes are read: the Security section comes first.
  Under that line, up to the next line that starts with `#`, it takes at
  most 3 advisory IDs in the strict form `GHSA-xxxx-xxxx-xxxx`, where
  each `x` is one of `23456789cfghjmpqrvwx`, as words of their own. It
  finds every security release newer than this nodkey among the last 20
  releases, so a skipped one is not lost. Nothing else of the notes is ever used.
- 403 and 429 mean that GitHub limits the calls without a login from
  this address for now. Any other status but 200 is an error with only
  the status.
- An error has a fixed text, with at most the HTTP status. No text,
  header or link of the answer is ever shown or logged. The link to the
  page of the release is made from the version.

`nodkey ssh-agent [--socket PATH]` serves the SSH agent protocol on a
Unix socket until `SIGINT` or `SIGTERM` (section 6). It holds no SSH key.

- The default socket is `$XDG_RUNTIME_DIR/nodkey/agent.sock`. Without
  `XDG_RUNTIME_DIR`, give `--socket`. The path must be absolute and
  clean, and at most 107 bytes: the limit of a Unix socket. Point ssh to
  it: `export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/nodkey/agent.sock`.
- The socket's directory must be a directory, not a symbolic link, owned
  by the user, with mode `0700`. Any such directory passes, also
  `$XDG_RUNTIME_DIR` itself. nodkey makes the directory with mode `0700`
  if it is missing, such as `$XDG_RUNTIME_DIR/nodkey`, and never changes
  a directory that is there. Every directory on the way must pass the
  checks of the directories on the way to a key file (section 14), so
  that no other user can swap the socket's directory. The socket has
  mode `0600`, whatever the umask.
- While it runs, the agent holds a lock (`flock`) on the file
  `PATH.lock` next to the socket. nodkey makes that file with mode
  `0600`; it must be a regular file of the user, and it stays after the
  agent ends. A second agent on the same path stops at once (exit 1), so
  two agents never remove each other's socket.
- A socket that is already at the path is removed only when it is a
  socket of the user that no program serves: an agent ended without
  removing it. If a program serves it, or anything else is at the path,
  it stays, and the agent does not start.
- It refuses connections of other users, also of root: the kernel says
  who connected (`SO_PEERCRED`). Root can read the client's TLS key
  anyway.
- It serves at most 128 connections at the same time, and closes more at
  once. A message is at most 256 KiB, as for OpenSSH's own agent; its
  buffer grows as its bytes come, so a length alone takes little memory.
- It refuses `ssh-add` (adding, removing, locking and unlocking keys),
  every extension but `session-bind@openssh.com`, and every request that
  it does not know, with `SSH_AGENT_FAILURE`. It does not parse the
  private key that `ssh-add` sends, and clears that message from its
  memory, as best effort.
- It serves the agent protocol itself. The agent server of
  `golang.org/x/crypto` writes the text of each error to Go's global
  logger, without escaping and without a limit, so nodkey does not use
  it, and sends Go's global logger nowhere.
- On stderr, it prints where it listens, the short code of each request
  that waits for the person (`nodkey: waiting for approval (request
  k3f9)`), and one line about each request that it refused or that
  failed, such as `nodkey: no signature (request k3f9): denied`, with the
  same texts as `nodkey run`: `denied` for `403`, and `denied by a limit
  of the broker` for `429`. It also prints a warning about the version of
  the broker, once for each version that the broker sends (section 10).
  A line holds only fixed text, numbers, release versions, the short
  code, the broker's address, the socket's path and errors of the
  operating system, never text that a process on the agent machine sent.
- Any process of the user can cause both kinds of lines: the broker
  sends a short code for every request that starts to wait, also in its
  queue. So each kind has its own budget: at most 60 lines in a minute.
  Honest use has at most 15 requests that wait at the same time (section
  8). The lines over a budget are counted. The next line of the same kind
  in a later minute says how many were left out, and so does the agent
  when it stops.
- On `SIGINT` or `SIGTERM`, it closes the open connections, so the broker
  cancels the requests that still wait, and it waits for the connections
  at most 5 seconds. It removes its socket, if the socket is still the
  one it made, prints `nodkey: stopped by SIGTERM (exit 143)`, and ends
  itself with the same signal, as `nodkey run` does. So a shell sees 130
  or 143, and systemd sees a clean stop. A signal while the agent starts
  ends it the same way. After the first signal, nodkey no longer catches
  them: a second one ends it at once, and the socket stays until the next
  start removes it.
- It exits with 64 on wrong usage, with 69 when the client config or the
  TLS key cannot be read (as `nodkey run`), and with 1 when it cannot make
  its socket.

`nodkey audit verify FILE [--anchor SEQ:HASH]... [--anchors FILE|-]`
takes `FILE` before or after the options.

- `--anchor SEQ:HASH` may repeat.
- `--anchors FILE` reads anchors from a file, or from stdin for `-`. It
  uses every line that is exactly `audit anchor SEQ:HASH`, and skips the
  other lines, so it takes the output of `journalctl -u nodkey -o cat`.
  If no line is an anchor, that is wrong usage (64, with the one line of a
  usage error): a check with no anchor must not pass by mistake.
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

`nodkey update [--version X.Y.Z] [--gh PATH] [--reinstall | --notes]` installs a
release in place of the file that it runs from: the newest release, or
`X.Y.Z`, also an older one. It runs only as root. Otherwise it prints
`nodkey: nodkey update must run as root: run it as root (exit 1)`.
It runs the install script that is built into the binary (`install.sh`,
section 18) with `/bin/sh`. The script gets `--bin-dir` with the
directory of the file of nodkey, after links, and the flags that are
given: `--version`, `--gh` and `--reinstall`. No other value goes into
its arguments. Its stdin is `/dev/null`, and it writes to the stdout and
stderr of nodkey. So the code that checks a new release comes from the
build that is installed and was checked, not fresh from the network. A
file that is not named `nodkey` is refused: the script would replace
another file. `--version` must be `X.Y.Z`, such as `0.2.0`, and `--gh`
an absolute path; each may be given once.

`--notes` installs nothing. The script makes all the same checks (steps 1
to 8 of section 18), then runs the new, checked binary from its temporary
directory: first `nodkey version`, which must say the release, then
`nodkey changes --since X.Y.Z` with the installed version. A failed check
runs nothing. `--notes` needs root, as the update does, and does not go
with `--reinstall`. A normal `nodkey update` to a newer version prints the
same changes after it installs. If that fails, it prints the link of the
release notes and still succeeds, because the new file is in place.

`nodkey changes --since X.Y.Z` prints the entries of the CHANGELOG.md
that is built into the binary (`go:embed`) for the releases newer than
`X.Y.Z`, with the security fixes of all of them first. It exits with 0,
with 64 on wrong usage, such as an `X.Y.Z` that is not a release version,
and with 1 on any other error. Control and direction characters in the
text print as `?`. The text comes from the attested release, not from
GitHub's API.

The script gets a fixed environment: `PATH=/usr/sbin:/usr/bin:/sbin:/bin`,
`LC_ALL=C` and `HOME=/root`, and `HTTPS_PROXY`, `https_proxy`, `NO_PROXY`
and `no_proxy` if nodkey has them. Nothing else comes from the environment
of nodkey. With `sudo -E`, or after `su` without `-`, the environment of
root can come from another user, and variables such as `TAR_OPTIONS`,
`LD_PRELOAD` or `TMPDIR` would change what the programs of the script do
as root. Without `TMPDIR`, the script uses `/tmp`.

`install.sh` and `nodkey update` exit with:

| code | meaning |
|---|---|
| 0 | the release is installed, or there is nothing to do: that version is installed already, or the installed one is newer and `--version` does not ask for the older one |
| 1 | any failure; nothing was installed. The last line on stderr is `nodkey: <reason>; nothing was installed (exit 1)` |
| 64 | wrong usage |

## 16. Implementation rules

- No secret value in any log, error text, audit entry or Telegram message.
- The broker runs store programs by absolute path, with no shell, with only
  the environment they need (tokens and the `bw` session go in environment
  variables, never in arguments), with a timeout and a cap on output size.
  Their output is never logged. The details are below.
- `bw` keeps a local copy of the vault. The broker runs `bw sync --force`
  before each fetch, so a changed or removed item is not handed out from an
  old copy.
- `bws` and `bw` write state files in their home directory. Each store gets
  its own home directory, `NAME` in the store directory, such as
  `/var/lib/nodkey/stores/vault`. The store directory is `stores` in the
  directory of the audit log, which is the broker's state directory. It
  has mode `0700` and is owned by the broker user, so only that user can
  write to it (section 14). The broker makes it if it is missing; the
  example systemd unit makes it too (`StateDirectory=`).
- Limits on every input: request size (2 MiB, see section 10), number of
  secrets per request (32), field lengths. JSON decoding rejects unknown
  and repeated keys, and missing and `null` fields.
- The broker turns off core dumps and marks itself not dumpable
  (`PR_SET_DUMPABLE`). For core dumps, it sets its own soft and hard
  `RLIMIT_CORE` to 1 at start, and the example systemd unit sets
  `LimitCORE=1`. The store programs inherit this limit, and cannot raise
  it above the hard limit; Go's `os/exec` cannot set a limit for one
  child. If a store program crashes, a core handler such as
  systemd-coredump would write the program's environment, with the token
  or the session key, into the journal. With a limit of exactly 1 and a
  pipe (`|`) or file `core_pattern`, such as the default of systemd, the
  kernel calls no core handler and writes no core file. A limit of 0 does
  not stop a core handler, and a socket `core_pattern` (`@`) does not look
  at the limit at all. So keep a pipe or file `core_pattern` on the broker
  host. The broker reads both settings back, and does not start if it
  cannot make them. A hard limit of 0 is such a case, because the soft
  limit cannot be higher than the hard limit.
- `nodkey run` marks itself not dumpable (`PR_SET_DUMPABLE` 0) before it
  sends its request, so it writes no core dump while it holds the values,
  also when the agent sets `GOTRACEBACK`, and other processes of the user
  cannot read its memory. `execve` makes the command dumpable again. It
  does not change `RLIMIT_CORE`, which the command would inherit.
- Time limits use Go's monotonic clock, so setting the wall clock does not
  move them. The monotonic clock stops while the host sleeps (suspend), so
  a request and a grant also end when the wall clock reaches their end:
  they end at whichever clock gets there first. A grant from 11:55 for 15
  minutes ends at 12:10 on the wall clock, also if the host slept from
  12:00 to 20:00. A request whose end the wall clock has passed takes no
  answer.
- A systemd unit with sandbox settings ships as an example:
  [contrib/systemd/nodkey.service](contrib/systemd/nodkey.service). Its
  sandbox must let `bw` run: Node.js needs memory that is both writable
  and executable, so the unit must not set `MemoryDenyWriteExecute=yes`
  when it has a `bw` store. It must not set `PrivateUsers=yes` either:
  then the credentials and the config, owned by root, would look owned
  by `nobody`, and the broker would refuse them. The unit has one
  `LoadCredentialEncrypted=` line for each key, token and password file
  (section 11), and sets `StateDirectory=` (the audit log and the store
  directory, mode `0700`), `UMask=0077`, `LimitCORE=1`, `MemoryMax=`,
  `MemorySwapMax=0` and `MemoryZSwapMax=0` (no swap, section 11;
  `MemoryZSwapMax=` needs systemd 253 or newer, an older one ignores it
  with a warning, and `MemorySwapMax=0` alone is enough),
  `TimeoutStopSec=90s`, `RestartPreventExitStatus=64 76 77` (section 15)
  and `LogRateLimitIntervalSec=0`, so that journald never drops an anchor
  of the audit log.
- Swap and hibernation write memory to disk, and the broker's memory
  holds keys, tokens and, for a moment, secret values. So the broker host
  uses encrypted swap or none, and no hibernation (section 11).

### Store programs

The broker runs `bws` and `bw` like this (`internal/store`):

- By the absolute path from the config, with no shell. stdin is
  `/dev/null`, and the working directory is the store's home directory.
- With only these environment variables: `HOME` (the store's own home
  directory), and `BWS_ACCESS_TOKEN` for `bws`, or `PATH` and
  `BW_SESSION` for `bw`. `PATH` is `/usr/local/bin:/usr/bin:/bin`, so that
  a bw from npm, a script that starts with `#!/usr/bin/env node`, finds
  `node`. The broker checks these directories and the `node` in them at
  start (section 14). bws
  gets no `PATH`: it starts no other program. Nothing comes from the
  broker's own environment. So a variable such as `NODE_OPTIONS`, `LD_PRELOAD` or
  `BW_CLEANEXIT` (which makes bw exit with 0 after an error) cannot change
  what the program does. Neither can a proxy setting (`HTTPS_PROXY`) or
  extra CA certificates for bw (`NODE_EXTRA_CA_CERTS`): version 1 does not
  support them.
- The arguments are fixed words, the item's UUID and the path of the
  password file, never a token, a password or a session key. The broker
  checks again that the ID is a UUID, so it never starts with `-`.
- In a process group of its own. Each run has a time limit of 30 seconds.
  When the time is up, when the request ends (for example, the client
  hangs up), or when the program writes more than 1 MiB to stdout or
  64 KiB to stderr, the broker kills the whole process group, and the run
  fails. After each run, the broker kills the group again, in case the
  program left a process behind. If such a process keeps the output open
  for 2 seconds after the program ended, the run fails too. If the broker
  ends during a run, for example in a crash, the kernel kills the program
  (`Pdeathsig`).
- At most 4 runs of `bws` at the same time for one store, and one run of
  `bw` (section 11).
- The broker reads stdout, never stderr, and logs neither. An error names
  the store and the step, and gives a fixed reason and the exit code, such
  as `store "vault": bw sync: the program failed (exit code 1)`. It ends
  with a hint: `; to see why, run PROGRAM by hand as the broker's user, with
  HOME set to HOME`, with the path of the program and of its home. The hint
  holds no argument and no output of the program, so T18 holds. Any error
  means deny.
- The broker clears the output, the token and the session key in its
  memory when it no longer needs them. This is best effort: Go strings,
  such as the environment variable for a run, and buffers of the operating
  system are not cleared.
- bws keeps its login state in `.config/bws/state/` and its config in
  `.config/bws/config` in its home directory. For Bitwarden's EU cloud or
  your own server, run `bws config server-base URL` with that home, as for
  bw in section 11. bw keeps its copy of the vault and its login in
  `.config/Bitwarden CLI/data.json`. But if a directory named `bw-data`
  is next to bw's executable, bw keeps its state there and ignores
  `HOME`; so the broker refuses to start then (section 14).

What the broker runs, and what it reads. We checked this in the source of
bws 2.1.0 and bw 2026.9.1 on 2026-10-14
([bws](https://github.com/bitwarden/sdk-sm/tree/bws-v2.1.0/crates/bws),
[bw](https://github.com/bitwarden/clients/tree/cli-v2026.9.1/apps/cli)):

| when | command | what the broker reads |
|---|---|---|
| a `bws` fetch | `bws secret get ID --output json --color no` | stdout: one JSON object with `id`, `organizationId`, `projectId`, `key`, `value`, `note`, `creationDate` and `revisionDate`. The broker reads only `id` and `value`. |
| a `bw` unlock | `bw unlock --passwordfile FILE --raw --nointeraction` | stdout: only the session key, in base64. |
| a `bw` fetch, first | `bw sync --force --nointeraction` | only the exit code. |
| a `bw` fetch, then | `bw get item ID --nointeraction` | stdout: one JSON object, the item. The broker reads only `id`, `login.password`, `deletedDate` and `archivedDate`. |
| after a `bw` step failed | `bw status --nointeraction` | stdout: one JSON object. The broker reads only `status`: `unauthenticated` (logged out), `locked` (the session key does not work) or `unlocked`. |

- Both programs write errors to stderr and exit with 1; `bws` exits with
  2 on wrong usage. bw writes no newline at the end when stdout is not a
  terminal. `--nointeraction` makes bw fail instead of asking for the
  password when the vault is locked.
- An answer must be exactly one JSON object in valid UTF-8, with only
  whitespace around it. A key may be in an object only once, and keys
  must match exactly: `Value` is not `value`. A lone surrogate escape is
  refused. Other fields are skipped, so a newer version with more fields
  still works. Any other answer is refused, and the request is denied.
- `id` must be the asked ID, in upper or lower case. An answer without
  it, or for another item, is refused.
- A value that is missing, `null` or empty is refused. So is a value with
  a NUL byte: the environment of a command cannot hold it. So is an item
  that is not a login item, an item in the trash (`deletedDate` is not
  `null`) and an archived item (`archivedDate` is not `null`). bw 2026.9.1
  leaves both dates out of a normal item.
- bws exits with 0 and prints nothing when the token belongs to no
  organization. That is refused too.
- Other fields can hold secrets too, such as `note` for bws, and `notes`,
  `fields`, `passwordHistory` and `login.totp` for bw. The broker skips
  them without keeping them, and clears the whole answer after reading it.
- Without `--force`, bw downloads the vault only when the server's
  revision date of the account is later than bw's last sync, and bw takes
  the time of each sync from the broker's clock. With that clock ahead, bw
  would not download again, and a changed, trashed or archived item would
  still be handed out. `--force` downloads the whole vault each time. That
  is more traffic, but the account holds only the items that nodkey may
  hand out (section 11).

## 17. Testing

- **Unit tests** for each package: config, rules and grants (with a fake
  clock), limits and the queue, audit chain, tamper checks and torn-line
  recovery, session-bind and authentication request parsing, masking, message
  text and escaping, and the Telegram client against a fake Telegram server
  (wrong user, wrong chat, inline message, wrong message, bad button data,
  unknown ID, early tap, late tap, double tap, a tap sent again after a
  restart, a message that someone else edited, with an Approve and a
  Deny on it, also after a flood of forged taps, polling conflict, code
  429 and server errors, and a canary bot token that must not appear in
  any error or log line). A child process checks the HTTP client with
  `GODEBUG=http2debug=2` and a proxy. The lookup of a newer release runs
  against a fake GitHub server: every kind of answer that is not valid,
  403 and 429, a redirect, a time-out, an answer over 1 MiB, and, in a
  child process, a proxy. The broker's check runs with a fake lookup, a
  fake notice and a fake clock. The SSH checks also use real data:
  from an in-process SSH server and client, and from the OpenSSH client
  and, when it is installed, `sshd`.
- **Fake approver**: a test approver that says yes, no, nothing, or answers
  late, on command. It and a fake clock are in
  `internal/approval/approvaltest`, for the tests of the broker too.
- **Broker tests**: the broker's service runs behind the real transport
  server, over mutual TLS on the loopback address, with the real approval
  core, the fake approver and clock, fake stores in memory, and an audit
  log in memory that refuses what the real one refuses. SSH logins are
  real: an in-process SSH server checks the signatures.
- **Tests of `nodkey broker`**: the command runs in a child process, with
  a config whose files pass every check of section 14, fake store
  programs, and the real Telegram approver. The approver reaches a fake
  Telegram server through a fake HTTPS proxy that answers TLS with a
  certificate of a test CA, so nothing goes to the real Bot API. The
  same server answers for GitHub's API, for the check for a newer
  release, so nothing goes to the real GitHub either. The tests check the
  order of the start and the stop, the exit codes, that core dumps are
  off, a store that does not start, the notice about a newer release,
  and a canary from the request to the fake Telegram server, end to end.
- **Fake stores**: the test binary of `internal/store` acts like `bws` or
  `bw` when it runs under that name. It records its arguments and its
  environment, so the tests can check that no token, password or session
  key is ever an argument.
- **End-to-end test** (`test/e2e`): the real programs, with only Telegram
  and the store faked. It builds the `nodkey` binary from the repository,
  with the race detector when the test runs with it.
  - The SSH targets run in one Docker container, built from
    `test/e2e/testdata/sshd`: OpenSSH's `sshd` and git from Debian, on a
    base image pinned by its digest. Each target is an `sshd` of its own,
    with its own throwaway host key: `web-1` (Ed25519), `web-2` (ECDSA),
    `db-1` (RSA) and `web-3` (Ed25519). The broker's `known_hosts` has the
    first three, not `web-3`. The remote users `deploy` and `ops` have the
    public half of the broker's throwaway key `deploy` in their
    `authorized_keys`. Only the broker holds its private half. `deploy`
    has a bare git repository. The container has no capability but those
    that `sshd` needs, no new privileges, limits on its processes and
    memory, and `DisableForwarding yes`. It publishes its ports on
    `127.0.0.1` only, from a network of its own.
  - `nodkey broker`, `nodkey run`, `nodkey ssh-agent`, `nodkey ssh-grant`,
    `ssh` and `git` run on the test machine. The files of the broker and
    the clients are in a private directory that passes every check of
    section 14, with TLS keys from `nodkey keygen`. The store is a fake
    `bws`, a shell script. The broker's Telegram code is the real one: it
    reaches a fake Telegram server through a fake HTTPS proxy and a test
    CA, as in the tests of `nodkey broker`. The test taps "Approve once",
    "Approve 15 min" or "Deny" there. Two clients, `laptop` and `ci`, have
    their own keys and home directories.
  - The cases: `nodkey run` passes the secret into a command, which proves
    it with the SHA-256 of the value; after a Deny, the command does not
    run; an SSH login after "Approve once"; an unknown host key is refused
    before any message; after `ssh-grant` for `web-1` and `web-2`, these
    hosts need no tap, and `db-1` and the remote user `ops` still ask;
    `git clone` and `git push` over SSH, where one "Approve 15 min" covers
    the logins after it; a denied login, after which the grants of the key
    have ended. Each case also checks what the message shows, what the
    clients print, the entries in the audit log, and that no other
    message goes out. The config has no "never ask" rule, nothing in the
    test makes an alert, and the client and the broker are the same build
    from the source, so no notice about a version goes out either: every
    message must have buttons. A build from the source never asks GitHub
    for a newer release, and the test checks that the broker says so.
    At the end, `nodkey audit verify` checks the whole audit log with every
    anchor of the broker's journal, and a copy of the log with one changed
    entry fails.
  - The root-only test of `internal/client` runs as root in a container
    without a network, with only the capabilities `SETUID` and `SETGID`:
    a process of another user connects to the socket of
    `nodkey ssh-agent`, and the agent refuses it (`SO_PEERCRED`).
  - Run it with `go test -race -tags e2e ./test/e2e/...`. It needs
    Docker, OpenSSH's `ssh` 8.9 or newer, and `git`. Once the image and
    the binaries are built, it takes about 10 seconds. The CI job `e2e`
    runs it.
  - Each run of the test has a run ID: its start time and a random part.
    The names and labels of its containers, its network and its image
    hold it, and so does the name of its private directory, in
    `$XDG_RUNTIME_DIR`, or else in the cache directory (`$XDG_CACHE_HOME`,
    or else `~/.cache`). While it runs, the test holds a lock on the file
    `nodkey-e2e-RUNID.lock` in the temporary directory (`$TMPDIR`, or else
    `/tmp`). At the end, it removes everything that it made, and fails if
    something is left. A run that is killed, such as by the `-timeout` of
    `go test` or by Ctrl-C, cannot do that: the kernel stops its programs,
    its containers end on their own after 15 minutes, and the rest stays.
    So each run first removes
    what runs that have ended left: those whose lock file nobody holds,
    and those older than an hour whose lock file it cannot check: it is
    not there, or not a regular file. It never touches a run that holds
    its lock, or anything without a run ID. By hand, when no end-to-end
    test runs:

    ```sh
    docker ps --all --quiet --filter label=nodkey-e2e | xargs -r docker rm --force
    docker network ls --quiet --filter label=nodkey-e2e | xargs -r docker network rm
    docker image ls nodkey-e2e-sshd --format '{{.Repository}}:{{.Tag}}' | xargs -r docker image rm
    rm -rf "${XDG_CACHE_HOME:-$HOME/.cache}"/nodkey-e2e-* "${TMPDIR:-/tmp}"/nodkey-e2e-*.lock
    if [ -n "$XDG_RUNTIME_DIR" ]; then rm -rf "$XDG_RUNTIME_DIR"/nodkey-e2e-*; fi
    ```
- **Canary test**: part of the end-to-end test. The first canary is the
  value of the secret in the store. The second canary is a random word in
  the command line of a wrapper process, which runs `ssh` and `git`: as
  the value of `--api-token=`, and as a word of its own. The test searches
  every log (the broker's journal, `nodkey ssh-agent` and the `sshd`s),
  the audit log, every call to the fake Telegram server, and every output
  of the clients. It looks for the first canary as it is, in lower and
  upper case, in hex, and in base64 and base64url at each offset, and for
  each part of 12 characters of its random part in the same forms, so
  that a value that was cut is found too. It looks for the made-up bot
  token and the token of the store in the same forms, and for the second
  canary in any case. Any hit fails the test. The command line of the
  wrapper is claimed text, so section 7 shows it only in the message and
  in the audit log, masked. The test checks that every message and every
  audit entry of an SSH login shows `***` in place of both forms. It also
  checks that no other call to Telegram, and no output of `nodkey`, holds
  claimed text: a reason, a word of a command line, the working
  directory, or the variable name. Guards make sure that there was
  something to find: the broker handed out the secret (a `secret_sent`
  entry), and SSH logins went through the wrapper. So a `-run` filter
  that leaves out the cases makes the search fail, not pass.
- **One manual test with a real Telegram bot**, written down in
  [docs/manual-telegram-test.md](docs/manual-telegram-test.md). The token
  comes from a local file and is never committed. It ran on 2026-10-15,
  and its results are in issue #17. It could not test a double tap: in
  Telegram Web, the client used in the test, the buttons went away right
  after the first tap. So only the unit tests check a double tap, such
  as those with the fake Telegram server above.

## 18. Build, CI and releases

- CI on every pull request: `go test -race`, `go vet`, `golangci-lint`,
  `govulncheck`, `shellcheck` on `install.sh`, and the end-to-end job.
  ShellCheck is a fixed release, checked by its SHA-256.
- GitHub Actions are pinned to a commit SHA.
- Pull request titles follow Conventional Commits. Pull requests are squash
  merged.
- Pull request titles may use the type `security` (also `security(deps)`)
  for a real security fix. It puts a `### Security` section first in
  CHANGELOG.md and in the release notes; a line may name advisory IDs
  (`GHSA-...`). nodkey reads this line to flag security releases
  (section 15). See docs/releasing.md.
- release-please keeps a release pull request open. Merging it tags the
  version and creates the GitHub Release. A job then builds static Linux
  binaries (`CGO_ENABLED=0`, amd64 and arm64, `-trimpath`), a
  `SHA256SUMS` file, and a build provenance attestation. The attestation
  is also a file of the release (`nodkey_<version>.sigstore.json`), so it
  can be checked with no GitHub login.
- `install.sh`, at the root of the repository, installs a release on the
  host itself, as root: the broker host or an agent machine. It needs
  `sh`, `curl`, `tar`, `gzip`, `sha256sum`, `install`, `mktemp`, `stat`
  and `uname`, and no GitHub login. `nodkey update` runs the copy that is
  built into nodkey with `go:embed` (section 15). First, the script makes
  its environment safe. It removes the variables that change what its
  programs do: `TAR_OPTIONS` (tar can run commands from it), `GZIP`,
  `POSIXLY_CORRECT`, `CURL_HOME`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`,
  `SSL_CERT_DIR`, `SSLKEYLOGFILE`, `OPENSSL_CONF`, `OPENSSL_MODULES`,
  `OPENSSL_ENGINES` (an OpenSSL config can name a library for curl to
  load), `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `GCONV_PATH`,
  `CDPATH` and `IFS`. It sets `LC_ALL=C`. As
  root, it sets `PATH=/usr/sbin:/usr/bin:/sbin:/bin`. curl always gets
  `-q`, so it reads no `.curlrc`. Then the script:
  1. runs only on Linux, on amd64 or arm64;
  2. checks the places that it runs programs from and writes to, before
     it downloads anything: the bin directory, the old `nodkey` in it,
     the gh of `--gh`, and the temporary directory (`TMPDIR`, or `/tmp`).
     Each of them, and each directory above it up to `/`, must be owned
     by root, and group and others must not be able to write to it. A
     directory above them, and `TMPDIR` itself, may let others write only
     with the sticky bit, as `/tmp` does. Links in the path are resolved
     once, and the script uses the real path from then on. The old file
     and the gh must be files, not links. When the script does not run
     as root, the user who runs it may own these paths too: the tests run
     it so;
  3. takes the version of `--version`, or asks the GitHub API for the
     newest release, with no login; only a tag `vX.Y.Z` counts;
  4. stops when the installed `nodkey version` says that version already,
     unless `--reinstall` is given. It says that it did not check the
     installed file. Without `--version`, it does not install a version
     older than the installed one. A build from the source (`dev`, or not
     `X.Y.Z`) has an unknown version, and any release replaces it;
  5. downloads the tarball for the machine, `SHA256SUMS`, and the
     Sigstore bundle of the attestation, `nodkey_<version>.sigstore.json`,
     over HTTPS only, into a new private temporary directory. Each
     download has a size limit: 64 MiB for the tarballs (of nodkey and of
     gh), 1 MiB for the other files;
  6. checks the SHA-256 of the tarball against its own line in
     `SHA256SUMS`;
  7. gets `gh`: it downloads gh 2.102.0 and checks it against the SHA-256
     in the script, one for each CPU, or it takes the gh of `--gh PATH`.
     That gh must be 2.93.0 or newer: older ones have known bugs in
     `attestation verify` (GHSA-fgw4-v983-mgp8, GHSA-8xvp-7hj6-mcj9). The
     first line of `gh --version` must be `gh version X.Y.Z`, so a version
     such as `2.93.0-rc.1` does not count. Newer advisories
     (GHSA-mm27-mwq9-fr5g, GHSA-wjmr-j3rp-mh2g, GHSA-4mq3-hpgx-9cx8) are
     about `--signer-repo`, `--signer-workflow` and `--source-ref`, which
     the script does not use;
  8. runs `gh attestation verify --bundle` with the identity of the
     release workflow on `main` (as in
     [docs/releasing.md](docs/releasing.md#verify-a-download)) and
     `--deny-self-hosted-runners`. gh gets no login and an empty config:
     no `GH_TOKEN`, `GITHUB_TOKEN`, `GH_HOST`, `GH_ENTERPRISE_TOKEN` or
     `GITHUB_ENTERPRISE_TOKEN`, and `HOME`, `GH_CONFIG_DIR` and the
     `XDG_*` directories in the temporary directory. Its update notices,
     prompts and telemetry are off. It still gets the trusted root of
     Sigstore online;
  9. takes only `nodkey` out of the tarball, copies it under a new name
     into the directory of the old file, and checks that its
     `nodkey version` prints exactly `nodkey <version>`. The attestation
     proves which workflow built a file, not which version the file is.
     Without this check, an attested older build under a newer name
     would pass. The new nodkey runs only after the attestation passed;
  10. renames the new file over `/usr/local/bin/nodkey` (or `DIR/nodkey`
      for `--bin-dir DIR`), with mode `0755`, owned by root when the
      script runs as root. A rename in one directory replaces the old
      file in one step, never half;
  11. says what to restart: the broker (`systemctl restart nodkey`, which
      ends all grants) and each `nodkey ssh-agent`. It restarts nothing
      itself;
  12. removes the temporary directory, also after a failure or a signal.

  With `--notes`, the script does steps 1 to 8, then runs the new binary
  from the temporary directory to print its changes (section 15), and
  installs nothing (steps 9 to 11 do not run).

  Any failed step stops the script with a clear last line, and nothing
  is installed. All the work is in functions, and only the last line
  starts it, so a download through `curl ... | sh` that stops in the
  middle runs nothing. THREAT-MODEL.md T20 says what the script trusts.

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
