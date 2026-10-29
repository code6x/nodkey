# nodkey threat model

Status: accepted for version 1 on 2026-10-12.

This file says what nodkey protects, from whom, and where it stops. Read
[DESIGN.md](DESIGN.md) first for the words and the flows.

## 1. The problem in one paragraph

An AI coding agent works on a machine where it can do almost anything. It
can be wrong, it can be tricked by text it reads (prompt injection), and
anything it prints may end up in its context and in the model provider's
logs. If an SSH key or an API token sits on that machine, the agent can use
it at any time, for anything. nodkey moves the keys and the secret-store
access to another machine and asks a person before each use.

## 2. What we protect

| asset | where it lives |
|---|---|
| SSH private keys | broker memory; encrypted credentials on the broker host's disk |
| secret-store access (`bws` token, `bw` master password and session key) | broker host |
| secret values | the store; for a moment the broker; after approval, the one command on the agent machine |
| the approval decision | Telegram, the broker |
| the audit log | broker host, and hash copies in the broker's journal |
| the Telegram bot token | broker host |

## 3. Who we trust, and how much

| actor | trust |
|---|---|
| the approver (the person) | Trusted. Their judgment is the security check. |
| the approver's phone and Telegram account | Trusted. Anyone who can use this account can approve. So the account must not be logged in on any agent machine (see T7). |
| Telegram's servers | Trusted to deliver messages and to say truthfully who pressed a button. They see the message text, never a secret value that nodkey fetched. |
| the broker host | Fully trusted. Root on the broker host can read and change everything. |
| the agent machine | **Not trusted.** The agent may be root there. |
| the agent | **Not trusted.** It may make mistakes, lie, or follow injected instructions. |
| the network between client and broker | Not trusted. |
| target SSH hosts | Trusted to be who their host key says. |
| the secret stores and the `bws` / `bw` programs | Trusted. Install them from the official source and check what you install. |
| the Bitwarden accounts that can read the secrets of the stores | Trusted. Anyone who can use such an account can read these secrets in Bitwarden's own apps, with no tap. So these accounts must not be logged in on any agent machine (see T32). |
| GitHub's API (`api.github.com`) | Trusted only to name the newest release. A false answer can only give a wrong notice or hide one; it cannot install anything (see T34). |

## 4. What nodkey promises

1. **No use without a yes.** The agent cannot get a secret or an SSH
   signature unless the approver tapped Approve for that request, or a grant
   or a "never ask" rule allows it.
2. **The SSH key stays on the broker.** The agent gets signatures, never the
   key.
3. **A signature works for one session only.** It is bound to one SSH
   session with one host and one remote user. It cannot open a session to
   another host, or a later session. (The session itself can stay open for
   a long time; see section 5.)
4. **The host shown is the real host.** The broker checks the host key from
   `session-bind@openssh.com` against its own list, and refuses clients that
   do not send it. This holds when each host has its own host key; the
   broker refuses a list where two names share one key.
5. **No value in the agent's output by accident.** nodkey has no command
   that prints a secret. Values go only into the environment of the one
   command.
6. **A record.** Every request and decision is in a hash-chained log, and
   nothing is approved unless its record is on disk first. A grant from an
   "Approve N min" tap starts only after its decision is on disk.

## 5. What nodkey does not promise

Read this part carefully. These are real limits.

1. **After approval, the secret is on the agent machine.** It is in the
   environment of the command. A hostile agent with root can read it from
   that process. It can also ask for it with a command that prints it. The
   message shows the command, but the command is claimed and a script can
   hide what it does. nodkey limits *when* and *which* secret; it does not
   stop a hostile agent from keeping a secret it was given.
2. **After an approved SSH login, the agent has a shell on that host.** It
   can do anything that user can do there. It can keep the connection open
   and reuse it without new taps (`ControlMaster`, `ControlPersist`). It can
   add its own key to `authorized_keys` and come back later without nodkey.
   Manage `authorized_keys` with configuration management, so unknown keys
   are removed.
3. **The command and the reason are claims.** The agent can write anything
   there. The message marks them as claimed.
4. **A "never ask" rule is an open door** for that one secret or key, for
   anything on that client. See DESIGN.md decision 3.
5. **The broker host is the root of trust.** Root on it, or a copy of its
   memory, gives every key and token.
6. **Anyone who can use the approver's Telegram account can approve.** That
   includes a Telegram Desktop or Web session on the agent machine.
7. **The audit log on its own does not stop a careful attacker** who can
   write to it (see T17). It needs a copy of the hashes somewhere else.
8. **Keys that were on the agent machine before.** If an SSH key or token
   was ever readable on the agent machine, assume the agent may have a
   copy. Make a new key for the broker and remove the old one from the
   target hosts.
9. **Anyone who can use a Bitwarden account that can read the secrets can
   read them**, without nodkey and without a tap. That includes a login
   on the agent machine: the web app in a browser, the browser extension,
   the desktop app or the CLI (see T32).

## 6. Threats and answers

Each item: what could go wrong, what nodkey does, and the risk that
remains.

**T1. The agent asks for a secret it should not have.**
Only names in the broker config exist, and each lists the clients that may
use it. Unknown names are denied without a message.
The answer tells the names apart, though. The broker checks the names
before the limits of DESIGN.md section 8. So when a limit denies a
request, such as in the pause of 60 seconds after a Deny, a request with
valid names gets `429`, and one with a name that does not exist, or that
the client may not use, gets `403`, both without a message. So an agent
can learn, without a message, which secret names it may use, and with
`nodkey ssh-grant` which hosts are in the broker's `known_hosts` and in
the `hosts` of a key, and the rule and window of a key. We accept this small leak: these are names, not
secret values. (The client may list its key names anyway, with
`/v1/keys`.)
Risk that remains: the agent can learn the names of the secrets and hosts
that it may use; nothing beyond the rules the approver wrote.

**T2. The agent lies about the command or the reason.**
These fields are marked as claimed, below the verified ones. For
`nodkey run`, the program in the command line is the absolute path of
the file that the client runs, as `PATH` found it. So when a directory
early in `PATH`, such as `node_modules/.bin` of a package or a directory
that direnv adds, has its own `gh`, the person sees that path, not only
`gh`. A name that `PATH` finds only through a relative directory, such as
`.`, is refused. A program that is a symbolic link shows as the link, and
the kernel follows the link at `execve`, so if the link changes while the
request waits, its new target runs. Whoever can change the link, its
directory or the file already controls that program (for `/usr/bin`, only
root). This helps against honest mistakes and tricks, not against a
hostile agent: the client runs on the agent machine.
For an SSH login, `nodkey ssh-agent` reads the command lines of `ssh` and
its parents, and the reason, from `/proc` (DESIGN.md section 6). A
process can change its own command line and environment, and a process ID
can be used again by a new process. So these are claims too.
Risk that remains: the person can still be fooled. Deny any request that
looks strange.

**T3. The agent fakes the look of the message.**
It could put new lines, fake "✅ machine:" lines, direction marks, HTML or
links in its text. Claimed text is made one line per field, control and
invisible characters are removed, symbols that draw nothing become spaces,
stacked combining marks are capped and none starts a field, length is
capped, HTML is escaped, the text sits in `<code>`, link previews are off,
and claimed fields always come after the verified ones. The verified part holds only names from the
broker's config and data the broker checked. The broker itself checks that
the remote user name matches a strict pattern, and that environment
variable names match `[A-Z_][A-Z0-9_]{0,63}`; variable names are shown as
claimed. The broker never relies on checks done by the client. The
approval core checks again that each claimed field is one clean line, and
denies the request if one is not. The Telegram code cleans each claimed
field once more and escapes all text it shows. It cuts claimed fields so
that a message fits in one Telegram message, but it never cuts a verified
line: if the verified lines alone do not fit, no message is sent and the
request is denied.
Risk that remains: low.

**T4. An old or repeated tap approves something new.**
Each request has a new random 128-bit ID in the button. It works once, only
on its own message, only while the request waits, and only before it
expires. A restart forgets all IDs. The approval core checks all of this
again after the Telegram code, also the user and the button. Taking the
request out of the waiting list and deciding it is one step under one
lock, so two taps cannot both count. A tap that fails a check changes
nothing. The button data is read strictly. A copy of a message with the
same buttons, which someone with a stolen token can send as the bot, has
another message ID, so its buttons do not count. (A forwarded copy has
no buttons at all: the manual test of issue #17 showed this on
2026-10-15.) An Approve on a message that was edited, or
whose buttons are not the ones the broker sent, never counts, because
the broker never edits a message while its request waits (T6). A Deny
there still counts: a Deny is safe whatever the message shows. A second
tap does not change the result that a message shows, and after a
restart, the broker only removes the buttons of an old message and keeps
its text.
Risk that remains: none known.

**T5. Someone else presses the button.**
The broker accepts only the configured Telegram user ID, in the private
chat with that user.
The bot also reads text messages, for the command `/grants` only
(DESIGN.md section 8). It answers only the text `/grants` (or `/grants@`
and a name) from the approver, in the private chat with the
approver, at most 3 times in any 60 seconds, and only in that chat. The
answer lists the standing grants: the machine, the secrets, the windows,
the last use and the end. It never has a token or a hash. Any other text,
and any text from another user or chat, is ignored without an answer, so
nobody else learns of the grants, and nobody can make the bot send many
messages. A command can approve, renew or end nothing.
Risk that remains: see T7. Someone who can use the approver's account
can read the list.

**T6. The bot token is stolen.**
With the token, an attacker can read updates before the broker does, send
messages as the bot, and edit or delete the bot's messages. They cannot
press a button as the approver. Stolen updates make requests time out,
which means deny. A fake message from the bot with fake buttons sends IDs
the broker does not know, so they are refused, and each refused tap is
written to the audit log with a cause, so a forged button can be told
from a person's second tap. At most 20 refused taps a minute of other
users are logged and written, and, as a separate budget, at most 20 of
the approver's own taps. The broker counts the others, so the journal
and the disk do not fill up, and forged taps cannot crowd out the
entries of the person's taps. The broker only queues these entries in
the polling, so a slow disk does not stop the answers; it drops more
than 64 waiting entries, and logs how many. An attacker can also edit a message that
waits for an answer, to show other names, or swap the labels of its
buttons, so that the person approves without knowing it. The broker
never edits a waiting message, so it refuses every Approve on an edited
message or on one with other buttons, writes it with cause
`edited_message`, and sends an alert, at most one in 10 minutes. A Deny
on such a message still counts, if it is the Deny button that the broker
sent there: a Deny is safe whatever the message shows, so the pause and
the end of grants after it still work (T8). The alert goes out then too,
and the tap is written with cause `edited_message`, next to the Deny.
When another program polls with the same token, Telegram reports a
conflict. The broker logs an alert, sends an alert message, and stops
taking answers: every request that waits for the person is denied. Then
`nodkey broker` stops with exit code 76, and the example systemd unit
does not start it again, so the alert does not come again at each
restart. With the token, an attacker can stop the broker this way, but
they can deny service anyway, by reading the updates. When the broker
stops, it closes the connection of its waiting `getUpdates` call at once
and polls no more. Still, in rare cases a `getUpdates` request of a
broker that just stopped is on its way, reaches Telegram after the new
broker started to poll, and causes a conflict and an alert although
nobody else has the token (DESIGN.md section 7).
A proxy that inspects TLS, with its own certificate authority in the
system's store of the broker host, sees the token, and it can fake
Telegram's answers, so also taps. The broker logs at start which proxy
it uses (DESIGN.md section 7). Do not use such a proxy for the broker.
Risk that remains: denial of service, misleading text in the chat, and,
rarely, a false conflict alert right after a restart.
Only the button data says what a tap is, never the label. So a tap on a
"Deny" label that the attacker gave the data of an Approve does not
count: that request only expires, without the pause after a Deny. A tap
on an "Approve" label with the data of a Deny denies, with the pause and
the end of grants: that is denial of service too.
Keep the token in an encrypted credential; make a new one if it leaks.
When Telegram no longer accepts the old token, the broker stops with
exit code 77, and the example unit does not start it again until a
person puts the new token in place.

**T7. Someone else can use the approver's Telegram account.**
Telegram runs on several devices at once. If the approver's account is
logged in on the agent machine (Telegram Desktop, or Telegram Web in a
browser there), the agent can press Approve itself. It can also copy the
session files and use the account from anywhere. The same holds for any
other way to control the phone from the agent machine (for example `adb`
or KDE Connect). A taken-over account (for example by SIM swap) can approve
too.
What to do:
- Never log in to the approver's Telegram account on an agent machine.
  Check Telegram's Settings → Devices, and end every session you do not
  need.
- Better: use a Telegram account that is logged in only on the phone.
- Turn on Telegram's two-step verification and a passcode on the app.
Risk that remains: real. nodkey cannot see which device pressed a button.
A passkey page is a possible later step.

**T8. Approval fatigue.** The person taps Approve without reading.
Grants for N minutes and `ssh-grant` cut the number of taps. One tap on
an `ssh-grant` message allows exactly what its verified lines show: logins
by that client, with that key, as that remote user, to each listed host
(by its host keys in the broker's `known_hosts`), until the end shown.
The broker checks all of it itself; the checks of the client only give
quick errors (DESIGN.md section 13). Limits stop floods. The message is
short and puts the verified lines first. Notices
about "never ask" uses can go to a separate chat, so the approval chat
stays for real decisions. When the person sees something strange and taps
Deny, the client's grants for that secret or key end at once (for a key:
at every host and for every user), so a grant does not keep handing it
out, and the client's new requests for it are denied for 60 seconds
(T9). This holds also when someone else changed the message (T6): a
Deny is safe whatever the message shows, so the Deny button that the
broker sent on it still counts.
Risk that remains: the person may still tap without reading.

**T9. The agent floods the phone.**
Per client: at most 5 waiting messages and 6 new messages in any 60
seconds; a queue of at most 10; after a Deny, requests for the same secret
or key are denied without a message for 60 seconds, also those that
already wait in the queue. A request leaves the queue only with at least
30 seconds left, so no message comes that cannot be answered in time. A
"never ask" rule sends at most 6 notices in any 60 seconds per client; a
use over that is denied. So a client with such a rule cannot fill the
notice chat, or use up Telegram's limits so that messages for other
clients fail. The Telegram code also sends at most 20 notices in any 60
seconds for all clients together. A use over either limit is denied with
cause `limit`, and it does not count for `max_per_day`. So a burst of
notices of other clients cannot use up the uses of a night; it only
denies uses while the limit is full. A notice about the version of a
client (T33) counts toward neither limit. It has its own: at most 3 in
any 60 seconds, at most one try a minute for each client, and one notice
for each client in each start of the broker, rarely more than one. A
notice about a newer release (T34) shares that limit of 3, with at most
one try an hour after a failure.
Risk that remains: low. Telegram counts all the messages of the notice
chat. With up to 3 notices about versions in a minute, such as right
after a start, about 18 notices of "never ask" uses already pass the
about 20 that Telegram allows. Then Telegram can refuse a notice of a
"never ask" use with its code 429. If the tries of that notice do not
get through in time, the use is denied, and it counts for `max_per_day`
(DESIGN.md section 7). This needs about 18 such uses in one minute, so
it is rare.

**T10. Someone on the network reads or changes the traffic.**
TLS 1.3, with both sides' keys pinned. The pin is checked on every
connection, and TLS session resumption is off: the broker sends no session
tickets, the client keeps no sessions, and both sides refuse a resumed
session. Each side must send exactly one certificate and prove
that it holds its private key, so a copy of a certificate is not enough.
The client never uses a proxy and follows no redirects. It sends each
request once, and only a final `200` with a valid answer counts. Before
the pin check, anyone on the network can answer. So the errors that the
client prints hold only fixed text, errors of the operating system and
the pins, never text that the other side chose, such as a field of its
certificate: the agent reads that output.
Risk that remains: low.

**T11. The client's TLS key is copied.**
The agent is root on its machine, so it can copy the key. With it, the
attacker can only ask, like the agent. To block a client, remove its pin
from the broker config and restart the broker.
Risk that remains: same as the agent itself.

**T12. A signature is used for a different host or a different purpose.**
The broker only signs SSH authentication requests for the asked key. It
parses the data to sign itself and refuses any other kind of data (for
example git commit signatures), also a request with bytes after its last
field. It checks the session-bind signature and the session identifier.
It refuses a host that is not in the key's `hosts` list, when the key has
one. It refuses clients without a session-bind, more than one
session-bind, and forwarded binds. It refuses weak or unclear algorithms:
a key exchange with SHA-1, RSA signatures with SHA-1 (from the host or from the broker's
own key), unknown sign flags, and host certificates. Signing takes the
result of the checks, not raw bytes, so the broker signs only data that
it checked. The forwarding flag comes from the client, so refusing it
stops honest mistakes, not a hostile agent; the host check above does not
depend on that flag.
`nodkey ssh-agent` sends the broker every session-bind of the agent
connection, at most 2, with the exact bytes of the key, the data and the
flags; it refuses a third session-bind, and then asks nothing for that
connection. It gives `ssh` a signature only after it checked that the
format fits the key and the flags, and that the signature is valid for
the data. That is a check of the broker's answer, as for `nodkey run`
(T10); the checks that matter are the broker's.
Risk that remains: low.

**T13. The agent keeps access after an approved login.** See section 5,
item 2.
Risk that remains: real; outside nodkey.

**T14. The agent keeps a secret after approval.** See section 5, item 1.
`nodkey run` itself keeps no value: it replaces itself with the command
(`execve`), so the value is only in the environment of the command.
Before it asks, it marks itself not dumpable, so it writes no core dump
while it holds the values, also when the agent sets `GOTRACEBACK`, and
other processes of the user cannot read its memory then. The command
itself is dumpable again. Use short-lived or narrow secrets, and rotate a
secret after a strange request.
Risk that remains: real.

**T15. A secret leaks by accident into logs, messages or the agent's
output.**
No print command. Values that nodkey fetched are never logged, never in
errors, never in the audit log, never in Telegram. Store program output is
never logged. `nodkey run` prints only its own fixed text, the short code
of the `102 Processing` answer, the HTTP status, names from its
arguments and its config, and in a warning the broker's version from
the header `Nodkey-Version`, only when it is a release version: digits
and dots (DESIGN.md section 10). It never prints an answer body or any
other header, and nothing after the command started. A command line can hold
a secret the agent typed in (for example `mysql -pSECRET`), and it would
go to Telegram and the audit log. So
the broker masks values that look like secrets in every claimed field, and
shows at most 8 arguments. DESIGN.md section 7 lists what is masked, and
gives examples of what is not. It masks values of options with secret
names, `-p`, options of some programs such as `redis-cli -a`, values after
keys such as `password=` or `"token":`, headers, passwords in URLs, PEM
blocks, known token shapes, and long random-looking words. A field longer
than 64 KiB is not shown at all, so no field is cut before it is masked.
The variable name decides what the command does with the value. With some
names, common programs print the value, write it into a file or a file
name, send it to a server, or run it, for example `LD_PRELOAD`,
`JAVA_TOOL_OPTIONS`, `GIT_TRACE`, `PS4` or `PYTHONWARNINGS`. The person
sees the name in the message, but may not know what it means. So the
broker refuses these names, before any message, grant or rule, and the
client refuses them before it asks. DESIGN.md section 5 lists them, with
the reason for each.
Risk that remains: masking is best effort and finds the common forms only.
A secret in another form is shown as it is, for example a plain word
(`htpasswd -b users.txt dev SECRET`) or an option of a program the broker
does not know. A hostile agent can always get a secret past masking. The
claimed text stays a claim. The command itself may print a secret; version
1 does not filter the command's output. The deny list of variable names
covers common programs only: a setting of another program can still show
its value, such as `UNZIP` for unzip. The agent also sets the rest
of the command's environment, which the message does not show, so a
hostile agent can set `LD_PRELOAD` there and read any value (section 5,
item 1). The deny list stops mistakes and simple tricks with the name that
the person sees.

**T16. The broker host is broken into.** Everything is lost. Advice: a
dedicated user, the systemd sandbox settings in the example unit
(`contrib/systemd/nodkey.service`), secrets as encrypted credentials
sealed with the TPM, no agent running on that host, updates. The broker
marks itself not dumpable, so other processes of its user cannot attach
to it or read its memory. Swap and hibernation write memory to disk, with
the keys, the tokens and, for a moment, secret values in it: use
encrypted swap or none, and no hibernation, on the broker host. The
example unit lets the broker use no swap (`MemorySwapMax=0`,
`MemoryZSwapMax=0`).
Risk that remains: real; out of scope.

**T17. The audit log is changed.**
Each entry holds the hash of the one before. That finds accidental damage
and simple edits, but not a careful attacker: with write access they can
change a line and compute every later hash again, or remove entries from
the end. So the broker also writes each entry's number and hash to the
systemd journal (`audit anchor SEQ:HASH`), after the entry is on disk. The
broker's own user cannot change the journal, so a break-in as that user
cannot hide its tracks there, if the journal is kept on disk long enough.
Forward the journal to another machine, and not even root on the broker
host can change the copies. Check the log with every anchor since it began
(`nodkey audit verify --anchors`), not only with the newest one: after a
restart, the broker builds on the log as it finds it, so its new anchors
also cover a change made while it was stopped. With every anchor, a changed
entry and a cut log are found, also when the broker wrote more entries
after the cut. A torn line from a power cut is not part of the chain, but
its `log_recovered` entry holds the torn line's length and hash, so a
change to it or its removal is found too. The broker locks the log, so a
second broker cannot write to it. `nodkey audit verify` never prints the
text of a line, only line numbers, because a line can hold a secret that
the masking missed (T15). On Linux, `chattr +a` makes the file append-only
for everyone except root.
The anchor lines are trusted only because no other broker output can
print a line that is exactly `audit anchor SEQ:HASH`: not a log line, a
panic, a server error or a child program's error output. A false anchor
line could make a good log fail, or make entries after the newest real
anchor look checked. So the broker logs with slog's text handler, whose
lines start with `time=` and escape a line break in a value. It never
logs claimed text or a panic value, and it cuts every other value, such
as an error text, to 1 KiB. The transport cuts net/http's lines to
printable ASCII, and store programs' error output is never read. A test
puts a line break and `audit anchor 1:…` into claimed text, errors, a
panic value and the certificate of a refused client, and finds no such
line.
Risk that remains:
- Without a copy of the journal on another machine, root on the broker
  host can rewrite the log unseen.
- Entries after the newest copied anchor can be removed unseen.
- `chattr +a` does not stop the broker user from appending entries that
  look right. An entry appended while the broker is stopped, with the
  right `seq` and `prev`, becomes the last entry at the next start, and
  the later anchors cover it. The anchors do not find it; only the missing
  `audit anchor` line for that entry shows it. An appended
  `log_recovered` entry can also make the last real entry look like a
  torn line. The anchor of that entry finds this. When the forged entry
  is the last entry, the next start also sends one alert about a torn
  line; when more entries were appended after it, nothing alerts at the
  start.
- A log that was removed or moved away looks like a new log. Its anchors
  and those of the old log differ, so check with the anchors since the
  current log began, and keep the old file.

**T18. The store programs leak a token.**
Tokens and the `bw` session go in environment variables, never on the
command line, so other users cannot see them in the process list. The `bw`
master password is not in a variable either: bw reads the password file
itself. The broker passes only `HOME`, the one variable with the token
or the session key, and for bw a fixed `PATH`, and nothing from its own
environment, so a variable such as `NODE_OPTIONS` or `LD_PRELOAD` cannot
change what the program does. The broker never logs the programs'
output, and its errors hold only a fixed text and the exit code. Tests
check all of this with made-up secrets and fake programs that record what
they get. If a store program crashes, a core handler such as
systemd-coredump would write its environment, with the token or the
session key, into the journal. So the broker sets its soft and hard
`RLIMIT_CORE` to 1, which the programs inherit and cannot raise, and the
example unit sets `LimitCORE=1`: with exactly 1 and a pipe (`|`) or file
`core_pattern` (the systemd default), the kernel calls no core handler. A
limit of 0 does not stop one, and a socket `core_pattern` (`@`) does not
look at the limit (DESIGN.md section 16). The broker reads the limits
back, and does not start if it cannot set them.
Risk that remains: low. The broker clears the token and the session key
in its memory, but only as best effort: Go strings and the copies that the
system call makes are not cleared.

**T19. The bot token leaks in an error message.**
Go's HTTP errors include the URL, and the URL holds the token. So no
error and no log line of the Telegram code holds Go's error text: only
the Bot API method, a fixed reason, and at most a number such as
Telegram's error code. Telegram's description of an error is never shown
either, because it can quote the message text. The Telegram code speaks
only HTTP/1.1, so Go's HTTP/2 debug output cannot print the URL, and it
follows no redirect, so no other server gets the URL. The types that hold
the token hide it when they are printed. A test with a made-up token
searches every error, log line and audit report for it. The log line
about a proxy shows only its host, never a user name or a password from
the setting.
Risk that remains: low.

**T20. A dependency or the build is tampered with.**
Few dependencies. Actions pinned to commit SHAs. `govulncheck` in CI.
Release binaries come with `SHA256SUMS` and a build provenance attestation.
The attestation proves which workflow built a file, not which version the
file is: `gh attestation verify` compares only the SHA-256 of the file. An
attested build of 0.1.0, renamed as 9.9.9, still passes. So a check must
also run `nodkey version` of the new file, and compare it with the version
it wants (step 3 of
[docs/releasing.md, "Verify a download"](docs/releasing.md#verify-a-download)).

The installer, `install.sh`, and `nodkey update` do all these checks
before they install anything (DESIGN.md section 18). What they trust:
- The first install runs `install.sh` from `main`, as GitHub serves it.
  Whoever can change `main` can change the script. But they can also
  change the code of the next release, which the release workflow then
  builds and attests. So the script from `main` is as trusted as a build
  from `main`. A person can read the script before running it, or install
  by hand ([docs/setup.md section 2](docs/setup.md#2-get-nodkey)).
- An update with `nodkey update` runs the copy of the script that is
  built into the installed nodkey. That build was checked when it was
  installed. So nothing fresh from the network decides how a new release
  is checked.
- Both trust the gh that checks the attestation: gh 2.102.0, downloaded
  and checked against the SHA-256 in the script (its tarballs passed
  `gh attestation verify --repo cli/cli` when it was pinned), or the gh of
  `--gh`. They trust Sigstore: its trusted root, which gh gets online,
  and its certificate authority. They trust GitHub to say truthfully which
  workflow, on which branch and on which kind of runner, signed: the
  identity `.github/workflows/release.yml@refs/heads/main` and
  `--deny-self-hosted-runners`.
- Both trust root on the host where they run, and the way the person got
  root. As root, the script runs only the programs of the system, removes
  the variables that change what they do (such as `TAR_OPTIONS`), and
  refuses a bin directory, an old file, a gh of `--gh` or a temporary
  directory that another user can change. `nodkey update` gives the
  script a fixed environment. But a root shell that comes through the
  account of the agent, such as `sudo` in the agent's terminal, trusts
  that account: the agent can put its own `sudo` first in `PATH`, or type
  into the terminal. So on an agent machine, get root on the console, or
  with SSH as an admin user from a trusted computer
  ([docs/setup.md section 2](docs/setup.md#2-get-nodkey)). Never set up
  or update the broker host through an agent machine.
- On an agent machine that the agent controls, nodkey cannot keep its
  own client safe (section 3: the agent may be root there). The broker
  trusts nothing from the client, so a changed client gets no more than
  what the person approves on the phone.

The `bws` and `bw` programs are outside nodkey. They can be attacked too:
a malicious `@bitwarden/cli` 2026.4.0 was on npm for about 90 minutes on
2026-04-22
([Bitwarden's statement](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)).
Risk that remains:
- Normal open-source risk.
- Accepted on 2026-10-14: the release App `code6x-release` is shared with
  other code6x repositories, and each of them holds one of its keys. With
  any of these keys, someone can get a token that writes to nodkey:
  - They can create a new `v*` tag and publish a release with their own
    files and their own `SHA256SUMS`, with no pull request and no CI. Only
    the build attestation shows that the release workflow did not build
    these files. The installer and `nodkey update` refuse such a release.
    A check by hand must run `gh attestation verify` (see
    [docs/releasing.md](docs/releasing.md#verify-a-download)).
  - They can publish a new tag with the attested files of an older
    release under new names, such as the files and the bundle of 0.2.0
    as 0.3.0. The checksum and the attestation pass, and an old build,
    maybe one with a known security bug, would be installed. The
    installer and `nodkey update` refuse it: the new nodkey does not say
    that it is the version of the tag. A check by hand must run
    `nodkey version`.
  - They can make an older release the newest one on GitHub. Then
    `nodkey update` installs nothing, as it never installs an older
    version without `--version`. But a first install gets that older
    release. The installer prints the version that it installs.
  - A release that the installer refuses also stops `nodkey update`
    without `--version`, until a good newer release comes.
  - They can open a pull request, merge it once CI passes (`main` needs no
    human approval), and get it released. Such a release even has a valid
    attestation, and the installer installs it. In the same way they can
    change `install.sh` on `main`, which a first install runs.

  The rulesets still stop them from moving or deleting a `v*` tag, and
  immutable releases stop changes to a published release.

**T21. Telegram, the network or the phone is down.**
Requests expire and are denied. The agent waits, then fails. `nodkey run`
waits at most 15 minutes for the broker's answer, then exits with 69, so
a broker that hangs does not hold it for ever. A request whose message
cannot be sent is denied. If the polling stops for good, the
broker denies every request from then on, also one that a grant would
allow, and it stops. Also, the
requests that wait for the person are denied at once, and a message or
notice that is still being sent stops. A "never ask" use whose notice
cannot be sent is denied too, and it still counts for `max_per_day`,
because the broker cannot tell if the notice went out. If the broker host
sleeps, requests and grants still end on the wall clock.
Risk that remains: the agent's work stops. That is the safe way to fail.

**T22. A client uses a secret meant for another client.**
Each secret and key lists its clients. The client name comes from the
pinned TLS key, not from anything the client says: not from the request,
not from the names in its certificate, and not from the server name it
asks for. The TLS layer stores the name for the connection, and the broker
refuses a request without it.
Risk that remains: none known.

**T23. Telegram learns about the household or company.**
Messages show machine names, host names, secret names, commands and
reasons. Telegram can read them.
Risk that remains: accepted. Choose names with this in mind.

**T24. The `bw` master password is on the broker host.**
The Password Manager CLI cannot unlock without it, so an unattended broker
must keep it. A break-in on the broker host then gives the whole vault.
nodkey supports `bw` only with a separate account that holds nothing but
the items nodkey may hand out. Prefer `bws`, whose token sees only the
projects you give it.
Risk that remains: everything in that separate account.

**T25. Two machines share one host key.**
Cloned machines often do. Then a grant for one also covers the other, and
the message names the wrong machine. The broker refuses a `known_hosts`
file where one key has two names.
Risk that remains: a host key that was copied to a machine the broker does
not know about.

**T26. Another user on the broker host reads a key or changes what the
broker trusts.**
A key, token or password file that others can read gives them the secret.
A config file, `known_hosts` file or store program that others can change
lets them change the rules, the host names, or the program that gets the
store token. So at start the broker checks these files (DESIGN.md section
14). It refuses a key, token or password file that group or others can
read, also through an ACL entry. It refuses such a file if it is a
symbolic link, or if it is not on a local file system that nodkey knows
(such as ext4 or tmpfs); a network file system or FUSE is refused. On
overlayfs and ecryptfs, nodkey checks the file you name. It refuses a
config file, `known_hosts` file or store program that group or others can
write to. It refuses an audit log that is a symbolic link, that another
user owns, whose mode gives more than read and write to its owner, or that
is another file the broker reads or runs, such as a key file or the config
file (people read and copy the log, and the broker adds to it). It refuses
all of these below a directory that group or others can write to, also a
directory that holds a symbolic link on the way.
nodkey opens each file once, checks the open file, and reads from that
same open file. So the file cannot be swapped between the check and the
read. The client checks its own TLS key in the same way, and reads its
config file as the broker reads its config file: other users must not be
able to change `broker_pin`, the client's only trust in the broker.
`nodkey keygen` writes a new key file with mode `0600`, never over a file
or a link that is there. It checks the directories and the new, empty file in the same
way before it writes the key.
Each store program keeps its state, such as bw's copy of the vault, in
its own home directory, with mode `0700`, owned by the broker user, below
directories that pass the same checks. The broker refuses a `bw-data`
directory next to bw's executable, where bw would keep its state instead.
bw reads its password file by its path; the broker checks the file right
before each unlock. The directories in bw's `PATH` pass the same checks,
and the `node` in them passes the checks of a store's program, also after
its links, so nobody else can put or change the `node` that a bw script
starts.
Risk that remains: root and the broker user can still change everything
(T16); for example, they can swap the bw password file between the check
and bw's read. The libraries that a store program loads are not checked.
On overlayfs, nodkey sees only the mode bits of the top copy of a file; a
lower copy of a key can be readable by others who can reach the lower
layer (DESIGN.md section 14). Keep keys and tokens out of lower layers and
image layers.

**T27. A mistake in the config file allows more than the approver meant.**
A typo must never turn a rule off. Config files are strict: an unknown key,
a key in another case (`ASK`), a key outside the header of its own section
(a dotted key or an inline table), a missing key, or a value out of range is
an error, and the broker does not start. A "never ask" rule names exactly
one client. A `window` shorter than one minute is an error, so it cannot
quietly act like `always`. The approval core checks the rules again: it
denies an `ask` value it does not know (also an empty one), a `window`
outside 1 minute to 8 hours, a "never ask" rule that does not name
exactly one client, and a "never ask" rule for a key without hosts. Two
"never ask" secrets cannot use one store item, and two `[key.*]` sections
cannot use one key file. A copy of a key in a second file passes that file
check, so when the broker loads the keys, it also refuses two `[key.*]`
sections with the same public key. `max_per_day = 0`
is an error, not "no limit". `listen` must be one IP address, so the
broker does not listen on every network by mistake; a multicast or
broadcast address, an IPv6 zone and an IPv6 link-local address are
refused too. An error may show a file path, or a section name or key name
that looks normal, but never a secret value. A name that does not look
normal is not shown, because a mistake can put a token there. An error
can show a path, so do not paste a secret into a path setting.
Risk that remains: a rule that is valid but wider than the approver meant.
The broker cannot know what the approver meant. Review each change to the
config.

**T28. A peer sends large, slow, broken or many requests.**
A hostile agent has the client's key (T11), so it can send any request.
Any other machine that can reach the broker port can at least start a TLS
handshake.
- The broker reads at most 2 MiB of request body, and at most 12 KiB of
  request headers. It drops a peer that is too slow: 10 seconds for the
  TLS handshake and the headers, 30 seconds for the whole request, and 30
  seconds to take each answer.
- A body must be one strict JSON object: no unknown keys, no repeated
  keys, keys only in lower case, at most 16 levels deep, at most 256 keys
  in one object and 65,536 values in all. The broker checks this in one
  pass over the bytes before it decodes the body. Measured on 2026-10-14
  on a desktop computer, the worst body of 2 MiB then costs about 70 ms of
  CPU time and 20 MiB of memory; without the limits, it cost 180 ms and
  250 MiB.
- An error answer gives only the HTTP status. A panic in a handler drops
  the connection, and the log shows where it happened, never the panic
  value. The request is denied, and the audit log records it, also when
  the panic came before the approval core gave the request an ID; only a
  broken audit log cannot record it.
- The broker works on at most 32 requests of one client at a time, and
  refuses more at once (429). The approval core lets at most 15 requests of
  a client wait for the person (5 messages and a queue of 10), and grants
  let more pass quickly, such as the parallel logins of Ansible. So the cap
  does not stop normal work.
- Reading and cleaning the largest valid body takes about 20 MiB for a
  moment. So the broker reads and decodes at most 4 bodies of one client
  and 16 in all at the same time; another request waits for a place, at
  most 10 seconds, and then gets 429. That bounds this memory to about
  80 MiB for one client, and 320 MiB in all.
- The broker's log holds no text that a peer chose. A refused handshake
  gives one short line with the remote address and a fixed reason. The
  broker logs at most 60 lines about connections per minute, 60 with the
  pins of keys that no client has, and 60 about the requests of the
  clients, so other peers cannot crowd out the lines about the clients
  (DESIGN.md section 10). So a peer cannot flood the journal, or write a
  line into it that looks like an audit anchor.
Risk that remains: there is no limit on the number of connections. Any
peer that can reach the broker port, even without a key, can hold a
connection for up to 10 seconds, and makes the broker do a key exchange
for each new one. A client with a valid key can send up to 32 requests at
once, and many requests one after the other. A request that a limit
denies, or that comes after the approver stopped, costs the client
nothing, so the broker writes the entries of at most 20 such requests of
a client in a minute, and counts the others in its log; it also logs at
most 20 lines a minute about SSH logins and variable names that a check
refused. Every other request writes at least two audit entries, also
when it is denied, such as one for a name that does not exist, so such a
client can still fill the disk over time. All of this uses memory, CPU
and disk on the broker host. That is a denial of
service, not a way to get a secret or an approval. The answer is a
firewall that lets only the agent machines reach the broker port
(DESIGN.md section 10), and a check of the log's size.

**T29. A store program hangs, floods, or answers wrong or old data.**
The broker gives each run of a store program 30 seconds and caps its
output: 1 MiB on stdout and 64 KiB on stderr. Over a limit, or when the
request ends, it kills the program's whole process group, and the request
is denied. If the broker itself ends during a run, the kernel kills the
program. The broker reads only one strict JSON object, and denies
anything else: an answer without the asked ID or for another item, and a
missing or empty value, or one with a NUL byte. bw keeps a copy of the
vault, so the broker runs `bw sync --force` before each fetch, and denies
the request if the sync fails. Without `--force`, bw would compare the
server's time with the broker's clock, and with that clock ahead it would
never download again. An item in the trash or in the archive is refused,
because `bw get item` still returns such an item by its ID. If bw is
logged out, every request for that store is denied until a person logs in
again (DESIGN.md sections 11 and 16). With a pipe or file
`core_pattern`, a crashed program writes no core dump and starts no core
handler (T18).
Risk that remains: a process that leaves the program's process group (for
example with `setsid`) is not killed; systemd stops it when the service
stops. Such a process keeps the token or the session key in its
environment.

**T30. Another user on the agent machine uses the agent socket.**
With the socket, a user could ask for signatures in the name of this
client, and the message would show this machine. `nodkey ssh-agent` puts
its socket in a directory of the user with mode `0700`, below directories
that no other user can change, and gives the socket mode `0600`. It also
asks the kernel who connected (`SO_PEERCRED`), and closes the connection
of any other user, also of root, before it reads a request. It never
removes a file that is not a socket of the user, or a socket that a
program serves, and it holds a lock while it runs, so a second agent on
the same path does not start (DESIGN.md section 15).
Risk that remains: root on the agent machine can still act as the user,
and so use the socket. Root can read the client's TLS key anyway (T11),
and every request still needs the approver. Any process of the user can
keep the agent busy, but it serves at most 128 connections at the same
time, and a message takes memory only as its bytes come. That is a
denial of service, which a process of the user can cause anyway.

**T31. A process on the agent machine writes into the agent's log.**
Any process of the user can send `nodkey ssh-agent` requests, and the
agent's stderr may go to a terminal or to the journal. The agent server
of `golang.org/x/crypto` writes the text of each error to Go's global
logger, without escaping and without a limit. So `nodkey ssh-agent`
serves the agent protocol itself, and sends Go's global logger nowhere.
Its own lines hold fixed text, numbers, the short code, the broker's
release version, the broker's address, the socket's path and errors of
the operating system, never text that a process sent. A process can also cause many lines with a short
code: the broker sends one for every request that starts to wait, also in
its queue, and a request that hangs up frees its place. So the agent
writes at most 60 lines with a short code, and 60 about refused and
failed requests, in a minute, each kind with its own budget, and says
how many it left out. A test checks that a refused request gives one
fixed line, and nothing in Go's global logger.
Risk that remains: low. A process can still fill a budget. Then the
other lines of that kind are left out for the rest of that minute, also
the short code of a real request. The person can still match the message
on the phone by its verified lines: the host, the key and the remote
user.

**T32. A Bitwarden account that can read the secrets is logged in on an
agent machine.**
nodkey keeps the store token and the `bw` master password on the broker
host, so the agent gets a secret only through the broker. But people can
also read the secrets with their own Bitwarden accounts, in Bitwarden's
own apps. Such a read needs no tap, and nodkey's audit log does not show
it. A common setup keeps the main Bitwarden account logged in on the
agent machine: in the web app in a browser, the browser extension, the
desktop app or the CLI. The agent may be root there. It can read what
these apps show, and it can record the master password when you type it.
So if that account can read the secrets, the agent can read them too,
without nodkey. The same holds for a device with such a login that the
agent machine can control, such as a phone through `adb` or KDE Connect
(T7).
These accounts can read the secrets:
- For `bw`: the separate account (T24), every account that you share its
  items with, and every account that you give emergency access to it.
  When an emergency access request is granted, a "View" contact gets
  "view/read access to all items in your individual vault, including
  login items' passwords"
  ([emergency access](https://bitwarden.com/help/emergency-access/), seen
  2026-10-16).
- For `bws`, by Bitwarden's documentation and source code (seen
  2026-10-16):
  - every owner and admin of the organization. They "automatically have
    Can read, write access to all secrets, projects, machine accounts,
    and access tokens"
    ([member roles](https://bitwarden.com/help/manage-your-secrets-org/));
  - the member who made the project. Bitwarden gives this member read and
    write access to it
    ([source](https://github.com/bitwarden/server/blob/96fe09af893006195e6ecc50e7f6c8b786dea25d/bitwarden_license/src/Commercial.Core/SecretsManager/Commands/Projects/CreateProjectCommand.cs)),
    and its help page says such a member "can edit these objects once
    created"
    ([member roles](https://bitwarden.com/help/manage-your-secrets-org/));
  - the members and groups that you added to the project. They "will be
    able to view existing secrets in this project"
    ([projects](https://bitwarden.com/help/projects/));
  - the people that you gave access to one of its secrets directly. That
    lets them "interact with it from the Secrets view"
    ([secrets](https://bitwarden.com/help/secrets/));
  - the members and groups that you added to a machine account that can
    read the project or one of its secrets. They can "generate access
    tokens for the machine account and interact with all secrets the
    machine account has access to"
    ([machine accounts](https://bitwarden.com/help/machine-accounts/)).

What to do:
- Never log in on an agent machine to a Bitwarden account that can read
  the secrets: not in the web app, the browser extension, the desktop app
  or the CLI.
- Do not save the master password, the API key or the key of the
  two-step login of these accounts in a password manager that is open on
  an agent machine, such as your main Bitwarden account. With them, the
  agent could log in to the account from anywhere.
- If your main Bitwarden account is logged in on an agent machine, make
  the organization for Secrets Manager with a separate account, and do
  not add your main account to it.
- For `bw`, share the items of the separate account with no other
  account, and give no account emergency access to it.
- After each change to the organization, check who is an owner or an
  admin, and who is on the People tab of the project, its secrets and its
  machine accounts.
- Turn on two-step login for these accounts, with an authenticator app or
  a security key. A code by email does not help if you read that email on
  an agent machine.

Risk that remains: real. nodkey cannot see a read in Bitwarden's own
apps, and it cannot check where an account is logged in.

**T33. A client claims a false version.**
Each request has the client's version in a header, and each answer the
broker's (DESIGN.md section 10). Anyone with the client's key (T11) can
send any value there. So the broker takes it only as a claim: it changes
no answer, no check and no audit entry, and the request never waits for
it. A value that does not match the strict rule of a version counts as
none, and is never logged or shown. A false claim can cause one wrong
line in the journal and one wrong notice for that client in each start
of the broker, rarely more than one notice, however many values the
client sends.
A notice that did not go out is tried again, at most once a minute for
each client, with a journal line for each failed try. The notice is
silent, shows only the client's name from the config and release
versions, which are digits and dots, and has its own limit of 3 in a
minute. So it does not take from the limits of the notices of "never
ask" uses (T9), and it cannot fill the notice chat. The check is cheap,
so it adds nothing to T28.
The other way, the client takes the broker's version only from the
pinned connection (T10), and shows only release versions from it. So
every pinned client, also a hostile agent with the client's key (T11),
learns the exact version of the broker: whether it misses a security
fix of a newer release. A peer without a pinned key learns nothing: the
TLS handshake fails before any answer. After a security release, update
the broker first.
Risk that remains: low. A false claim can only send the person to update
a machine that is up to date (also the broker host), or hide that a
client is old. To know what runs on a machine, run `nodkey version`
there.

**T34. The check for a newer release tells GitHub about the broker, or
gets a false answer.**
A release of the broker asks GitHub's API for the newest release of
nodkey: 10 minutes after its start, and then once a day, unless
`[updates]` says `check = false` (DESIGN.md section 15). `nodkey version`
does the same on a terminal. The call has no login and holds no secret.
GitHub learns the address of the host, or of its proxy, the time of each
check, and the exact version of nodkey from the User-Agent: so it can
tell whether the broker misses a security fix. A proxy learns that the
host talks to GitHub.
A false answer can come from GitHub itself, from a proxy that inspects
TLS, or from any CA that the host trusts: one in the system's store, or
one in `SSL_CERT_FILE` or `SSL_CERT_DIR` (DESIGN.md section 7).
- It can name a newer release that does not exist, hide one, or make
  the check fail. The notice and the line of `nodkey version` show only
  release versions, which are digits and dots, and a link that nodkey
  makes from the version: never text or a link from the answer. A tag
  that is not `vX.Y.Z`, a draft, a prerelease, a redirect, or an answer
  over 1 MiB is an error. Each error gives one line with a fixed text,
  and no notice.
- It cannot install anything. The notice only says what to run.
  `nodkey update` checks the attestation of the release and the version
  of the new binary before it installs (T20). A release that does not
  exist, or a file that the release workflow did not build, fails there.
- The check never touches a request, a secret, the audit log or an
  approval. Its notices are silent, and share the limit of 3 in any 60
  seconds with the notices about versions (T9, T33). In each start, each
  newer release gets one notice, rarely more than one: a try that times
  out after Telegram took the message sends it again, at the next check
  1 hour later. The first check of a start comes 10 minutes after it.
  So a broker that systemd starts again and again sends no notice,
  unless each start runs for 10 minutes or more; then it sends at most
  one in each start, about 6 an hour. So it cannot fill the notice chat.

Two cases are worse than a wrong notice:
- GitHub allows 60 calls an hour without a login from one address. An
  agent machine behind the same public address as the broker host can
  use them up, such as with `nodkey version` on a terminal in a loop, or
  with `curl`. Then each check of the broker gets 403 or 429, and a
  security release gets no notice. Only the journal shows it: one line for each
  failed check.
- A release that the release workflow built from a merged pull request
  passes the attestation check of `nodkey update` (the risk that T20
  accepts). Within a day of each release, the notice asks every owner to
  install it. So such a release reaches more brokers, and sooner.

Risk that remains: low. A false answer, or calls that an agent uses up,
can hide a security release for a while: also watch the releases of the
repository on GitHub, and read the release notes before you update. A
false answer can send the person to run `nodkey update` for no reason,
which then installs nothing. To keep the address and the version from
GitHub, set `check = false` in `[updates]`, and use
`nodkey version --offline`.

**T35. A planned grant is used by something else on the same client, or
is asked for with a false reason.**
A scheduled grant (DESIGN.md section 8) lets a client use named secrets,
or a key at listed hosts, inside a time span, a number of times, without
a tap. The broker knows the client only by its TLS key. So anything on
that client can use the grant inside its time: the agent, another
program, or the job that was meant to. This is the risk of a "never ask"
rule (DESIGN.md section 12, decision 3 B) again, but smaller.
- The agent can ask for a scheduled grant at any time, with any reason,
  such as "job nightly-backup". The reason is claimed, as all text of the
  client (T2, T3). The person cannot check that such a job exists, so a tap
  must be read as "this client may use these secrets in this time", and
  nothing more. The message shows the secrets, the uses and the span as
  verified lines, and the reason below the claimed line.
- It needs a tap, which a "never ask" rule does not. It ends by itself.
  Its uses are counted. If something else uses up the grant, the real
  job fails, and that is a visible sign. Each use sends a silent notice
  (T9), and a use whose notice cannot be sent is denied.
- It is off unless the rule of the secret or key says `preapprove = true`.
  The limits of `[preapprove]` bound it: how far ahead it starts, how long
  it is open, how many uses, and how many grants a client holds. The
  `window` of the rule does not cap it, so a rule with a short window
  does not mean a short grant: the owner who sets `preapprove = true`
  accepts the limits of `[preapprove]`.
- A grant covers a request only as a whole, and is not mixed with other
  grants or rules. A run that asks for one more secret needs a tap.
- A Deny of the same client for a secret of the grant ends it, also before
  its start. The client can cancel its own grant, which only takes a right
  away. So can the person, with the **Revoke** button on the message of the
  grant. A forged or replayed Revoke tap can only take a right away, so it
  cannot start or widen a grant. A Revoke skips the check of a changed
  message (T6), because it only takes a right away, and it never raises
  the alert about a changed message, except on a message whose request
  may still wait: there it is refused as a changed message, with the
  alert. The alert still comes from the other taps. Every other check stays: the approver's user ID, the private chat,
  not an inline message, strict button data, and in the core the grant of
  the request ID on that very message. So a Revoke also counts on a
  message that Telegram sends without content (older than 48 hours). A
  tap on a grant message with the button of another request is refused
  as a changed message, with the alert. A Revoke on a grant that has ended is
  refused as a late tap. A Revoke that does not count is a `foreign_tap`
  entry. One that counts is the `grant_ended` entry with cause `revoked`.
  Another client's ID and an unknown ID get the same answer, so a
  client cannot learn which grants others hold.
- The agent can fill the phone with requests for grants. They count as
  other requests toward the limits per client (DESIGN.md section 8), and
  `max_grants` bounds the grants that wait or stand.
- Time: the start is read on the wall clock; the end has come when either
  clock reaches it. A wall clock that someone sets forward on the broker
  host can start a grant early (T16 covers that host). One that is set
  back cannot make a grant last longer, and cannot give more uses.
- Grants live in memory. A broker restart drops them. A grant that ends
  with uses left sends a silent "not used" notice, and a stop sends one
  notice that lists the dropped grants, so the person learns that a job
  will ask for a tap. These notices are the broker's own text, with names
  from the config and checked IDs; the "not used" notice also shows the
  claimed reason below the claimed line, cleaned and masked as in every
  message. If they cannot be sent, they are
  logged; the audit log has every end.
- A grant must not outlive the client that asked for it. If the client
  hangs up, or its answer cannot be written, after the grant started, the
  broker cancels the grant and writes `grant_ended` (`cancelled`), as for
  a cancel of the client. An answer that the client does not
  read (a signal, a connection that breaks after the flush, a timeout)
  leaves a live grant whose ID the client does not have (a small window,
  as for `nodkey ssh-grant`, DESIGN.md section 13). The client says so,
  and the ID is in the `grant_id` of the audit entries of the request. The grant is bounded by its
  limits, and the person can cancel it.
Risk that remains: for the time of a grant, anything on the client can
use up to N uses of what it names. After a use, the secret stays on the
agent machine (section 5, item 1). Choose short spans, few uses and
narrow secrets, as for a "never ask" rule.

**T36. A standing grant is used by something else on the same client.**
A standing grant (DESIGN.md section 8) lets a client use named secrets in
daily or weekly windows for weeks, without a tap. The broker knows the
client only by its TLS key, so the grant also has a token that changes at
each use. The token is in a file on the client.
- **The honest limit.** The token finds a theft; it does not stop it. The
  same user can read the token file, and can rewrite it. A thief who
  copies the token and uses it first gets the secrets once. The real job
  then comes with the old token, and the broker ends the grant and sends
  an alarm. A thief who reads the file and writes back the new token each
  time can use the grant like the job. Then the one-use-per-window rule
  (`over_uses`) and the missed-window alarm are what catch it.
- The broker keeps only the SHA-256 hash of each token. A token works only
  with the TLS key of its client, so a copy on another machine gets an
  alarm and no secret.
- Old token, or more uses than allowed: the request is denied, the grant
  ends and an alarm comes. A retry after a lost answer looks the same, so
  the client saves the new token before it uses the secrets and never
  retries by itself. A new grant is one tap, so there is no pause state.
- A valid token outside the windows is denied with an alarm, and the grant
  stays; this holds also before the start of the grant, and the day's
  alarm counts only if it was sent. The current or old token of another
  client's grant has left its machine: the request is denied and that
  grant ends, with an alarm that names it. An unknown token is denied with
  a rate-limited alarm; it may be a guess. Alarms have sound, count toward
  the 20 notices in all, and one grant sends at most one in a window.
- Run the job as its own system user, so an agent that runs as another
  user cannot read the token file. The client refuses a token file that
  others can read or write, or that it does not own. Root can still read
  it.
- A standing grant is wider than a scheduled grant, so it has its own rule
  flag (`standing = true`), its own limits (`[standing]`), and a weekly
  list of all standing grants on the phone.
- A Deny of another request does not end a standing grant, so a Deny
  cannot be used to break the job. The person ends it with **Revoke**.
- **Renew** gives a right, so a Renew tap has every check of an Approve
  (T6): the approver's user ID, the private chat, strict button data, a
  warning message that nobody changed, and in the core the grant of the
  request ID with that very warning. Its `decision` entry is on disk before
  the new grant exists. The new grant has no token: only the next use of
  the old grant's token, which the job holds, gets one. So a forged Renew
  cannot give a new token to anyone who does not hold the old one. The old
  tokens pass to the new grant, so a stolen old token is still an alarm,
  and an alarm or Revoke of the old grant also ends a renewal that waits.
- Standing grants live in memory and are dropped at a broker stop. The
  stop notice lists them (T35).

Risk that remains: the same as T35, for weeks. Choose few uses, short
windows, narrow secrets and a near end date.

## 7. Assumptions

- The broker host is patched, has no agent on it, and only the owner has
  root. It has a TPM2 chip, or the owner accepts that a full disk copy
  gives the credentials.
- The broker host is set up from its console, or from a trusted computer
  where no agent runs. Its tokens and passwords are made and copied only
  there or on the phone, never through an agent machine. No agent
  machine holds a way to get root on the broker host, such as an SSH
  key, an SSH agent or a `ControlMaster` socket.
- Root installs the nodkey binary on each host, from a root shell that
  does not come through the account of the agent, and the user of the
  agent never downloads, builds or copies it. Root runs `install.sh` or
  `nodkey update` on the host itself, which check the release (T20). Or
  the binary comes straight from a trusted machine where it was built or
  downloaded and checked, and its SHA-256 is checked on the broker host
  ([docs/setup.md section 1](docs/setup.md#where-you-do-the-setup)).
- Only root can change the nodkey binary and its directory, such as
  `/usr/local/bin`. `nodkey update` runs, as root, the script that is
  built into that binary.
- The approver's Telegram account is not logged in on any agent machine.
- No Bitwarden account that can read the secrets of the stores is logged
  in on any agent machine, and no agent machine can read its master
  password.
- The approver reads the verified lines before tapping.
- The `ssh` program on the agent machine is OpenSSH 8.9 or newer, so it
  sends session-bind. It uses a key exchange with SHA-2, as it does by
  default.
- The broker's `known_hosts` file is correct, and each host has its own
  host key.

## 8. Review

This file changes with the code. Every pull request that changes what a
message shows, what the broker checks, or where a secret goes, must update
this file in the same pull request.
