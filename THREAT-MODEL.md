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
| secret-store access (`bws` token, `bw` master password) | broker host |
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
   nothing is approved unless its record is on disk first.

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

## 6. Threats and answers

Each item: what could go wrong, what nodkey does, and the risk that
remains.

**T1. The agent asks for a secret it should not have.**
Only names in the broker config exist, and each lists the clients that may
use it. Unknown names are denied without a message.
Risk that remains: none beyond the rules the approver wrote.

**T2. The agent lies about the command or the reason.**
These fields are marked as claimed, below the verified ones.
Risk that remains: the person can still be fooled. Deny any request that
looks strange.

**T3. The agent fakes the look of the message.**
It could put new lines, fake "✅ machine:" lines, direction marks, HTML or
links in its text. Claimed text is made one line per field, control and
invisible characters are removed, length is capped, HTML is escaped, the
text sits in `<code>`, link previews are off, and claimed fields always
come after the verified ones. The verified part holds only names from the
broker's config and data the broker checked. The broker itself checks that
the remote user name matches a strict pattern, and that environment
variable names match `[A-Z_][A-Z0-9_]{0,63}`; variable names are shown as
claimed. The broker never relies on checks done by the client.
Risk that remains: low.

**T4. An old or repeated tap approves something new.**
Each request has a new random 128-bit ID in the button. It works once, only
on its own message, only while the request waits, and only before it
expires. A restart forgets all IDs.
Risk that remains: none known.

**T5. Someone else presses the button.**
The broker accepts only the configured Telegram user ID, in the private
chat with that user.
Risk that remains: see T7.

**T6. The bot token is stolen.**
With the token, an attacker can read updates before the broker does, send
messages as the bot, and edit or delete the bot's messages. They cannot
press a button as the approver. Stolen updates make requests time out,
which means deny. A fake message from the bot with fake buttons sends IDs
the broker does not know, so they are refused. When another program polls
with the same token, Telegram reports a conflict, and the broker sends an
alert.
Risk that remains: denial of service, and misleading text in the chat.
Keep the token in an encrypted credential; make a new one if it leaks.

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
Grants for N minutes and `ssh-grant` cut the number of taps. Limits stop
floods. The message is short and puts the verified lines first. Notices
about "never ask" uses can go to a separate chat, so the approval chat
stays for real decisions.
Risk that remains: the person may still tap without reading.

**T9. The agent floods the phone.**
Per client: at most 5 waiting messages and 6 new messages per minute; a
queue of at most 10; after a Deny, requests for the same secret or key are
denied without a message for 60 seconds.
Risk that remains: low.

**T10. Someone on the network reads or changes the traffic.**
TLS 1.3, with both sides' keys pinned. The pin is checked on every
connection, and TLS session resumption is off.
Risk that remains: low.

**T11. The client's TLS key is copied.**
The agent is root on its machine, so it can copy the key. With it, the
attacker can only ask, like the agent. To block a client, remove its pin
from the broker config and restart the broker.
Risk that remains: same as the agent itself.

**T12. A signature is used for a different host or a different purpose.**
The broker only signs SSH authentication requests for the asked key. It
checks the session-bind signature and the session identifier. It refuses
clients without a session-bind, forwarded binds, and any other kind of data
(for example git commit signatures). The forwarding flag comes from the
client, so refusing it stops honest mistakes, not a hostile agent; the
host check above does not depend on that flag.
Risk that remains: low.

**T13. The agent keeps access after an approved login.** See section 5,
item 2.
Risk that remains: real; outside nodkey.

**T14. The agent keeps a secret after approval.** See section 5, item 1.
Use short-lived or narrow secrets, and rotate a secret after a strange
request.
Risk that remains: real.

**T15. A secret leaks by accident into logs, messages or the agent's
output.**
No print command. Values that nodkey fetched are never logged, never in
errors, never in the audit log, never in Telegram. Store program output is
never logged. A command line can hold a secret the agent typed in (for
example `mysql -pSECRET`), and it would go to Telegram and the audit log. So
the broker masks values that look like secrets, and shows at most 8
arguments.
Risk that remains: masking catches common forms only. The command itself
may print a secret; version 1 does not filter the command's output.

**T16. The broker host is broken into.** Everything is lost. Advice: a
dedicated user, the systemd sandbox settings in the example unit, secrets
as encrypted credentials sealed with the TPM, no agent running on that
host, updates.
Risk that remains: real; out of scope.

**T17. The audit log is changed.**
Each entry holds the hash of the one before. That finds accidental damage
and simple edits, but not a careful attacker: with write access they can
change a line and compute every later hash again. So the broker also
writes each entry's number and hash to the systemd journal. The broker's
own user cannot change the journal, so a break-in as that user cannot hide
its tracks there, if the journal is kept on disk long enough. Forward the
journal to another machine, and not even root on the broker host can change
the copies. `nodkey audit verify --anchor` then finds any change before a
copied hash. On Linux, `chattr +a` makes the file append-only for everyone
except root.
Risk that remains: without a copy on another machine, root on the broker
host can rewrite the log unseen.

**T18. The store programs leak a token.**
Tokens and the `bw` session go in environment variables, never on the
command line, so other users cannot see them in the process list. The
broker passes only the variables the program needs.
Risk that remains: low.

**T19. The bot token leaks in an error message.**
Go's HTTP errors include the URL, and the URL holds the token. The Telegram
code removes the URL before it logs anything. A test checks it.
Risk that remains: low.

**T20. A dependency or the build is tampered with.**
Few dependencies. Actions pinned to commit SHAs. `govulncheck` in CI.
Release binaries come with `SHA256SUMS` and a build provenance attestation.
The `bws` and `bw` programs are outside nodkey. They can be attacked too:
a malicious `@bitwarden/cli` 2026.4.0 was on npm for about 90 minutes on
2026-04-22
([Bitwarden's statement](https://community.bitwarden.com/t/bitwarden-statement-on-checkmarx-supply-chain-incident/96127)).
Risk that remains: normal open-source risk.

**T21. Telegram, the network or the phone is down.**
Requests expire and are denied. The agent waits, then fails.
Risk that remains: the agent's work stops. That is the safe way to fail.

**T22. A client uses a secret meant for another client.**
Each secret and key lists its clients. The client name comes from the
pinned TLS key, not from anything the client says.
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

## 7. Assumptions

- The broker host is patched, has no agent on it, and only the owner has
  root. It has a TPM2 chip, or the owner accepts that a full disk copy
  gives the credentials.
- The approver's Telegram account is not logged in on any agent machine.
- The approver reads the verified lines before tapping.
- The `ssh` program on the agent machine is OpenSSH 8.9 or newer, so it
  sends session-bind.
- The broker's `known_hosts` file is correct, and each host has its own
  host key.

## 8. Review

This file changes with the code. Every pull request that changes what a
message shows, what the broker checks, or where a secret goes, must update
this file in the same pull request.
