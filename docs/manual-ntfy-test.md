# Manual test with a real ntfy server

The tests of nodkey use a fake ntfy server. It cannot prove that the real
server and the real phone apps behave the same. This test runs a
throwaway broker with a self-hosted ntfy server, and you tap the buttons
on an Android phone and on an iPhone. It is the manual test of issue
[#24](https://github.com/code6x/nodkey/issues/24). Write the results into
that issue.

What the test checks:

| issue #24 asks | checks |
|---|---|
| Messages reach Android and iOS, with a self-hosted server and the upstream. | [1](#check-1-delivery) |
| Approve once, Approve N min and Deny work, as `http` actions. | [2](#check-2-approve-once), [3](#check-3-approve-n-min), [4](#check-4-deny) |
| The message is replaced (same sequence ID) when a request ends. | [2](#check-2-approve-once) to [5](#check-5-expiry) |
| A late or second answer changes nothing. | [6](#check-6-second-tap), [7](#check-7-late-tap-after-a-restart), [8](#check-8-a-forged-answer) |
| Revoke on a scheduled grant. | [9](#check-9-revoke-on-a-scheduled-grant) |
| Silent notices use a low priority, alerts a high one. | [10](#check-10-priorities) |

[DESIGN.md section 7, "ntfy details"](../DESIGN.md#ntfy-details) says
what the broker does in each case. The docs of ntfy do not confirm the
`http` action and message updates on iOS, so check 1 to 5 matter most
on the iPhone.

## Rules

- Use two new topics and a new user for this test. Never use the
  topics, users or token of a real broker.
- The token goes into one file with mode `0600`, outside of every
  repository. Never paste it into a chat with a person or an AI
  assistant, an issue, a commit or a command line.
- Tap only on the phones. The test machine never reads the request
  topic.
- Remove the users and the access rules of the test at the end.

## What you need

- A self-hosted ntfy server with `https`, with these lines in its
  `server.yml`, and a root shell on it for `ntfy user`, `ntfy access` and
  `ntfy token`:

  ```yaml
  auth-file: "/var/lib/ntfy/user.db"
  auth-default-access: "deny-all"
  upstream-base-url: "https://ntfy.sh"
  ```

  The examples use `https://ntfy.example.com`.
- An Android phone and an iPhone, each with the ntfy app.
- A Linux machine with the nodkey source at the commit that you test,
  Go 1.26 or newer, `git`, `curl` and `jq`. It does not need systemd.
- Three terminals on that machine: **terminal 1** runs the broker,
  **terminal 2** runs the client, and **terminal 3** is for the rest.

## Set up

### 1. Users and access rules

On the ntfy server:

```sh
ntfy user add nodkey-test-broker    # asks for a password
ntfy user add nodkey-test-phone
ntfy access nodkey-test-broker nodkey-test-requests write-only
ntfy access nodkey-test-broker nodkey-test-answers read-only
ntfy access nodkey-test-phone nodkey-test-requests read-only
ntfy access everyone nodkey-test-answers write-only
ntfy token add --label="nodkey manual test" nodkey-test-broker
```

The last command prints the token of the broker.

### 2. Save the token

In terminal 3:

```sh
T=~/.config/nodkey-test
install -d -m 0700 "$T"
read -rs TOKEN    # paste the token, then press Enter; it is not shown
(umask 077; printf '%s\n' "$TOKEN" > "$T/ntfy-token")
unset TOKEN
ls -l "$T/ntfy-token"    # must show -rw-------
```

Check the access rules, without a token:

```sh
S=https://ntfy.example.com
curl -sS -o /dev/null -w '%{http_code}\n' "$S/nodkey-test-requests/json?poll=1"
curl -sS -o /dev/null -w '%{http_code}\n' "$S/nodkey-test-answers/json?poll=1"
```

Both must print `403`: nobody may read the topics without a login.

### 3. The phones

On each phone, in the settings of the ntfy app, add the user
`nodkey-test-phone` with its password for `https://ntfy.example.com`.
Then subscribe to `nodkey-test-requests` on that server. On Android, turn
on instant delivery for the subscription. Do not subscribe to
`nodkey-test-answers`.

### 4. Build nodkey, and make the files of the broker

Do [step 5 of the Telegram test](manual-telegram-test.md#5-build-nodkey-and-make-the-files-of-the-broker)
up to the config of the broker. Then use this config of the broker,
`$T/broker.toml`, with the pin of the client:

```toml
listen = "127.0.0.1:7743"
tls_key = "~/.config/nodkey-test/broker.key"
audit_log = "~/.config/nodkey-test/state/audit.jsonl"
known_hosts = "~/.config/nodkey-test/known_hosts"

[ntfy]
server = "https://ntfy.example.com"
request_topic = "nodkey-test-requests"
answer_topic = "nodkey-test-answers"
token_file = "~/.config/nodkey-test/ntfy-token"
timeout = "60s"

[preapprove]

[client.test]
pin = "sha256:...client..."  # the pin of the client

[store.fake]
type = "bws"
program = "~/.config/nodkey-test/bin/fake-bws"
token_file = "~/.config/nodkey-test/bws-token"

[secret.demo-always]
store = "fake"
id = "11111111-1111-4111-8111-111111111111"
clients = ["test"]
ask = "always"
preapprove = true

[secret.demo-window]
store = "fake"
id = "22222222-2222-4222-8222-222222222222"
clients = ["test"]
ask = "window"
window = "2m"

[secret.demo-never]
store = "fake"
id = "22222222-2222-4222-8222-222222222222"
clients = ["test"]
ask = "never"
```

Make the config of the client, and make both files private, as the rest
of step 5 of the Telegram test says.

### 5. Start the broker

Do [step 6 of the Telegram test](manual-telegram-test.md#6-start-the-broker):
start the broker in terminal 1, and define `ask` in terminal 2.

## The checks

Do check 1 to 7 on the Android phone, then again on the iPhone. Both
phones get each message; tap on the one that you test. Write what you saw
into the [results table](#results). If something else happens, write it
down exactly, with the time, and keep `$T/broker.log`.

In each message, check the title (`🔑 Secrets · request XXXX`), the lines
with ✅ (`machine: test`, `secrets:` and the name), the claimed lines
below them, and the expiry line. The short code in the title must be the
code that terminal 2 prints.

### Check 1: Delivery

1. Lock the phone that you test.
2. Terminal 2: `ask demo-always "check 1"`.

Expected:

- A notification comes, with sound, within a few seconds. Write down
  how many seconds it took on each phone.
- It shows the lines above, and the buttons **Approve once** and
  **Deny**. Leave it for check 2.

### Check 2: Approve once

1. Tap **Approve once** on the message of check 1.

Expected:

- Terminal 2 prints `the command got 15 characters` and `exit code: 0`.
- The notification goes away (the button has `clear: true`).
- The message in the app keeps its text, the expiry line becomes
  `👍 approved once at HH:MM:SS`, and the buttons are gone. It is
  the same message, not a second one. The update makes no sound.

### Check 3: Approve N min

1. Terminal 2: `ask demo-window "check 3"`. The message has three
   buttons: **Approve once**, **Approve 2 min** and **Deny**.
2. Tap **Approve 2 min**.
3. At once, terminal 2: `ask demo-window "check 3, inside the grant"`.
4. Wait until 2 minutes after the tap. Then, terminal 2:
   `ask demo-window "check 3, after the grant"`. Leave this message for
   check 4.

Expected:

- Step 2: the command runs, and the message shows
  `👍 approved for 2 min at HH:MM:SS`, without buttons.
- Step 3: no message. The command runs at once.
- Step 4: a new message with the three buttons.

### Check 4: Deny

1. Tap **Deny** on the message of check 3, step 4.
2. At once, terminal 2: `ask demo-window "check 4, inside the pause"`.

Expected:

- Step 1: terminal 2 prints `nodkey: denied (exit 77)`. The message
  shows `⛔ denied at HH:MM:SS`, without buttons.
- Step 2: no message. Terminal 2 prints
  `nodkey: denied by a limit of the broker (exit 77)` at once.

### Check 5: Expiry

1. Terminal 2: `ask demo-always "check 5"`. Do not tap.
2. Wait 60 seconds.

Expected: terminal 2 prints `nodkey: denied (exit 77)`. The message
shows `⌛ expired — denied`, without buttons.

### Check 6: Second tap

1. Terminal 2: `ask demo-always "check 6"`.
2. Tap **Approve once** two times, as fast as you can. Or, after the
   first tap, open the app and tap the button again on the message in
   the list, if it still has buttons. If no second tap is possible,
   write "not possible" into the results, with the app and its version.

Expected:

- The command runs once.
- If a second tap was possible: the log of the broker (terminal 1) has
  `ntfy: refused an answer`, and the message still shows
  `👍 approved once at HH:MM:SS`.

### Check 7: Late tap after a restart

1. Terminal 2: `ask demo-always "check 7"`. Do not tap.
2. Terminal 3, kill the broker hard, so that it cannot replace the
   message:

   ```sh
   pkill -KILL -f "nodkey broker --config $T/broker.toml"
   ```

   Terminal 1 prints `the broker exited with 137`. Terminal 2 prints an
   error and exit code 69.
3. Terminal 1: start the broker again, with the same command as in
   [step 5](#5-start-the-broker).
4. On the phone, tap **Approve once** on the old message.

Expected:

- Nothing runs. The log has `ntfy: refused an answer`, with
  `why="no request with this ID waits for an answer here"`.
- The old message keeps its buttons: after a restart, the broker does
  not know the message any more. Write down what the phone shows.

### Check 8: A forged answer

Anyone may write to the answer topic, so send an answer with a wrong
value, as an attacker could.

1. Terminal 2: `ask demo-always "check 8"`. Do not tap.
2. Terminal 3, send **Approve once** with a made-up value:

   ```sh
   ID=$(jq -r 'select(.event == "request") | .request_id' "$T/state/audit.jsonl" | tail -1)
   curl -sS -o /dev/null -w '%{http_code}\n' \
     -d "{\"request\":\"$ID\",\"action\":\"once\",\"value\":\"AAAAAAAAAAAAAAAAAAAAAA\"}" \
     "$S/nodkey-test-answers"
   ```

3. Tap **Deny** on the phone.

Expected:

- Step 2: curl prints `200`: anyone may write. Terminal 2 still waits.
  The log has `ntfy: refused an answer`, with
  `why="the value is not the value of this button of the request"`.
- Step 3: terminal 2 prints `nodkey: denied (exit 77)`.

### Check 9: Revoke on a scheduled grant

With `NOW` and `LATER` as times in the next 10 minutes (for example
`2026-11-02T14:05` and `2026-11-02T14:08`, in the local time of the
broker), terminal 2:

```sh
HOME="$T/home" "$T/nodkey" preapprove --secret demo-always \
  --from NOW --until LATER --uses 2 --reason "check 9"
```

1. Tap **Approve**. Look at the message.
2. Tap **Revoke**.

Expected:

- Step 1: the message has the line `👍 approved at ...` and one
  **Revoke** button.
- Step 2: the message has no button, and a line
  `⛔ revoked at ..., with 2 use(s) left`.

### Check 10: Priorities

1. Terminal 2: `ask demo-never "check 10"`. A notice comes:
   `🔔 Secrets · request XXXX` with
   `allowed by a "never ask" rule, without a tap`.
2. Terminal 3, stop the broker cleanly, then cut the last line of the
   audit log in half, as a power cut could:

   ```sh
   pkill -TERM -f "nodkey broker --config $T/broker.toml"
   printf '{"seq":' >> "$T/state/audit.jsonl"
   ```

   Terminal 1 prints `the broker exited with 0`. Do not use Ctrl-C here:
   in bash, it stops `tee` too.

3. Terminal 1: start the broker again. An alert comes:
   `The audit log ended in a torn line, as after a power cut...`.

Expected, on both phones:

- A request (checks 1 to 9) has priority 4 (high): sound, and on
  Android a pop-up.
- The notice of step 1, and each message after its request ended, have
  priority 2 (low): no sound, no pop-up.
- The alert of step 3 has priority 5 (urgent): sound, and the
  strongest alert that the phone gives.

Write down what each phone did. Do check 11 after this check, so that
`audit verify` sees the torn line and its `log_recovered` entry.

### Check 11: The audit log

Terminal 3:

```sh
"$T/nodkey" audit verify "$T/state/audit.jsonl" --anchors "$T/broker.log"
jq -c '{seq, event, answer, cause, user_id, channel} | with_entries(select(.value != null))' "$T/state/audit.jsonl"
```

Expected: `audit verify` prints `ok:` and `anchors: ... checked, all
match`. Each `decision` entry has `user_id` 0 and
`channel` `ntfy:nodkey-test-answers`. There is no `foreign_tap` entry:
refused answers are only in the log of the broker.

### Check 12: The token in the logs

Terminal 3:

```sh
grep -cF -f "$T/ntfy-token" "$T/broker.log" "$T/state/audit.jsonl"
```

Expected: it prints `0` for both files.

### Check 13: A token that the server refuses (optional)

1. Terminal 1: start the broker again, if it does not run.
2. On the ntfy server: `ntfy token remove nodkey-test-broker <token>`.
   Type the token on the server, not on the test machine.

Expected: within about 2 minutes, the log has
`ntfy: the server refused the read token; no answers can come any more`,
and terminal 1 prints `the broker exited with 77`.

## Clean up

1. Terminal 1: stop the broker with Ctrl-C, if it still runs.
2. On the ntfy server:

   ```sh
   ntfy access --reset nodkey-test-broker
   ntfy access --reset nodkey-test-phone
   ntfy access --reset everyone nodkey-test-answers
   ntfy user del nodkey-test-broker
   ntfy user del nodkey-test-phone
   ```

3. Remove the files of the test, with the token:
   `rm -rf ~/.config/nodkey-test`.
4. On each phone, remove the subscription and the user.

## Results

Copy this table into a comment on issue #24, and fill it in. The issue is
public. Leave out the token, the name of the server, and every raw
answer of the server.

- Date:
- nodkey commit:
- ntfy server version:
- Android phone, Android version, ntfy app version:
- iPhone, iOS version, ntfy app version:

| # | check | expected | Android | iPhone | notes |
|---|---|---|---|---|---|
| 1 | delivery, phone locked | a notification with sound; the seconds it took | | | |
| 2 | Approve once | the command runs; notification gone; the same message shows `approved once`, no buttons | | | |
| 3 | Approve 2 min | the command runs; `approved for 2 min`; no buttons | | | |
| 3 | inside the grant | no message; the command runs | | | |
| 3 | after the grant | a new message | | | |
| 4 | Deny | exit 77; `denied`; no buttons | | | |
| 4 | inside the pause | `denied by a limit of the broker`, exit 77 at once | | | |
| 5 | expiry | exit 77 after 60 s; `expired — denied`; no buttons | | | |
| 6 | second tap | the command runs once; `refused an answer`, or "not possible" | | | |
| 7 | late tap after a restart | nothing runs; `refused an answer`; what the phone shows | | | |
| 8 | forged answer | curl `200`; refused; the request still waits | | | |
| 9 | Revoke on a scheduled grant | button gone; `revoked` | | | |
| 10 | request priority | 4: sound, pop-up | | | |
| 10 | notice and ended message priority | 2: no sound | | | |
| 10 | alert priority | 5: sound | | | |
| 11 | `audit verify`; `user_id` 0, `channel` | ok, all anchors match | | | |
| 12 | the token in the logs | `0` for both files | | | |
| 13 | refused token (optional) | exit code 77 | | | |
