# Manual test with a real Telegram bot

The tests of nodkey use a fake Telegram server. It cannot prove that the
real Bot API behaves the same. This test runs a throwaway broker with a
real bot, and you tap the buttons on your phone. It is the test of issue
[#17](https://github.com/code6x/nodkey/issues/17). Write the results into
that issue.

What the test checks, in the words of issue #17:

| issue #17 asks | checks |
|---|---|
| Approve once, Approve N min, Deny and expiry work on the phone. | [1](#check-1-approve-once), [2](#check-2-approve-n-min), [3](#check-3-deny), [4](#check-4-expiry) |
| A late tap and a double tap are refused. | [5](#check-5-double-tap), [6](#check-6-late-tap-after-a-restart) |
| Buttons disappear after each answer. | each check |
| Telegram sends the buttons of the message (`reply_markup`) with every tap. | [1](#check-1-approve-once) and [2](#check-2-approve-n-min) |
| What an edit without `reply_markup` does to the buttons. | [7](#check-7-an-edit-without-reply_markup) |
| A tap on a message edited by another client is refused (`edit_date`). | [7](#check-7-an-edit-without-reply_markup) or [8](#check-8-an-edit-that-keeps-the-buttons) |
| How "message is not modified" is handled. | [5](#check-5-double-tap) and [9](#check-9-message-is-not-modified) |
| A second poller gets a 409, and the broker stops with an alert. | [10](#check-10-a-second-poller) |
| (Also: the errors of the real Bot API never put the token into a log, THREAT-MODEL.md T19.) | [13](#check-13-the-bot-token-in-the-logs) |

[DESIGN.md section 7](../DESIGN.md#7-approval-messages) says what the
broker does in each case.

## Rules

- Make a new bot for this test. Never use the bot of a real broker:
  Telegram lets only one program read the updates of a bot, and the test
  makes the broker stop on purpose.
- The bot token goes into one file with mode `0600`, outside of every
  repository. Never paste it into a chat with a person or an AI
  assistant, an issue, a commit or a command line.
- Tap only on your phone.
- Delete the bot at the end.

## What you need

- A phone with Telegram. Its account is the approver.
- A Linux machine with the nodkey source at the commit that you test,
  Go 1.26 or newer, `git`, `curl` and `jq`. It does not need systemd.
- Three terminals on that machine: **terminal 1** runs the broker,
  **terminal 2** runs the client, and **terminal 3** calls the Bot API.

## Set up

### 1. Make a test bot

In Telegram, open the chat with [@BotFather](https://t.me/BotFather) and
send `/newbot`. Choose a name, such as `nodkey test`, and a user name
that ends in `bot`. BotFather answers with the token. Then open the new
bot and tap **Start**.

### 2. Save the token

In terminal 3:

```sh
T=~/.config/nodkey-test
install -d -m 0700 "$T"
read -rs TOKEN    # paste the token, then press Enter; it is not shown
(umask 077; printf '%s\n' "$TOKEN" > "$T/telegram-token")
unset TOKEN
ls -l "$T/telegram-token"    # must show -rw-------
```

### 3. A helper for the Bot API

The helper `tg METHOD JSON` calls the Bot API with the token from the
file. `printf` is part of the shell, and curl reads the address from its
input, so the token is not in the list of processes. In terminal 3:

```sh
tg() {
  printf 'url = "https://api.telegram.org/bot%s/%s"\n' "$(cat "$T/telegram-token")" "$1" |
    curl -sS --config - -H 'Content-Type: application/json' -d "$2"
  echo
}
tg getMe '{}'
```

`getMe` must answer `"ok":true`, with the user name of the test bot.

### 4. Find your user ID

Tapping **Start** sent the message `/start` to the bot. In terminal 3:

```sh
tg getUpdates '{"allowed_updates":["message"]}' | jq '.result[].message.from.id'
```

Keep the number in a variable:

```sh
CHAT=123456789    # your user ID; the private chat with the bot has the same ID
```

From now on, never call `getUpdates` while the broker runs, except in
[check 10](#check-10-a-second-poller).

### 5. Build nodkey, and make the files of the broker

In terminal 3, in the nodkey source:

```sh
git rev-parse HEAD    # write this commit into the results
go build -o "$T/nodkey" ./cmd/nodkey
install -d -m 0700 "$T/bin" "$T/state" "$T/home" "$T/home/.config" "$T/home/.config/nodkey"
"$T/nodkey" keygen --out "$T/broker.key"
HOME="$T/home" "$T/nodkey" keygen --out "$T/home/.config/nodkey/client.key"
```

The two `keygen` commands print the pin of the broker, then the pin of
the client. The broker runs as you, with its files in `$T`. The client
uses `$T/home` as its home directory, so that its config does not touch
a real one in your own home directory.

A fake store program. It acts like `bws` for two made-up secrets, and
fails for every other ID:

```sh
cat > "$T/bin/fake-bws" <<'EOF'
#!/bin/sh
# A fake bws for the manual Telegram test of nodkey.
case "$1 $2 $3" in
'secret get 11111111-1111-4111-8111-111111111111')
  printf '%s' '{"id":"11111111-1111-4111-8111-111111111111","value":"made-up-value-1"}' ;;
'secret get 22222222-2222-4222-8222-222222222222')
  printf '%s' '{"id":"22222222-2222-4222-8222-222222222222","value":"made-up-value-2"}' ;;
*) exit 1 ;;
esac
EOF
chmod 0700 "$T/bin/fake-bws"
(umask 077; echo made-up-store-token > "$T/bws-token")
install -m 0644 /dev/null "$T/known_hosts"
```

The config of the broker, `$T/broker.toml`. Put in your user ID and the
pin of the client:

```toml
listen = "127.0.0.1:7743"
tls_key = "~/.config/nodkey-test/broker.key"
audit_log = "~/.config/nodkey-test/state/audit.jsonl"
known_hosts = "~/.config/nodkey-test/known_hosts"

[telegram]
token_file = "~/.config/nodkey-test/telegram-token"
user_id = 123456789          # your user ID
timeout = "60s"

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

[secret.demo-window]
store = "fake"
id = "22222222-2222-4222-8222-222222222222"
clients = ["test"]
ask = "window"
window = "2m"
```

The config of the client, `$T/home/.config/nodkey/client.toml`. Put in
the pin of the broker:

```toml
broker = "127.0.0.1:7743"
broker_pin = "sha256:...broker..."
tls_key = "~/.config/nodkey/client.key"
```

Make both files private, so that the broker and the client accept them:

```sh
chmod 0600 "$T/broker.toml" "$T/home/.config/nodkey/client.toml"
```

### 6. Start the broker

In terminal 1. The log goes to the screen and to `$T/broker.log`, and
the last line shows the exit code of the broker:

```sh
T=~/.config/nodkey-test
"$T/nodkey" broker --config "$T/broker.toml" 2> >(tee -a "$T/broker.log" >&2); echo "the broker exited with $?"
```

Wait for the line `nodkey broker: listening; the broker is ready`. If
the broker stops instead, its last lines say why. For example, it
refuses a file or a directory that group or others can write to.

In terminal 2, define the client command `ask SECRET REASON`. It asks
for the secret in `DEMO_TOKEN`, and the command prints only the length
of the value:

```sh
T=~/.config/nodkey-test
ask() {
  HOME="$T/home" "$T/nodkey" run --secret DEMO_TOKEN="$1" --reason "$2" -- \
    sh -c 'echo "the command got ${#DEMO_TOKEN} characters"'
  echo "exit code: $?"
}
```

## The checks

Each check says what to do, and what you should see. Write what you saw
into the [results table](#results). If something else happens, write it
down exactly, with the time, and keep `$T/broker.log`.

In each message, check the lines with ✅ (`machine: test`, `secrets:`
and the name), the claimed lines below them, and the expiry line. The
short code in the first line of the message must be the code that
terminal 2 prints.

### Check 1: Approve once

1. Terminal 2: `ask demo-always "check 1"`
2. Terminal 2 prints `nodkey: waiting for approval (request XXXX)`. On
   the phone, a message `🔑 Secrets · request XXXX` comes, with the
   buttons **Approve once** and **Deny**.
3. Tap **Approve once**.

Expected:

- The phone shows `Approved.` for a moment.
- Terminal 2 prints `the command got 15 characters` and `exit code: 0`.
- The message keeps its text, the expiry line becomes
  `👍 approved once by you at HH:MM:SS`, and the buttons are gone.

This also shows that Telegram sends the buttons of the message with the
tap. Without them, the broker would refuse the Approve: the phone would
show `Someone else changed this message. This tap does not count.`, and
an alert would come.

### Check 2: Approve N min

1. Terminal 2: `ask demo-window "check 2"`. The message has three
   buttons: **Approve once**, **Approve 2 min** and **Deny**.
2. Tap **Approve 2 min**.
3. At once, terminal 2: `ask demo-window "check 2, inside the grant"`.
4. Wait until 2 minutes after the tap. Then, terminal 2:
   `ask demo-window "check 2, after the grant"`. Leave this message for
   check 3.

Expected:

- Step 2: the command runs, and the message shows
  `👍 approved for 2 min by you at HH:MM:SS`, without buttons.
- Step 3: no message. The command runs at once.
- Step 4: a new message with the three buttons.

### Check 3: Deny

1. Tap **Deny** on the message of check 2, step 4.
2. At once, terminal 2: `ask demo-window "check 3, inside the pause"`.

Expected:

- Step 1: the phone shows `Denied.`. Terminal 2 prints
  `nodkey: denied (exit 77)`. The message shows
  `⛔ denied by you at HH:MM:SS`, without buttons.
- Step 2: no message. Terminal 2 prints
  `nodkey: denied by a limit of the broker (exit 77)` at once: the
  broker denies new requests for this secret for 60 seconds after a
  Deny.

### Check 4: Expiry

1. Terminal 2: `ask demo-always "check 4"`. Do not tap.
2. Wait 60 seconds.

Expected: terminal 2 prints `nodkey: denied (exit 77)`. The message
shows `⌛ expired — denied`, without buttons.

### Check 5: Double tap

1. Terminal 2: `ask demo-always "check 5"`.
2. Tap **Approve once** two times, as fast as you can. If the buttons are
   gone before the second tap, write that down: a double tap was not
   possible.

Expected:

- The command runs once.
- The second tap, if it reached Telegram: the phone shows
  `This request has ended.`, and the log of the broker (terminal 1) has
  `telegram: refused a button press` with `cause=unknown_request`.
- The message still shows `👍 approved once by you at HH:MM:SS`. The
  second tap must not change it.
- The log has no line `cannot update the message of a request that
  ended`. After the second tap, the broker writes the same text again.
  Telegram answers "message is not modified", and the broker takes that
  as done.

### Check 6: Late tap after a restart

1. Terminal 2: `ask demo-always "check 6"`. Do not tap.
2. Terminal 3, while the message waits, kill the broker hard, so that it
   cannot remove the buttons:

   ```sh
   pkill -KILL -f "nodkey broker --config $T/broker.toml"
   ```

   Terminal 1 prints `the broker exited with 137`. Terminal 2 prints an
   error and exit code 69.
3. Terminal 1: start the broker again, with the same command as in
   [step 6](#6-start-the-broker).
4. On the phone, tap **Approve once** on the old message.

Expected:

- The phone shows `This request has ended.`.
- The buttons of the old message are gone. Its text stays as it was,
  with the old expiry line: after a restart, the broker does not know
  the result, so it only removes the buttons.
- The log has `telegram: refused a button press` with
  `cause=unknown_request`.

If the new broker stops at once with exit code 76, the poll of the
killed broker was still active at Telegram. Write it down, and start the
broker again.

### Check 7: An edit without reply_markup

Here you play someone who has the bot token, and edits a message that
waits. You need its message number. The bot gives each message in its
chats the next number, so send a probe message first:

1. Terminal 3:

   ```sh
   P=$(tg sendMessage "{\"chat_id\":$CHAT,\"text\":\"probe 7\"}" | jq .result.message_id)
   M=$((P + 1)); echo "probe: $P, the next message: $M"
   ```

2. Terminal 2: `ask demo-always "check 7"`. Do not tap. Its message
   should be number `$M`.
3. Terminal 3, change the text of the message, without `reply_markup`:

   ```sh
   tg editMessageText "{\"chat_id\":$CHAT,\"message_id\":$M,\"text\":\"check 7: changed by another client\"}" | jq -c '.ok, .result.reply_markup'
   ```

   The phone must show the new text on the message of step 2. If the
   call failed, or another message changed, the number was not right:
   tap **Deny**, and start again at step 1.
4. Look at the message. Write down whether the buttons are still there.
5. If the buttons are still there, tap **Approve once**, then **Deny**.
   If they are gone, wait 60 seconds for the expiry.

Expected:

- If the buttons stayed: **Approve once** shows
  `Someone else changed this message. This tap does not count.`, and
  terminal 2 still waits. An alert message comes:
  `⚠️ nodkey: Someone else changed a message of the broker while its
  request waited for an answer...`. The log has
  `telegram: ALERT: someone else changed a message of the broker`, and
  `telegram: refused a button press` with `cause=edited_message`. Then
  **Deny** shows `Denied. Someone else changed this message.`, terminal
  2 prints `nodkey: denied (exit 77)`, and the message gets its own text
  back, with `⛔ denied by you at HH:MM:SS` and no buttons. The buttons
  were the same as before, so the broker refused the Approve only for
  the edit (`edit_date`): this also passes
  [check 8](#check-8-an-edit-that-keeps-the-buttons).
- If the buttons went away: after 60 seconds, terminal 2 prints
  `nodkey: denied (exit 77)`. The message gets its own text back, with
  `⌛ expired — denied`. No alert comes, because there was no tap.

### Check 8: An edit that keeps the buttons

Skip this check if the buttons stayed in check 7. Otherwise, edit a
message and give it its own buttons again, as someone with the token
could. The broker never edits a message while it waits, so it must
refuse the Approve because of the edit (`edit_date`) alone.

1. Terminal 3, a new probe:

   ```sh
   P=$(tg sendMessage "{\"chat_id\":$CHAT,\"text\":\"probe 8\"}" | jq .result.message_id)
   M=$((P + 1)); echo "probe: $P, the next message: $M"
   ```

2. Terminal 2: `ask demo-always "check 8"`. Do not tap.
3. Terminal 3, read the buttons of the message: forward it into the same
   chat. The answer holds the buttons of the copy:

   ```sh
   MARKUP=$(tg forwardMessage "{\"chat_id\":$CHAT,\"from_chat_id\":$CHAT,\"message_id\":$M}" | jq -c .result.reply_markup)
   echo "$MARKUP"
   ```

   It must show the two buttons of the message, with `callback_data`
   `o:...` and `d:...`. If it shows `null`, the copy has no buttons:
   write that down, and read the buttons from the pinned message
   instead:

   ```sh
   tg pinChatMessage "{\"chat_id\":$CHAT,\"message_id\":$M,\"disable_notification\":true}"
   MARKUP=$(tg getChat "{\"chat_id\":$CHAT}" | jq -c .result.pinned_message.reply_markup)
   echo "$MARKUP"
   ```

4. If the copy of step 3 has buttons, tap **Approve once** on the copy.
   Expected: `This button does not count.`, and in the log
   `cause=wrong_message`. The request still waits.
5. Terminal 3, change the text, and keep the buttons:

   ```sh
   tg editMessageText "{\"chat_id\":$CHAT,\"message_id\":$M,\"text\":\"check 8: a harmless text\",\"reply_markup\":$MARKUP}" | jq -c '.ok, .result.edit_date'
   ```

6. Tap **Approve once** on the changed message, then **Deny**.

Expected: the same as in check 7, when the buttons stayed. The broker
sends at most one alert about a changed message in 10 minutes, so this
alert may not come again; the line with `cause=edited_message` must be
in the log anyway. If you pinned the message in step 3, unpin it:
`tg unpinChatMessage "{\"chat_id\":$CHAT,\"message_id\":$M}"`.

### Check 9: "message is not modified"

Ask Telegram for an edit that changes nothing: the probe of check 8, or
of check 7, with its own text.

```sh
tg editMessageText "{\"chat_id\":$CHAT,\"message_id\":$P,\"text\":\"probe 8\"}"
```

Use `probe 7` if `$P` is the probe of check 7. Expected:
`"ok":false,"error_code":400`, and a `description` that holds
`message is not modified`. The broker looks for exactly these words.
Write down the whole description. Together with check 5, this shows that
the broker takes this answer as done, and logs no warning.

### Check 10: A second poller

The broker must run, and no request may wait.

1. Terminal 3, read the updates of the bot as a second program:

   ```sh
   tg getUpdates '{"timeout":5}'
   ```

Expected:

- The log has `telegram: ALERT: Telegram reports a polling conflict`
  and `broker: another program polls with the bot token`.
- An alert message comes:
  `⚠️ nodkey: Telegram reports a conflict: another program reads the
  updates of this bot, or a webhook is set. The bot token may be
  stolen...`.
- Terminal 1 prints `the broker exited with 76`.
- Write down only what kind of answer the `getUpdates` call got: an
  empty list, a number of updates, or an error code such as 409. Do not
  copy the answer itself: it can hold your name, your user name and your
  user ID.

### Check 11: A token that Telegram no longer takes (optional)

1. Terminal 1: start the broker again.
2. In BotFather, send `/revoke`, and choose the test bot. Do not save
   the new token.

Expected: within about a minute, the log has `Telegram refused
getUpdates` with `(401)`, and terminal 1 prints
`the broker exited with 77`. No alert comes: the token no longer works.

### Check 12: The audit log

Terminal 3:

```sh
"$T/nodkey" audit verify "$T/state/audit.jsonl" --anchors "$T/broker.log"
jq -c '{seq, event, secrets, answer, cause, code} | with_entries(select(.value != null))' "$T/state/audit.jsonl"
```

Expected: `audit verify` prints `ok:` and `anchors: ... checked, all
match`. The list of entries shows each check:

- `decision` entries with `approve_once`, `approve_window` and `deny`;
- a `grant_used` entry from check 2;
- `denied` entries with `approver`, `limit` and `expired`;
- `foreign_tap` entries with `unknown_request` (checks 5 and 6) and
  `edited_message` (check 7 or 8). One has `wrong_message`, if you
  tapped the copy in check 8;
- an `error` entry with `poll_conflict` (check 10).

### Check 13: The bot token in the logs

The real Bot API fails in other ways than the fake server of the tests,
so check once more that no error put the token into a log
(THREAT-MODEL.md T19). Terminal 3:

```sh
grep -cF -f "$T/telegram-token" "$T/broker.log" "$T/state/audit.jsonl"
```

`grep` reads the token from the file, so it is not in the list of
processes. Expected: it prints `0` for both files.

## Clean up

1. Terminal 1: stop the broker with Ctrl-C, if it still runs.
2. In BotFather, send `/deletebot`, and choose the test bot.
3. Remove the files of the test, with the token: `rm -rf ~/.config/nodkey-test`.
4. Delete the chat with the test bot on the phone, if you want.

## Results

Copy this table into a comment on issue #17, and fill it in. The issue is
public. Leave out the token, your user ID, the name of the bot, every
raw answer of the Bot API, and the lines of the log with `user_id` or
`chat_id`.

- Date:
- nodkey commit:
- Phone, and its Telegram app and version:

| # | check | expected | result | notes |
|---|---|---|---|---|
| 1 | Approve once | the command runs; `approved once`; buttons gone | | |
| 1, 2 | Telegram sends `reply_markup` with each tap | Approve counts, no alert | | |
| 2 | Approve 2 min | the command runs; `approved for 2 min`; buttons gone | | |
| 2 | inside the grant | no message; the command runs | | |
| 2 | after the grant | a new message | | |
| 3 | Deny | exit 77; `denied by you`; buttons gone | | |
| 3 | inside the pause | `denied by a limit of the broker`, exit 77 at once, no message | | |
| 4 | expiry | exit 77 after 60 s; `expired — denied`; buttons gone | | |
| 5 | double tap | second tap: `This request has ended.`; the result stays; no warning in the log | | |
| 6 | late tap after a restart | `This request has ended.`; buttons gone; old text stays | | |
| 7 | edit without `reply_markup` | write down: the buttons stayed, or went away | | |
| 7 or 8 | Approve on an edited message (`edit_date`) | refused; alert; `cause=edited_message` | | |
| 7 or 8 | Deny on an edited message | counts; exit 77; own text back | | |
| 8 | a forward keeps the buttons | write down: yes or no | | |
| 8 | Approve on the forwarded copy | `This button does not count.`; `cause=wrong_message` | | |
| 9 | "message is not modified" | error 400 with these words; the description | | |
| 10 | second poller | alert; exit code 76; `getUpdates` got: empty list, N updates, or error code | | |
| 11 | revoked token (optional) | exit code 77; no alert | | |
| 12 | `audit verify` with the anchors | ok, all anchors match | | |
| 13 | the bot token in the logs | `0` for `broker.log` and for `audit.jsonl` | | |
