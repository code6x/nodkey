# Website logins with agent-browser

An agent logs in to a website with
[agent-browser](https://github.com/vercel-labs/agent-browser). nodkey is
its credential plugin: after your tap on the phone, the plugin gives
agent-browser one login from the shared Bitwarden collection.
agent-browser fills the form. The password is not in the agent's
commands or in agent-browser's normal output.

Tested with **agent-browser 0.38.1**, on 2026-11-13. Another version may
speak another protocol. Use 0.38.1, or test the new version first
(DESIGN.md section 21.10).

What the agent can still see: a filled field, if it reads it; the
session after the login; and a TOTP code, which it fills itself
(THREAT-MODEL.md T48).

## Before you start

- The broker hands out website logins: [setup.md, "Website logins: a
  shared collection"](setup.md#website-logins-a-shared-collection). The
  rule of the items needs `preapprove = true`.
- nodkey is installed on the agent machine, and `nodkey doctor` shows no
  problem.
- agent-browser 0.38.1 is installed on the agent machine.

## 1. Add the plugin to agent-browser

As the user of the agent, put this into `~/.agent-browser/config.json`.
If the file has other settings, add only the `plugins` entry.

```json
{
  "plugins": [
    {
      "name": "nodkey",
      "command": "/usr/local/bin/nodkey",
      "args": ["agent-browser-plugin"],
      "capabilities": ["credential.read", "command.run"]
    }
  ]
}
```

Give the full path of `nodkey` (`command -v nodkey` shows it). Put
`agent-browser-plugin` into `args`: agent-browser does not split
`command` at spaces. Check it:

```sh
agent-browser plugin show nodkey
```

## 2. Log in

Each login takes three steps. Use the page of the login form for
`--url`, the same in each step.

1. Find the item ID. The list needs no tap.

   ```sh
   agent-browser plugin run nodkey nodkey.list --payload '{"url":"https://example.com/sign-in"}'
   ```

   It prints the ID, the name and the username of each login for the
   page, and never a password.

2. Ask for the tap. This waits until you tap Approve on the phone, as
   long as any other nodkey request:

   ```sh
   nodkey preapprove --login 11111111-1111-1111-1111-111111111111 --url https://example.com/sign-in
   ```

3. Within 60 seconds after the tap, log in:

   ```sh
   agent-browser auth login example --credential-provider nodkey --item 11111111-1111-1111-1111-111111111111 --url https://example.com/sign-in
   ```

   It prints `Logged in as 'example'`. The tap allows this one login;
   the next login needs a new tap.

Why the tap comes first: agent-browser waits only 15 seconds for a
plugin, and a tap often takes longer. The plugin itself never asks for a
tap.

When the login form is already open, after some clicks, add
`--no-navigate`. agent-browser then checks that the open page has the
origin of `--url`.

### A code from an authenticator app (TOTP)

When the site asks for a code after the password, get it within 2
minutes after the login:

```sh
agent-browser plugin run nodkey nodkey.totp --payload '{"itemRef":"11111111-1111-1111-1111-111111111111","url":"https://example.com/sign-in"}'
```

It prints the code, and the agent fills it. The broker makes the code;
the seed never leaves it. You get one code for each login.

## When it fails

| what you see | why | what to do |
|---|---|---|
| `Plugin 'nodkey' returned success=false` after `auth login` | agent-browser does not show the reason. Most often: no tap first, or more than 60 seconds since the tap | Run `nodkey preapprove --login` again, then `auth login` at once. The broker's audit log has the cause; `no_tap` means no tap |
| `Failed to start plugin 'nodkey'` | the `command` is not a path to `nodkey`, or the subcommand is in `command` | Fix step 1 |
| `nodkey: the item is not an item ID` | `--item` is a name | Use the ID from `nodkey.list` |
| `nodkey: the request has no page URL` | no `--url` | Give `--url` with the page of the login |
| `nodkey: the page URL: ... not https` | the page is `http` | nodkey hands out logins only for `https` pages |
| `nodkey: totp: denied` | no login in the last 2 minutes, or the code was already given | Log in again, then ask for the code |

## 3. Stop Chrome from saving passwords: the `agents` profile

A Google Chrome that an agent drives offers to save a filled password in
Chrome's own password manager ("Save password?"). The offer is outside
the page, so the agent does not see it. But a person at the screen can
click Save, and with a lasting profile the password then stays on the
disk of the agent machine. The command line flag
`--disable-save-password-bubble` no longer works.

Make one Chrome profile for agents, with saving turned off.
agent-browser copies a named profile to a new temporary folder for each
session, so every session starts from it. Make it in Chrome itself:
agent-browser finds profiles by their names in Chrome's `Local State`
file, and a folder made by hand is not found.

**These steps are not yet tested from start to end.** A profile with the
two settings of step 7 is tested: Chrome 153 shows no prompt with it.

Once, on the agent machine, as the user of the agent:

1. In Chrome: the profile menu, then **Add**, then **Continue without an
   account**. Name the profile `agents`.
2. In the window of that profile, open
   `chrome://password-manager/settings`. Turn off **Offer to save
   passwords** and **Sign in automatically**.
3. Open `chrome://settings/addresses`. Turn off saving and filling of
   addresses.
4. Open `chrome://settings/payments`. Turn off saving and filling of
   payment methods.
5. Close the window. Do not use this profile by hand, do not sign in to
   Google in it, and do not add extensions to it: every agent session
   gets a copy of it.
6. In `~/.agent-browser/config.json`, add `"profile": "agents"`.
7. Check: the `Preferences` file in the profile's folder has
   `"credentials_enable_service": false` and
   `"profile": {"password_manager_enabled": false}`. Then do a test login
   (section 2): Chrome must show no "Save password?" prompt.

**Never unlock your own vault in this browser**, or in any browser or app
that an agent can drive (THREAT-MODEL.md T32 and T46).
