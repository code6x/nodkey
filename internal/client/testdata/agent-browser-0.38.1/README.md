# Recorded requests of agent-browser 0.38.1

These are the exact requests that agent-browser 0.38.1 (npm package
`agent-browser@0.38.1`, binary `agent-browser-linux-x64`) wrote to the
stdin of a recording plugin, on 2026-11-13. The page was a local test
page on 127.0.0.1. `abplugin_test.go` sends them to
`nodkey agent-browser-plugin`.

| file | command |
|---|---|
| `credential-resolve.json` | `agent-browser auth login shop --credential-provider nodkey --item 11111111-1111-1111-1111-111111111111 --url https://127.0.0.1:18766/login.html` |
| `credential-resolve-no-url.json` | `agent-browser auth login nourl --credential-provider nodkey --item abc` (no `--url`) |
| `plugin-run-list.json` | `agent-browser plugin run nodkey nodkey.list --payload '{"url":"https://example.com/"}'` |
| `plugin-run-totp.json` | `agent-browser plugin run nodkey nodkey.totp --payload '{"itemRef":"11111111-1111-1111-1111-111111111111","url":"https://127.0.0.1:18766/login.html"}'` |

What agent-browser 0.38.1 does with the answer (seen the same day):

- It reads one JSON object from stdout, and only when the plugin exits
  with 0. It needs `"protocol":"agent-browser.plugin.v1"` in it.
- `credential.resolve`: on success, it reads the object `credential`
  (`username`, `password`, `url`). On `"success":false` it prints only
  "returned success=false", not the error text.
- `plugin run`: it prints the whole answer on success, and the `error`
  text on `"success":false`.
- It does not show the plugin's stderr.
- The command in its config is not split at spaces: the argument goes in
  `"args"`.
