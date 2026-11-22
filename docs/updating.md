# Updating nodkey

This page lists each change in nodkey that can break a program or a
script that uses it: a new default, other output on stdout or stderr, a
new exit code, other signals, another process that runs the command, a
new meaning of a config key, or a new time limit. Before you update,
read every section from your version up to the new one.

Each section says who is affected, what to do, and gives a command that
shows the new way. The steps of an update itself are in
[docs/setup.md, section 13](setup.md#13-upgrades-and-key-changes).

From 2026-11-17 on, the release notes list such a change under
"⚠ BREAKING CHANGES", and its pull request adds a section here
([docs/releasing.md](releasing.md#changes-in-behavior-for-callers)).
Older releases listed it as a normal feature.

## Updating from 0.8.0 or older

**What changed (#225).** A client may ask for a secret of a
`[project.*]` section by its ID in Bitwarden, as `SECTION/ID`. When the
part after the `/` is a UUID, the broker now matches it only with the
IDs of the secrets of the project, never with their keys. Before, it was
matched with the keys.

**Who is affected.** Only a caller that asks for a project secret whose
key in Bitwarden is itself a UUID, such as
`ci/0a1b2c3d-0000-4000-8000-00000000a002`. That name now asks for the
secret with that ID. If no secret of the project has that ID, the
request is denied, as for an unknown key.

**What to do.** Give the secret a key that is not a UUID in Bitwarden,
or ask for it by its ID. The tap message shows which secret it is: its
key and the last 8 characters of its ID. For example:

```sh
nodkey run --secret TOKEN=ci/0a1b2c3d-0000-4000-8000-00000000a002 -- my-tool
```

## Updating from 0.7.0 or older

**What changed (#214).** Nothing that a caller sees. The harness of the
contract tests in `test/contract/` (#209, new after 0.7.0) now stops
the trial broker (`nodkey try`) with SIGTERM alone. Before, it closed the
stdin of `nodkey try` first, and sometimes `nodkey try` saw the end of
its input before the signal and ended with exit status 1. No release had
the old harness. A change to the harness
counts as a change in behavior for callers
([test/contract/README.md](../test/contract/README.md)), so it has this
section. `nodkey run` and `nodkey try` did not change.

**Who is affected.** No caller of `nodkey run`. A person who runs the
contract tests gets the same tests, without the random failure at the
end.

**What to do.** Nothing. To run the contract tests:

```sh
go test -race -count=1 ./test/contract/
```

## Updating from 0.5.0 or older

**What changed (0.6.0, #171).** `nodkey run` masks the values that it
fetched: it replaces each one with `***` in the command's stdout and
stderr. This is now the default whenever stdout or stderr of
`nodkey run` is not a terminal. A masked `nodkey run` stays as the parent
of the command: it does not replace itself with the command, as 0.5.0
did. On a terminal (stdout and stderr both a terminal), nothing changed.

**Who is affected.**

- A program that reads the output of `nodkey run` through a pipe, such
  as a mail client with a password command like
  `nodkey run --secret P=mail-read -- printenv P`. It now gets `***`, and
  its login fails.
- A script that checks that its parent is the process that started
  `nodkey run`. Its parent is now a process named `nodkey`.

**What to do.** Keep the mask on. With `--no-mask`, even a plain
`printenv` or a debug line of the command shows the value.

- For a password command: run the program itself inside `nodkey run`,
  and let its password command read the value from the program's own
  environment. For example, with `password.cmd = "printenv MAIL_READ"` in
  the program's config:

  ```sh
  nodkey run --secret MAIL_READ=mail-read --reason "read the mail" -- mail-client sync
  ```

- For a parent check: accept a parent named `nodkey`, and look at that
  process's parent. nodkey is not dumpable, so read `/proc/PID/stat`, not
  `/proc/PID/exe`:

  ```sh
  parent=$PPID
  name=$(sed 's/^[0-9]* (\(.*\)) .*/\1/' "/proc/$parent/stat")
  if [ "$name" = nodkey ]; then
    parent=$(awk '{print $4}' "/proc/$parent/stat")
  fi
  ```

  A process name is not proof: any program of the same user can take
  the name `nodkey`. Use this only where the parent check is a
  convenience, not a security boundary.

The full text, with what a masked command gets (stdin, file descriptors)
and the risks of each way, is in
[docs/setup.md, "Keep the mask on"](setup.md#keep-the-mask-on-password-commands-and-wrappers).
