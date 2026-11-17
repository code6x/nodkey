# Contract tests

These tests pin what a program or a script sees when it calls
`nodkey run`. They test the behavior that callers rely on, not the code
inside nodkey. They came after #191: the change to masking in #171 passed
every unit test, but it broke two kinds of callers.

**A change to a file here is a change in behavior for callers.** A pull
request that changes, removes or moves a file here, also the harness or
the helper, must say `Changes behavior for existing callers: yes`, must
put `!` in its title, and must add a section to
[docs/updating.md](../../docs/updating.md). The PR check does this
([docs/releasing.md](../../docs/releasing.md#changes-in-behavior-for-callers)).
Only two things do not count: a new `*_test.go` file, because a new
test pins behavior that callers already have, and a change to this
README. So put a new test in a new file.

Only this README and `*_test.go` files go in this folder: no subfolder,
no `testdata/`, no `go.mod`. The check counts any other new file as a
change in behavior.

## How they work

- `TestMain` builds `./cmd/nodkey` and starts a trial broker with
  `nodkey try` in a private directory. The tests answer its requests on
  its stdin: "Approve N min" for `demo-token`, and Deny for every other
  request. They run the real `nodkey run` with the client config of the
  trial.
- The command is the test binary itself (the helper), or `/bin/sh`. The
  helper writes facts to a report file: its process IDs, the name of its
  parent, what its stdin and fd 3 held, and the SHA-256 of the secret in
  its environment. It never writes the value, and no test prints it, also
  not on a failure.
- Each test runs in the ways that apply to it, out of five (pattern 5):
  stdout and stderr on pipes;
  stdout on a pipe and stderr on a pseudo-terminal; both on a
  pseudo-terminal with `--mask`; both on a pseudo-terminal (`execve`);
  and pipes with `--no-mask` (`execve`).
- They need Linux, `/bin/sh` and `/dev/ptmx`, and no root. They run in
  the `go test -race ./...` job of CI.

## The patterns

The documented behavior is in DESIGN.md section 5 ("What the command
gets") and in docs/setup.md section 11 ("Keep the mask on: password
commands and wrappers").

1. A password command: a program reads the output of `nodkey run` through
   a pipe, and gets `***`: `TestPasswordCommandThroughPipeGetsMask`. The
   documented way, where the program runs inside `nodkey run` and its
   password command reads the program's own environment, gets the value:
   `TestPasswordCommandInsideRunGetsValue`.
2. The parent of the command. Masked: a process named `nodkey`, whose
   parent is the caller; its `/proc/PID/stat` can be read and its
   `/proc/PID/exe` cannot (as root, that one check is left out). With
   `execve`: the command has the process ID of `nodkey run`, and its
   parent is the caller: `TestParentProcess`.
3. Exit codes and signals. The exit code of the command:
   `TestExitCode`. A command that dies of a signal: `TestDeathBySignal`.
   `SIGTERM` and `SIGHUP` reach the command; masked, `SIGINT` and
   `SIGUSR1` do not; with `execve`, they do: `TestSignalsReachCommand`.
4. stdin and inherited file descriptors: the command reads the stdin of
   `nodkey run`, and fd 3 that the caller passed reaches it. Masked, its
   stdout and stderr are pipes: `TestStdinAndFileDescriptors`.
5. Each test above, on pipes and on a pseudo-terminal (see "How they
   work").

Also: a denied request ends with exit 77, and the command does not run:
`TestDenied`.

## Run them

```sh
go test -race ./test/contract/...
```
