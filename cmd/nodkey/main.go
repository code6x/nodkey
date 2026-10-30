// Command nodkey lets an AI coding agent use a secret or an SSH key only
// after a person approves that one request on a phone.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/code6x/nodkey/internal/client"
	"github.com/code6x/nodkey/internal/transport"
	runningversion "github.com/code6x/nodkey/internal/version"
)

// version is the nodkey version. Release builds set it with
// -ldflags "-X main.version=<version>".
var version = "dev"

// writeKeyFile makes the key file of nodkey keygen. It is a variable only
// so that a test can run keygen in a child process without the real
// directory checks, which refuse the system temporary directory.
var writeKeyFile keyWriter = transport.GenerateKeyFile

// Exit codes.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 64 // EX_USAGE from sysexits.h: the command was used wrongly.
)

const usageText = `Usage: nodkey <command> [arguments]

Commands:
  broker [--config FILE]
            run the broker: the daemon that asks the approver on Telegram
  keygen    make a TLS key for the broker or a client, and print its pin
  run       run a command with secrets, once a person approves on the phone
  ssh-agent serve an SSH agent for ssh; the keys stay on the broker
  ssh-grant ask once for SSH logins to a list of hosts, for some minutes
  preapprove ask now for a grant to use later: secrets or SSH logins, in a
            time span, for a number of uses
  audit verify FILE [--anchor SEQ:HASH]... [--anchors FILE|-]
            check the hash chain of an audit log, and its anchors
  update [--version X.Y.Z] [--gh PATH] [--reinstall | --notes]
            install a release in place of this nodkey, or with --notes
            only print its changes; run it as root
  changes --since X.Y.Z
            print the changes after X.Y.Z from the built-in changelog
  version [--offline]
            print the version; on a terminal, also say if a newer
            release is out
  help [COMMAND]
            print this help, or the help of COMMAND

Options:
  --version same as the command version
`

func main() {
	runningversion.Running = version
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run runs nodkey with args (without the program name) and returns the
// exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nodkey", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	// --version is the command version, with the flags of that command.
	if len(args) > 0 && (args[0] == "-version" || args[0] == "--version") {
		return runVersion(args[1:], version, stdout, stderr, realVersionCheck)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(stderr)
		}
		return parseErrorCode(stderr, "", err)
	}
	if fs.NArg() == 0 {
		return usageFail(stderr, "", "give a command")
	}

	name, rest := fs.Arg(0), fs.Args()[1:]
	switch name {
	case "broker":
		return runBroker(rest, stderr)
	case "keygen":
		ignoreBrokenPipe()
		return runKeygen(rest, stdout, stderr, writeKeyFile)
	case "audit":
		return runAudit(rest, stdin, stdout, stderr)
	case "run":
		return runRun(rest, stderr)
	case "ssh-agent":
		return runSSHAgent(rest, stderr)
	case "ssh-grant":
		return runSSHGrant(rest, stderr)
	case "preapprove":
		return runPreapprove(rest, stdout, stderr)
	case "update":
		return runUpdate(rest, stdout, stderr)
	case "changes":
		return runChanges(rest, stdout, stderr)
	case "version":
		return runVersion(rest, version, stdout, stderr, realVersionCheck)
	case "help":
		return runHelp(rest, stdin, stdout, stderr)
	default:
		return usageFail(stderr, "", fmt.Sprintf("unknown command %.64q", name))
	}
}

// printUsage writes the usage text to w. A failed write to stderr cannot
// be reported anywhere, so the error is ignored.
func printUsage(w io.Writer) {
	_, _ = io.WriteString(w, usageText)
}

// usageFail writes the one line of a usage error of the command cmd ("" for
// nodkey itself) and returns exitUsage: "nodkey CMD: REASON; see "nodkey CMD
// --help" (exit 64)". It prints no usage text.
func usageFail(stderr io.Writer, cmd, reason string) int {
	return client.UsageError(stderr, cmd, reason)
}

// parseErrorCode returns the exit code for an error from flag parsing. For
// --help it is 0, and the command prints its usage before. Else it writes
// the one line of the usage error; the flag set must have its output
// discarded.
func parseErrorCode(stderr io.Writer, cmd string, err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	return usageFail(stderr, cmd, flagErrorText(err.Error()))
}

// flagErrorText turns the text of an error of the flag package into our
// own text. It never passes the text on as it is: the flag package puts
// the user's input into it. The input is quoted and cut to 64 characters.
// The reason of a bad value is kept (at most 64 characters), because it
// comes from the flag package or from our own flag types, and it is fixed
// text, such as "want X.Y.Z, such as 0.2.0".
func flagErrorText(msg string) string {
	if name, ok := strings.CutPrefix(msg, "flag provided but not defined: -"); ok {
		return fmt.Sprintf("unknown option %.64q", name)
	}
	if name, ok := strings.CutPrefix(msg, "flag needs an argument: -"); ok {
		return fmt.Sprintf("option %.64q needs a value", name)
	}
	rest, ok := strings.CutPrefix(msg, "invalid value ")
	if !ok {
		rest, ok = strings.CutPrefix(msg, "invalid boolean value ")
	}
	if ok {
		// The value is quoted with %q, so its end is exact.
		if quoted, err := strconv.QuotedPrefix(rest); err == nil {
			rest = rest[len(quoted):]
			rest = strings.TrimPrefix(strings.TrimPrefix(rest, " for flag"), " for")
			name, reason, _ := strings.Cut(strings.TrimPrefix(rest, " -"), ": ")
			return fmt.Sprintf("bad value for option %.64q: %s", name, reason)
		}
	}
	return "wrong option"
}

// runHelp prints the general usage, or with one argument the help of that
// command: the same text as "nodkey COMMAND --help", but on stdout.
func runHelp(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	switch {
	case len(args) > 1:
		return usageFail(stderr, "help", "give at most one command")
	case len(args) == 0 || slices.Contains([]string{"help", "-h", "-help", "--help"}, args[0]):
		if _, err := io.WriteString(stdout, usageText); err != nil {
			return exitFailure
		}
		return exitOK
	}
	name := args[0]
	if !slices.Contains(commands, name) {
		return usageFail(stderr, "help", fmt.Sprintf("unknown command %.64q", name))
	}
	out := &recordingWriter{w: stdout}
	code := run([]string{name, "--help"}, stdin, out, out)
	if out.err != nil {
		return exitFailure
	}
	return code
}

// commands are the commands of nodkey that "nodkey help COMMAND" knows.
// Each must handle --help before it does any work.
var commands = []string{"broker", "keygen", "audit", "run", "ssh-agent", "ssh-grant", "preapprove", "update", "changes", "version"}

// recordingWriter keeps the first write error, because the usage
// functions of the commands ignore it.
type recordingWriter struct {
	w   io.Writer
	err error
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	n, err := r.w.Write(p)
	if err != nil && r.err == nil {
		r.err = err
	}
	return n, err
}
