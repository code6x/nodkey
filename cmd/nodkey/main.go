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

	"github.com/code6x/nodkey/internal/transport"
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
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run runs nodkey with args (without the program name) and returns the
// exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nodkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printUsage(stderr) }
	// --version is the command version, with the flags of that command.
	if len(args) > 0 && (args[0] == "-version" || args[0] == "--version") {
		return runVersion(args[1:], version, stdout, stderr, realVersionCheck)
	}
	if err := fs.Parse(args); err != nil {
		return parseErrorCode(err)
	}
	if fs.NArg() == 0 {
		printUsage(stderr)
		return exitUsage
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
		_, _ = fmt.Fprintf(stderr, "nodkey: unknown command %q\n\n", name)
		printUsage(stderr)
		return exitUsage
	}
}

// printUsage writes the usage text to w. A failed write to stderr cannot
// be reported anywhere, so the error is ignored.
func printUsage(w io.Writer) {
	_, _ = io.WriteString(w, usageText)
}

// parseErrorCode returns the exit code for an error from flag parsing.
// The flag package has already printed the message and the usage.
func parseErrorCode(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	return exitUsage
}

// runHelp prints the general usage, or with one argument the help of that
// command: the same text as "nodkey COMMAND --help", but on stdout.
func runHelp(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	switch {
	case len(args) > 1:
		_, _ = io.WriteString(stderr, "Usage: nodkey help [COMMAND]\n")
		return exitUsage
	case len(args) == 0 || slices.Contains([]string{"help", "-h", "-help", "--help"}, args[0]):
		if _, err := io.WriteString(stdout, usageText); err != nil {
			return exitFailure
		}
		return exitOK
	}
	name := args[0]
	if !slices.Contains(commands, name) {
		_, _ = fmt.Fprintf(stderr, "nodkey: unknown command %q\n\n", name)
		printUsage(stderr)
		return exitUsage
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
