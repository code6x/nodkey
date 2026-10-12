// Command nodkey lets an AI coding agent use a secret or an SSH key only
// after a person approves that one request on a phone.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// version is the nodkey version. Release builds set it with
// -ldflags "-X main.version=<version>".
var version = "dev"

// Exit codes.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 64 // EX_USAGE from sysexits.h: the command was used wrongly.
)

const usageText = `Usage: nodkey <command> [arguments]

Commands:
  version   print the version
  help      print this help
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run runs nodkey with args (without the program name) and returns the
// exit code.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nodkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { printUsage(stderr) }
	if err := fs.Parse(args); err != nil {
		return parseErrorCode(err)
	}
	if fs.NArg() == 0 {
		printUsage(stderr)
		return exitUsage
	}

	name, rest := fs.Arg(0), fs.Args()[1:]
	switch name {
	case "version":
		return runVersion(rest, stdout, stderr)
	case "help":
		if _, err := io.WriteString(stdout, usageText); err != nil {
			return exitFailure
		}
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "nodkey: unknown command %q\n\n", name)
		printUsage(stderr)
		return exitUsage
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nodkey version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = io.WriteString(stderr, "Usage: nodkey version\n") }
	if err := fs.Parse(args); err != nil {
		return parseErrorCode(err)
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return exitUsage
	}
	if _, err := fmt.Fprintf(stdout, "nodkey %s\n", version); err != nil {
		return exitFailure
	}
	return exitOK
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
