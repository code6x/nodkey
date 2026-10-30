package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/code6x/nodkey/internal/config"
)

const keygenUsage = `Usage: nodkey keygen --out FILE

Make a new TLS key for the broker or for a client, and write it to FILE
with mode 0600. FILE must not exist. Print the pin of the key on stdout,
and nothing else. Put the pin into the config of the other side: a
client's pin into the broker's [client.NAME] section, the broker's pin
into each client's broker_pin.
`

// keyWriter makes a new key file and returns its pin, like
// transport.GenerateKeyFile. Tests pass their own.
type keyWriter func(path string) (config.Pin, error)

// runKeygen runs nodkey keygen. It writes the key with write, then prints
// the pin, and nothing secret.
func runKeygen(args []string, stdout, stderr io.Writer, write keyWriter) int {
	flags := flag.NewFlagSet("nodkey keygen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	out := flags.String("out", "", "the new key file")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stderr, keygenUsage)
		}
		return parseErrorCode(stderr, "keygen", err)
	}
	if flags.NArg() > 0 {
		return usageFail(stderr, "keygen", fmt.Sprintf("unexpected argument %.64q", flags.Arg(0)))
	}
	if *out == "" {
		return usageFail(stderr, "keygen", "give --out FILE")
	}
	pin, err := write(*out)
	if err != nil {
		return fail(stderr, exitFailure, err.Error())
	}
	if _, err := fmt.Fprintln(stdout, pin.String()); err != nil {
		// Without the pin, the new key is of no use, and keygen would
		// refuse to write it again. So remove it.
		msg := "cannot print the pin, so the new key file was removed"
		if rerr := os.Remove(*out); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			msg = fmt.Sprintf("cannot print the pin, and cannot remove the new key file: %v", rerr)
		}
		return fail(stderr, exitFailure, msg)
	}
	return exitOK
}

// fail prints the last line of a nodkey command that fails, as DESIGN.md
// section 15 says: "nodkey: <reason> (exit <code>)". It returns code.
func fail(stderr io.Writer, code int, reason string) int {
	_, _ = fmt.Fprintf(stderr, "nodkey: %s (exit %d)\n", reason, code)
	return code
}
