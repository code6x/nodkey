package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/code6x/nodkey/internal/release"
	nodkeyversion "github.com/code6x/nodkey/internal/version"
)

// versionCheckTimeout bounds the check of nodkey version for a newer
// release.
const versionCheckTimeout = 10 * time.Second

const versionUsage = `Usage: nodkey version [--offline]

Print the version of nodkey on stdout, such as "nodkey 0.2.0". When
stdout is a terminal, a release of nodkey then asks GitHub for the
newest release, for at most 10 seconds, and prints one line on stderr:
whether a newer release is out, or why it could not check. When stdout
is not a terminal, such as a pipe or a file, it prints no such line and
makes no call to GitHub. Neither does a build from the source.

  --offline  do not ask GitHub

The exit code is 0, also when the check fails, 64 on wrong usage, and 1
when stdout cannot be written.
`

// versionCheck is what the check of nodkey version for a newer release
// uses. Tests use fakes, so that no test asks GitHub or needs a terminal.
type versionCheck struct {
	// isTerminal reports whether stdout is a terminal.
	isTerminal func(w io.Writer) bool
	// newest asks GitHub for the newest release, for a nodkey whose
	// version is own.
	newest func(ctx context.Context, own nodkeyversion.Release) (nodkeyversion.Release, error)
}

// realVersionCheck asks GitHub, on a real terminal.
var realVersionCheck = versionCheck{
	isTerminal: isTerminal,
	newest: func(ctx context.Context, own nodkeyversion.Release) (nodkeyversion.Release, error) {
		info, err := release.New(own).Lookup(ctx)
		return info.Newest, err
	},
}

// runVersion runs nodkey version with args (after "version"), for a nodkey
// whose version is own, and returns the exit code. It prints the line
// "nodkey <own>" on stdout, as before: the installer and scripts read it.
// Then, only when own is a release, --offline is not given and stdout is
// a terminal, it asks GitHub for the newest release, and prints one line
// on stderr. Only stdout decides: when it is a pipe or a file, such as in
// $(...) in the installer, nodkey version never waits for GitHub, and
// prints no other line.
func runVersion(args []string, own string, stdout, stderr io.Writer, check versionCheck) int {
	fs := flag.NewFlagSet("nodkey version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = io.WriteString(stderr, versionUsage) }
	offline := fs.Bool("offline", false, "do not ask GitHub")
	if err := fs.Parse(args); err != nil {
		return parseErrorCode(err)
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return exitUsage
	}
	if _, err := fmt.Fprintf(stdout, "nodkey %s\n", own); err != nil {
		return exitFailure
	}
	r, isRelease := nodkeyversion.ParseRelease(own)
	if *offline || !isRelease || !check.isTerminal(stdout) {
		return exitOK
	}
	ctx, cancel := context.WithTimeout(context.Background(), versionCheckTimeout)
	defer cancel()
	newest, err := check.newest(ctx, r)
	// A failed write to stderr cannot be reported anywhere; stdout has the
	// version.
	_, _ = io.WriteString(stderr, releaseLine(r, newest, err)+"\n")
	return exitOK
}

// releaseLine returns the line of nodkey version about the newest release
// newest, for a nodkey whose version is own, or about err. It holds only
// fixed text, release versions, the link made from the version, and the
// error, whose text is fixed too. A newest release that is not newer
// than own, also an older one, is "the newest release": nodkey never
// suggests a downgrade.
func releaseLine(own, newest nodkeyversion.Release, err error) string {
	switch {
	case err != nil:
		return "nodkey: cannot check for a newer release: " + err.Error()
	case newest.Compare(own) > 0:
		return "nodkey: a newer release is out: nodkey " + newest.String() +
			`; to update, run "sudo nodkey update"; release notes: ` + release.PageURL(newest)
	}
	return "nodkey: this is the newest release"
}
