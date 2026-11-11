package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/doctor"
)

const configDiffUsage = `Usage: nodkey broker config-diff [--short] [--max-chars N] OLD NEW

List the changes from the broker config OLD to NEW by what they mean:
who gets which secret or SSH key, and with or without a tap. Comments,
order and spaces are not changes. Each change that widens access or
weakens a control starts with a warning sign (⚠). So does each change
that config-diff does not know as one that narrows access.

OLD and NEW are each a config file, with the known_hosts that it uses
next to it (by the base name of its path in the config), or a directory
with broker.toml and known_hosts (as "nodkey broker check --files DIR"). It reads no
credential, needs no root, and uses no network.

  --short        print a short form that fits one Telegram message: the
                 changes that widen access first, then the rest, cut with
                 "and N more"
  --max-chars N  the most characters of the short form (default 3500)

Exit codes: 0 the configs mean the same, 1 they differ, 2 a file cannot
be read or is not a valid config, 64 wrong usage.
`

// exitDiffUnreadable is the exit code of nodkey broker config-diff when
// a config cannot be read.
const exitDiffUnreadable = 2

// runConfigDiff runs nodkey broker config-diff (issue #174).
func runConfigDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nodkey broker config-diff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	short := fs.Bool("short", false, "the short form")
	maxChars := fs.Int("max-chars", 3500, "the most characters of the short form")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, configDiffUsage)
			return exitOK
		}
		return parseErrorCode(stderr, "broker config-diff", err)
	}
	if fs.NArg() != 2 {
		return usageFail(stderr, "broker config-diff", "give OLD and NEW, each a config file or a directory, "+
			"after the options")
	}
	if *maxChars < minShortChars || *maxChars > 100000 {
		return usageFail(stderr, "broker config-diff", fmt.Sprintf("--max-chars must be from %d to 100000", minShortChars))
	}
	// ${CREDENTIALS_DIRECTORY} stands for the directory of the unit. No
	// file in it is read; only the paths are compared.
	if err := os.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/"+doctor.Unit); err != nil {
		_, _ = fmt.Fprintf(stderr, "nodkey broker config-diff: cannot set CREDENTIALS_DIRECTORY: %s\n", err)
		return exitDiffUnreadable
	}
	var cfgs [2]*config.Broker
	for i, arg := range fs.Args() {
		cfg, err := readDiffArg(arg)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "nodkey broker config-diff: %s: %s; %s\n", [2]string{"OLD", "NEW"}[i],
				claim.Line(err.Error(), checkLineMax), claim.Line(diffArgHint(arg), checkLineMax))
			return exitDiffUnreadable
		}
		cfgs[i] = cfg
	}
	changes := config.Diff(cfgs[0], cfgs[1])
	if len(changes) == 0 {
		_, _ = io.WriteString(stdout, "no change\n")
		return exitOK
	}
	lines := make([]string, len(changes))
	widens := make([]bool, len(changes))
	for i, c := range changes {
		c.Text = claim.Line(c.Text, checkLineMax)
		lines[i], widens[i] = c.String(), c.Widens
	}
	if *short {
		lines = shortForm(lines, widens, *maxChars)
	}
	_, _ = io.WriteString(stdout, strings.Join(lines, "\n")+"\n")
	return exitFailure
}

// readDiffArg reads a config for config-diff: a file, or a directory
// with broker.toml and known_hosts. It uses the parser of the start
// (config.ReadBrokerFiles), without the checks of the other files.
func readDiffArg(arg string) (*config.Broker, error) {
	fi, err := os.Stat(arg)
	if err != nil {
		return nil, err // a *fs.PathError names the path
	}
	if fi.IsDir() {
		return config.ReadBrokerFiles(filepath.Join(arg, "broker.toml"), arg)
	}
	// known_hosts comes from the directory of the file, not from the path
	// in the config: two configs that name the same path would otherwise
	// both read the live file, and a new host key would not show.
	return config.ReadBrokerFiles(arg, filepath.Dir(arg))
}

// diffArgHint says how to check the config arg that cannot be read.
func diffArgHint(arg string) string {
	fi, err := os.Stat(arg)
	switch {
	case err != nil:
		return "give a config file, or a directory with broker.toml and known_hosts, that exists"
	case fi.IsDir():
		return fmt.Sprintf("check it with nodkey broker check --files %q (docs/setup.md section 7)", arg)
	}
	return fmt.Sprintf("check it with nodkey broker check --config %q --files %q (docs/setup.md section 7)",
		arg, filepath.Dir(arg))
}

// minShortChars is the smallest --max-chars: room for the line that says
// how many changes widen access.
const minShortChars = 200

// shortForm cuts lines to at most maxChars characters, with the lines
// that widen access first. When it cuts, the last line says how many
// lines are left out. When the lines that widen do not all fit, it gives
// none of them: one line says how many there are, and that the full list
// must be read.
func shortForm(lines []string, widens []bool, maxChars int) []string {
	var wide, rest []string
	for i, l := range lines {
		if widens[i] {
			wide = append(wide, l)
		} else {
			rest = append(rest, l)
		}
	}
	all := append(append([]string(nil), wide...), rest...)
	if size(all) <= maxChars {
		return all
	}
	more := func(n int) string {
		return fmt.Sprintf("and %d more; read the full list with nodkey broker config-diff OLD NEW", n)
	}
	if size(append(append([]string(nil), wide...), more(len(rest)))) > maxChars {
		return []string{fmt.Sprintf("⚠ %d changes widen access, and they do not fit here; read the full "+
			"list with nodkey broker config-diff OLD NEW (%d changes in all)", len(wide), len(lines))}
	}
	out := append([]string(nil), wide...)
	for i, l := range rest {
		next := append(append([]string(nil), out...), l, more(len(rest)-i-1))
		if size(next) > maxChars {
			return append(out, more(len(rest)-i))
		}
		out = append(out, l)
	}
	return out // not reached: all lines did not fit
}

// size is the number of characters of lines joined with line breaks, as
// Telegram counts them: in UTF-16 code units.
func size(lines []string) int {
	n := 0
	for _, l := range lines {
		n += len(utf16.Encode([]rune(l))) + 1
	}
	return max(n-1, 0)
}
