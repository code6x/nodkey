package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/code6x/nodkey"
	nodkeyversion "github.com/code6x/nodkey/internal/version"
)

const changesUsage = `Usage: nodkey changes --since X.Y.Z

Print the changes of the releases after X.Y.Z, from the changelog that is
built into this nodkey. The security fixes of all these releases come
first, then the other changes. If there is no security fix, it says so
first, then lists the changes. nodkey update --notes runs this with the
new, checked release, before it installs anything.

  --since X.Y.Z  the version that you run now, such as 0.2.0

Exit codes: 0 done, 1 failure, 64 wrong usage.
`

// runChanges runs nodkey changes with the changelog that is built into
// this binary.
func runChanges(args []string, stdout, stderr io.Writer) int {
	return changesOf(nodkey.Changelog, args, stdout, stderr)
}

// changesOf runs nodkey changes with the changelog text, so that a test
// can give its own.
func changesOf(text string, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("nodkey changes", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var since nodkeyversion.Release
	sinceFlag := checkedFlag{check: func(s string) error {
		r, ok := nodkeyversion.ParseRelease(s)
		if !ok {
			return errors.New("want X.Y.Z, such as 0.2.0")
		}
		since = r
		return nil
	}}
	flags.Var(&sinceFlag, "since", "print the changes after the release `X.Y.Z`")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stderr, changesUsage)
		}
		return parseErrorCode(stderr, "changes", err)
	}
	if flags.NArg() > 0 {
		return usageFail(stderr, "changes", fmt.Sprintf("unexpected argument %.64q", flags.Arg(0)))
	}
	if !sinceFlag.set {
		return usageFail(stderr, "changes", "give --since X.Y.Z")
	}
	out := formatChanges(parseChangelog(text), since)
	if _, err := io.WriteString(stdout, out); err != nil {
		return exitFailure
	}
	return exitOK
}

// releaseEntry is the entry of one release in the changelog.
type releaseEntry struct {
	version  nodkeyversion.Release
	heading  string    // the heading line, without "## "
	security []string  // the lines of ### Security
	other    []section // the other sections, in their order
}

// section is a ### section of a release entry.
type section struct {
	title string
	lines []string
}

// parseChangelog reads the release entries of a changelog in the form
// that release-please writes. A release heading is "## [X.Y.Z](link)
// (date)" or "## X.Y.Z (date)". An entry whose heading has no valid
// version is left out, with all its lines: it cannot be compared.
func parseChangelog(text string) []releaseEntry {
	var entries []releaseEntry
	var cur *releaseEntry
	var sec *section
	inSecurity := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), len(text)+1)
	for scanner.Scan() {
		line := safeLine(scanner.Text())
		switch {
		case strings.HasPrefix(line, "## "):
			cur, sec, inSecurity = nil, nil, false
			heading := strings.TrimSpace(line[3:])
			if r, ok := nodkeyversion.ParseRelease(headingVersion(heading)); ok {
				entries = append(entries, releaseEntry{version: r, heading: heading})
				cur = &entries[len(entries)-1]
			}
		case cur == nil:
		case strings.HasPrefix(line, "### "):
			title := strings.TrimSpace(line[4:])
			inSecurity = title == "Security"
			sec = nil
			if !inSecurity {
				cur.other = append(cur.other, section{title: title})
				sec = &cur.other[len(cur.other)-1]
			}
		case strings.TrimSpace(line) == "":
		case inSecurity:
			cur.security = append(cur.security, line)
		case sec != nil:
			sec.lines = append(sec.lines, line)
		}
	}
	return entries
}

// headingVersion returns the version part of a release heading: the text
// in the first [ ], or the first word.
func headingVersion(heading string) string {
	if rest, ok := strings.CutPrefix(heading, "["); ok {
		v, _, _ := strings.Cut(rest, "]")
		return v
	}
	v, _, _ := strings.Cut(heading, " ")
	return v
}

// safeLine replaces each control character, each invisible format
// character (such as a change of the text direction), each line or
// paragraph separator and each invalid UTF-8 byte with "?", so that the
// changelog cannot send codes to the terminal or hide what it says.
func safeLine(line string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError ||
			r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, line)
}

// formatChanges returns the text that nodkey changes prints: the
// security items of the entries newer than since, then their other
// sections. Without security items, it says so in one line, and the
// sections come under # CHANGES.
func formatChanges(entries []releaseEntry, since nodkeyversion.Release) string {
	var newer []releaseEntry
	for _, e := range entries {
		if e.version.Compare(since) > 0 {
			newer = append(newer, e)
		}
	}
	if len(newer) == 0 {
		return fmt.Sprintf("No release in the changelog of this nodkey is newer than %s.\n", since)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Changes after nodkey %s, from the changelog of this nodkey.\n", since)
	var security []releaseEntry
	for _, e := range newer {
		if len(e.security) > 0 {
			security = append(security, e)
		}
	}
	if len(security) > 0 {
		b.WriteString("\n# SECURITY FIXES\n")
		for _, e := range security {
			fmt.Fprintf(&b, "\n## %s\n\n", e.heading)
			for _, l := range e.security {
				b.WriteString(l + "\n")
			}
		}
	}
	heading, empty := "# OTHER CHANGES", "No other changes."
	if len(security) == 0 {
		fmt.Fprintf(&b, "\nNo security fixes after nodkey %s.\n", since)
		heading, empty = "# CHANGES", "The changelog lists no changes for this release."
	}
	fmt.Fprintf(&b, "\n%s\n", heading)
	for _, e := range newer {
		fmt.Fprintf(&b, "\n## %s\n", e.heading)
		n := 0
		for _, s := range e.other {
			if len(s.lines) == 0 {
				continue
			}
			n++
			fmt.Fprintf(&b, "\n### %s\n\n", s.title)
			for _, l := range s.lines {
				b.WriteString(l + "\n")
			}
		}
		if n == 0 {
			fmt.Fprintf(&b, "\n%s\n", empty)
		}
	}
	return b.String()
}
