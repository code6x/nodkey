package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"

	"github.com/code6x/nodkey/internal/audit"
)

// Exit codes of nodkey audit verify (DESIGN.md section 15), from
// sysexits.h like exitUsage.
const (
	exitDataErr = 65 // EX_DATAERR: the log failed the check
	exitNoInput = 66 // EX_NOINPUT: a file cannot be opened or read
)

const auditUsageText = `Usage: nodkey audit verify FILE [--anchor SEQ:HASH]... [--anchors FILE|-]

Check the hash chain of an audit log, and that each anchor matches its
entry. The broker writes "audit anchor SEQ:HASH" to the journal for each
entry. Check with every anchor since the log began, not only the newest:
the newest anchor proves only the entries up to it, and only since it was
written. For example:

  journalctl -u nodkey -o cat | nodkey audit verify FILE --anchors -

  --anchor SEQ:HASH  check that entry SEQ has the hash HASH; may repeat
  --anchors FILE     read the anchors from FILE, or from stdin for "-":
                     every line that is exactly "audit anchor SEQ:HASH"

Exit codes: 0 the log passed, 64 wrong usage, 65 the log failed the
check, 66 a file cannot be opened or read, 1 the result cannot be
printed.
`

// runAudit runs nodkey audit with args (after "audit").
func runAudit(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageFail(stderr, "audit", `give a command: "verify"`)
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(args[1:], stdin, stdout, stderr)
	case "-h", "-help", "--help", "help":
		if _, err := io.WriteString(stdout, auditUsageText); err != nil {
			return exitFailure
		}
		return exitOK
	default:
		return usageFail(stderr, "audit", fmt.Sprintf("unknown command %.64q", args[0]))
	}
}

// runAuditVerify runs nodkey audit verify. It never prints text from the
// log: a line could hold a secret pasted by mistake.
func runAuditVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nodkey audit verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var anchors anchorList
	fs.Var(&anchors, "anchor", "check that entry SEQ has the hash HASH (`SEQ:HASH`); may repeat")
	var anchorsFile onceString
	fs.Var(&anchorsFile, "anchors", "read the anchors from `FILE`, or from stdin for -")
	// FILE may come before or after the flags.
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printAuditUsage(stderr)
		}
		return parseErrorCode(stderr, "audit verify", err)
	}
	if fs.NArg() == 0 {
		return usageFail(stderr, "audit verify", "name the log FILE")
	}
	path := fs.Arg(0)
	if err := fs.Parse(fs.Args()[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printAuditUsage(stderr)
		}
		return parseErrorCode(stderr, "audit verify", err)
	}
	if fs.NArg() > 0 {
		return usageFail(stderr, "audit verify", "give one FILE only")
	}
	if anchorsFile.set {
		read, code := readAnchorsFile(anchorsFile.value, stdin, stderr)
		if code != exitOK {
			return code
		}
		anchors = append(anchors, read...)
	}

	f, err := os.Open(path) //nolint:gosec // G304: the person names the log to check; nodkey only reads it.
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nodkey: audit verify: %v\n", err) // a *fs.PathError names the path
		return exitNoInput
	}
	res, err := audit.Verify(f, anchors...)
	_ = f.Close() // read only; a close error changes nothing
	if ve := (*audit.VerifyError)(nil); errors.As(err, &ve) {
		_, _ = fmt.Fprintf(stderr, "nodkey: audit log %s: %v\n", path, ve)
		return exitDataErr
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nodkey: audit log %s: %v\n", path, err)
		return exitNoInput
	}

	out := fmt.Sprintf("ok: %d entries (torn lines: %d)\n", res.Entries, res.TornLines)
	if res.Anchors == 0 {
		out += "anchors: none checked\n"
	} else {
		newest := slices.MaxFunc(anchors, func(a, b audit.Anchor) int { return cmp.Compare(a.Seq, b.Seq) })
		out += fmt.Sprintf("anchors: %d checked, all match; the newest is entry %d\n", res.Anchors, newest.Seq)
	}
	// The last line is the last entry. Entries after the newest anchor are
	// not proven.
	out += fmt.Sprintf("last entry: %s\n", res.Last)
	if _, err := io.WriteString(stdout, out); err != nil {
		return exitFailure
	}
	return exitOK
}

// readAnchorsFile reads the anchors of --anchors: from stdin for "-",
// else from the file at path. A file with no anchor is wrong usage: the
// person meant to check anchors, and none would be checked.
func readAnchorsFile(path string, stdin io.Reader, stderr io.Writer) ([]audit.Anchor, int) {
	r := stdin
	if path != "-" {
		f, err := os.Open(path) //nolint:gosec // G304: the person names the file with the anchors; nodkey only reads it.
		if err != nil {
			var pe *fs.PathError
			if errors.As(err, &pe) {
				err = pe.Err // the path is the person's own text; show it quoted and cut
			}
			_, _ = fmt.Fprintf(stderr, "nodkey: audit verify: --anchors %.64q: %v\n", path, err)
			return nil, exitNoInput
		}
		defer func() { _ = f.Close() }() // read only; a close error changes nothing
		r = f
	}
	anchors, err := audit.ReadAnchors(r)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nodkey: audit verify: --anchors %.64q: %v\n", path, err)
		return nil, exitNoInput
	}
	if len(anchors) == 0 {
		return nil, usageFail(stderr, "audit verify", fmt.Sprintf("--anchors %.64q: no line is exactly %q and an anchor; "+
			"use journalctl -o cat", path, audit.JournalPrefix))
	}
	return anchors, exitOK
}

// anchorList is the --anchor flag. It may repeat.
type anchorList []audit.Anchor

func (l *anchorList) String() string { return fmt.Sprint(len(*l), " anchors") }

func (l *anchorList) Set(s string) error {
	a, err := audit.ParseAnchor(s)
	if err != nil {
		return err
	}
	*l = append(*l, a)
	return nil
}

// onceString is a flag that may be given once.
type onceString struct {
	value string
	set   bool
}

func (o *onceString) String() string { return o.value }

func (o *onceString) Set(s string) error {
	if o.set {
		return errors.New("give it once")
	}
	o.value, o.set = s, true
	return nil
}

// printAuditUsage writes the usage of nodkey audit to w. A failed write to
// stderr cannot be reported anywhere, so the error is ignored.
func printAuditUsage(w io.Writer) {
	_, _ = io.WriteString(w, auditUsageText)
}
