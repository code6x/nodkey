package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/code6x/nodkey/internal/audit"
)

// Exit codes of nodkey audit verify (DESIGN.md section 15), from
// sysexits.h like exitUsage.
const (
	exitDataErr = 65 // EX_DATAERR: the log failed the check
	exitNoInput = 66 // EX_NOINPUT: a file cannot be opened or read
)

const auditUsageText = `Usage: nodkey audit verify FILE [--anchor SEQ:HASH]... [--anchors FILE|-]
                          [--accept-open SEQ:HASH]...

Check the hash chain of an audit log, and that each anchor matches its
entry. The broker writes "audit anchor SEQ:HASH LOGID" to the journal for
each entry, and "audit open SEQ:HASH LOGID" each time it opens the log.
LOGID is the SHA-256 of line 1 of the log. Check with every anchor since the log began, not only the newest:
the newest anchor proves only the entries up to it, and only since it was
written. For example:

  journalctl -u nodkey -o cat | nodkey audit verify FILE --anchors -

  --anchor SEQ:HASH  check that entry SEQ has the hash HASH; may repeat
  --anchors FILE     read the journal lines from FILE, or from stdin for
                     "-": every line that is exactly "audit anchor
                     SEQ:HASH LOGID" or "audit open SEQ:HASH LOGID". Each
                     open line must match the last anchor of its log
                     before it. Lines of other logs (another LOGID) are
                     shown, not checked. An "audit anchor SEQ:HASH" line
                     without LOGID is of the log of the next open line
                     with a LOGID.
  --accept-open SEQ:HASH
                     accept the open line "audit open SEQ:HASH LOGID"
                     that does not match, on your word: only after you
                     know why, such as a power cut. Entry SEQ must still
                     have the hash HASH. Needs --anchors; may repeat

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
	var accepts anchorList
	fs.Var(&accepts, "accept-open", "accept the open line with the head `SEQ:HASH` as a known gap; may repeat")
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
	if len(accepts) > 0 && !anchorsFile.set {
		return usageFail(stderr, "audit verify", "--accept-open needs --anchors with the journal")
	}
	var journal []audit.JournalLine
	if anchorsFile.set {
		read, code := readJournalFile(anchorsFile.value, stdin, stderr)
		if code != exitOK {
			return code
		}
		journal = read
	}

	f, err := os.Open(path) //nolint:gosec // G304: the person names the log to check; nodkey only reads it.
	if err != nil {
		if pe := (*os.PathError)(nil); errors.As(err, &pe) {
			err = pe.Err // the path is the person's own text; show it quoted and cut
		}
		_, _ = fmt.Fprintf(stderr, "nodkey: audit log %q: %v\n", path, err)
		return exitNoInput
	}
	var res audit.Result
	if anchorsFile.set {
		res, err = audit.VerifyJournal(f, journal, anchors, accepts)
	} else {
		res, err = audit.Verify(f, anchors...)
	}
	_ = f.Close() // read only; a close error changes nothing
	if ve := (*audit.VerifyError)(nil); errors.As(err, &ve) {
		printVerifyErrors(stderr, path, err)
		return exitDataErr
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nodkey: audit log %q: %v\n", path, err)
		return exitNoInput
	}

	out := fmt.Sprintf("ok: %d entries (torn lines: %d)\n", res.Entries, res.TornLines)
	if res.Anchors == 0 {
		out += "anchors: none checked\n"
	} else {
		out += fmt.Sprintf("anchors: %d checked, all match; the newest is entry %d\n", res.Anchors,
			res.NewestAnchor)
	}
	if anchorsFile.set {
		out += fmt.Sprintf("log ID: %s\n", res.LogID)
		out += fmt.Sprintf("open lines: %d checked, all match the anchor before them; new log starts: %d\n",
			res.Opens, res.NewStarts)
		if res.AcceptedOpens > 0 {
			out += fmt.Sprintf("accepted gaps: %d open lines that do not match, accepted with --accept-open\n",
				res.AcceptedOpens)
		}
		for _, o := range res.OtherLogs {
			out += fmt.Sprintf("other log in the journal: ID %s, up to entry %d; "+
				"if no person moved it away, it was deleted or replaced\n", o.LogID, o.Newest)
		}
	}
	// The last line is the last entry. Entries after the newest anchor are
	// not proven.
	out += fmt.Sprintf("last entry: %s\n", res.Last)
	if _, err := io.WriteString(stdout, out); err != nil {
		return exitFailure
	}
	return exitOK
}

// printVerifyErrors writes each problem of err, a *audit.VerifyError or
// several joined, on its own line. If one is a gap at an open line, a last
// line says how to find out why, and how to accept it then.
func printVerifyErrors(stderr io.Writer, path string, err error) {
	errs := []error{err}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		errs = j.Unwrap()
	}
	gap := false
	for _, e := range errs {
		_, _ = fmt.Fprintf(stderr, "nodkey: audit log %q: %v\n", path, e)
		if ve := (*audit.VerifyError)(nil); errors.As(e, &ve) && ve.Gap {
			gap = true
		}
	}
	if gap {
		_, _ = io.WriteString(stderr, "nodkey: audit verify: find out why each open line does not match "+
			"(docs/setup.md section 12); if you know that a gap is harmless, such as after a power cut, "+
			"give --accept-open SEQ:HASH with the head of that \"audit open\" line\n")
	}
}

// readJournalFile reads the journal lines of --anchors: from stdin for
// "-", else from the file at path. A file with no anchor or open line is
// wrong usage: the person meant to check anchors, and none would be
// checked.
func readJournalFile(path string, stdin io.Reader, stderr io.Writer) ([]audit.JournalLine, int) {
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
	lines, err := audit.ReadJournal(r)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nodkey: audit verify: --anchors %.64q: %v\n", path, err)
		return nil, exitNoInput
	}
	if len(lines) == 0 {
		return nil, usageFail(stderr, "audit verify", fmt.Sprintf("--anchors %.64q: no line is exactly %q or %q "+
			"and an anchor; use journalctl -o cat", path, audit.JournalPrefix, audit.JournalOpenPrefix))
	}
	return lines, exitOK
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
