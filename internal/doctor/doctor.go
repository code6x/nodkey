// Package doctor is the read-only check of a setup: nodkey doctor on a
// client and nodkey doctor broker on the broker host (DESIGN.md section
// 15). A check changes nothing, decrypts no credential and reads no secret
// value. Each failed check says what is wrong, why it matters, the fix and
// the docs section.
package doctor

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Status is the result of one check.
type Status string

// The statuses of a check.
const (
	OK   Status = "ok"
	Fail Status = "FAIL"
	Skip Status = "skip" // a check that this one needs did not pass
)

// Problem is what a failed check reports. Its texts hold fixed text, paths
// and versions: never a value from a file or a secret.
type Problem struct {
	What string // what is wrong
	Why  string // why it matters
	Fix  string // the command or the change that fixes it
	Docs string // the docs section, such as "docs/setup.md section 11"
}

// Check is one check. Run returns a short detail when it passes, or a
// Problem.
type Check struct {
	Name  string   // short and fixed, such as "config"
	Needs []string // the checks that must pass before this one runs
	Run   func() (detail string, p *Problem)
}

// Result is the result of one check. Its JSON form is fixed (DESIGN.md
// section 15).
type Result struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
	What   string `json:"what,omitempty"`
	Why    string `json:"why,omitempty"`
	Fix    string `json:"fix,omitempty"`
	Docs   string `json:"docs,omitempty"`
}

// Report is the result of all checks, in their order.
type Report struct {
	Checks []Result `json:"checks"`
}

// Run runs checks in their order. A check whose Needs did not all pass is
// skipped. A Problem without a fix or a docs section is a mistake in
// nodkey; it still counts as a failure.
func Run(checks []Check) Report {
	passed := map[string]bool{}
	var r Report
	for _, c := range checks {
		res := Result{Name: c.Name, Status: OK}
		var missing []string
		for _, n := range c.Needs {
			if !passed[n] {
				missing = append(missing, n)
			}
		}
		if len(missing) > 0 {
			res.Status = Skip
			res.Detail = "needs " + strings.Join(missing, ", ")
			r.Checks = append(r.Checks, res)
			continue
		}
		detail, p := c.Run()
		if p != nil {
			res.Status, res.What, res.Why, res.Fix, res.Docs = Fail, p.What, p.Why, p.Fix, p.Docs
		} else {
			res.Detail = detail
			passed[c.Name] = true
		}
		r.Checks = append(r.Checks, res)
	}
	return r
}

// OK reports whether every check passed.
func (r Report) OK() bool {
	for _, c := range r.Checks {
		if c.Status != OK {
			return false
		}
	}
	return true
}

// WriteText writes one line per check, and for a failed check the lines
// of why, fix and docs. A control character in a text, such as from a
// path, becomes "?", so no text can move the cursor or change colors.
func (r Report) WriteText(w io.Writer) error {
	var b strings.Builder
	for _, c := range r.Checks {
		c.Detail, c.What = noControl(c.Detail), noControl(c.What)
		switch c.Status {
		case Fail:
			fmt.Fprintf(&b, "FAIL %s: %s\n", c.Name, c.What)
			fmt.Fprintf(&b, "     why: %s\n     fix: %s\n     see: %s\n", c.Why, c.Fix, c.Docs)
		default:
			line := fmt.Sprintf("%-4s %s", c.Status, c.Name)
			if c.Detail != "" {
				line += ": " + c.Detail
			}
			b.WriteString(line + "\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// noControl returns s with each control or format character, such as a
// change of the text direction, as "?".
func noControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return '?'
		}
		return r
	}, s)
}

// jsonReport is the JSON form: {"ok": BOOL, "checks": [RESULT...]}.
type jsonReport struct {
	OK     bool     `json:"ok"`
	Checks []Result `json:"checks"`
}

// WriteJSON writes the report as one JSON object and a line break.
func (r Report) WriteJSON(w io.Writer) error {
	checks := r.Checks
	if checks == nil {
		checks = []Result{}
	}
	data, err := json.Marshal(jsonReport{OK: r.OK(), Checks: checks})
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}
