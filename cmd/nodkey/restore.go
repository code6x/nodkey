package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// restored is what the start found in the audit log about the grants from
// before (DESIGN.md section 8, "Grants after a restart").
type restored struct {
	open, dropped []approval.RestoredGrant
	// cause, if set, says why no grant from before is open again; err
	// says what went wrong, and how to fix it.
	cause audit.ResetCause
	err   error
}

// restoreGrants reads the open audit log at path, and opens the grants
// from before again in core. Call it after audit.Open, which records a
// torn last line, and before the core runs.
func restoreGrants(core *approval.Core, path string, now time.Time) restored {
	rl, cause, err := audit.ReadForRestore(path, now)
	if cause != "" {
		return restored{cause: cause, err: err}
	}
	open, dropped, err := core.Restore(rl.Records, rl.Head)
	if err != nil {
		return restored{cause: audit.ResetFormat, err: err}
	}
	return restored{open: open, dropped: dropped}
}

// endCauseOf is the cause of the grant_ended entry of a grant that the
// start dropped.
func endCauseOf(r approval.DropReason) audit.EndCause {
	switch r {
	case approval.DropEnded:
		return audit.EndEnded
	case approval.DropConfig, approval.DropClient:
		return audit.EndConfig
	}
	return audit.EndStopped
}

// write writes the entries of r, after broker_started: grants_reset when
// no grant was opened again, and a grant_ended entry for each dropped
// grant. An error stops the start: a grant must not stay open without its
// entries.
func (r restored) write(l *audit.Logger) error {
	if r.cause != "" {
		if _, err := l.Append(audit.GrantsReset{Cause: r.cause}); err != nil {
			return fmt.Errorf("cannot write the grants_reset entry: %w", err)
		}
		return nil
	}
	for _, d := range r.dropped {
		if _, err := l.Append(audit.GrantEnded{Subject: d.Subject, Cause: endCauseOf(d.Reason), UsesLeft: max(d.UsesLeft, 0)}); err != nil {
			return fmt.Errorf("cannot write the grant_ended entry of a grant from before: %w", err)
		}
	}
	return nil
}

// maxRestoreLines is the most grants that the notice after start lists.
const maxRestoreLines = 20

// notice returns the one message after start about the grants from before,
// or "" when there were none. It names grants by ID, client and secrets
// or key, never by claimed text.
func (r restored) notice() string {
	if r.cause != "" {
		return "The broker did not open any grant from before this start again: the audit log " +
			resetText(r.cause) + ". Each grant must be approved again. Check the log with " +
			"\"nodkey audit verify --anchors\"; the journal of the broker says more."
	}
	if len(r.open) == 0 && len(r.dropped) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "The broker started. %d grant(s) from before are open again, %d dropped.", len(r.open), len(r.dropped))
	n := 0
	line := func(g approval.RestoredGrant, state string) {
		if n++; n > maxRestoreLines {
			return
		}
		what := g.Subject.Key
		if len(g.Subject.Secrets) > 0 {
			what = strings.Join(g.Subject.Secrets, ", ")
		}
		fmt.Fprintf(&b, "\n%s: %s, %s, %s", g.Subject.GrantID, g.Subject.Client, what, state)
	}
	for _, g := range r.open {
		line(g, "open")
	}
	for _, g := range r.dropped {
		line(g, "dropped: "+dropText(g.Reason))
	}
	if n > maxRestoreLines {
		fmt.Fprintf(&b, "\n... and %d more", n-maxRestoreLines)
	}
	return b.String()
}

// resetText says what is wrong with the log, for a cause.
func resetText(c audit.ResetCause) string {
	switch c {
	case audit.ResetHead:
		return "does not match its head file (it was cut, replaced, or an older copy was put back)"
	case audit.ResetClock:
		return "has entries later than the clock of this host (set the clock right)"
	case audit.ResetFormat:
		return "has an entry that this version of nodkey cannot read"
	}
	return "does not verify"
}

// dropText says why a grant was dropped.
func dropText(r approval.DropReason) string {
	switch r {
	case approval.DropEnded:
		return "it ended while the broker was stopped"
	case approval.DropConfig:
		return "the config no longer allows it"
	case approval.DropClient:
		return "its client is gone from the config"
	}
	return "its last use is not proven by the audit log"
}
