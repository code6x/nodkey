package approval

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"
)

// GrantInfo is one live standing grant, as the list of DESIGN.md section 8
// shows it. It holds no token and no hash.
type GrantInfo struct {
	Client  string
	Secrets []string
	// Windows are the windows as text, such as "daily 03:00-05:00".
	Windows []string
	// LastUse is the wall time of the last use, or the zero time for a
	// grant that was never used.
	LastUse time.Time
	// End is the wall time at which the grant ends.
	End time.Time
}

// ListStanding returns the live standing grants, ordered by client and
// then by end. A grant that has not started yet is live.
func (c *Core) ListStanding() []GrantInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	var out []GrantInfo
	for _, g := range c.grants {
		if !g.standing() || !now.before(g.end) {
			continue
		}
		gi := GrantInfo{Client: g.client, LastUse: g.lastUse, End: g.end.wall}
		for _, r := range g.refs {
			gi.Secrets = append(gi.Secrets, r.name)
		}
		for _, w := range g.windows {
			gi.Windows = append(gi.Windows, windowText(w))
		}
		out = append(out, gi)
	}
	slices.SortFunc(out, func(a, b GrantInfo) int {
		return cmp.Or(strings.Compare(a.Client, b.Client), a.End.Compare(b.End),
			strings.Compare(strings.Join(a.Secrets, ","), strings.Join(b.Secrets, ",")))
	})
	return out
}

// GrantLister is an Approver that can answer the bot command /grants. The
// core gives it the function that lists the standing grants before it
// calls Run.
type GrantLister interface {
	SetGrantSource(f func() []GrantInfo)
}

// Summarizer is an Approver that can send the weekly summary of the
// standing grants (DESIGN.md section 8).
type Summarizer interface {
	Summary(ctx context.Context, grants []GrantInfo) error
}
