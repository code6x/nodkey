package approval_test

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestListStanding: a live standing grant is listed with its windows,
// "never" before a use, the time of the use after it, and the end. A grant
// that ended is not listed.
func TestListStanding(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := standEnv(t)
		defer e.stop()
		if l := e.core.ListStanding(); len(l) != 0 {
			t.Fatalf("%d grants before any was made", len(l))
		}
		tok := newToken(t)
		e.grant(standReq("laptop", tok, "github-token", "npm-token"), 1)
		l := e.core.ListStanding()
		if len(l) != 1 {
			t.Fatalf("%d grants, want 1", len(l))
		}
		g := l[0]
		if g.Client != "laptop" || len(g.Secrets) != 2 || len(g.Windows) != 1 || g.Windows[0] != "daily 03:00-05:00" ||
			!g.LastUse.IsZero() || !g.End.Equal(noon.Add(30*24*time.Hour)) {
			t.Errorf("the entry is %+v", g)
		}
		e.pass(15*time.Hour + time.Minute) // 03:01 on 2026-10-15
		e.useGrant(tok)
		l = e.core.ListStanding()
		if len(l) != 1 || !l[0].LastUse.Equal(noon.Add(15*time.Hour+time.Minute)) {
			t.Errorf("after a use: %+v", l)
		}
		e.pass(31 * 24 * time.Hour)
		if l := e.core.ListStanding(); len(l) != 0 {
			t.Errorf("an ended grant is listed: %+v", l)
		}
	})
}
