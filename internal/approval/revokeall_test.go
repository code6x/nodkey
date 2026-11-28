package approval_test

// Tests of Core.RevokeAll, the emergency stop of nodkey revoke --all and
// of the "Revoke all" button (DESIGN.md section 8).

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// TestRevokeAllEndsEveryGrant: a window grant, a scheduled grant and a
// standing grant all end. The scheduled and the standing grant get one
// grant_ended entry each with cause revoked, and their messages lose the
// Revoke button. Each later request needs a tap again.
func TestRevokeAllEndsEveryGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t, func(cfg *config.Broker) {
			cfg.Standing = config.DefaultStanding()
			cfg.Standing.MaxUses = 3
			s := cfg.Secrets["npm-token"]
			s.Rule.Standing = true
			cfg.Secrets["npm-token"] = s
		})
		defer e.stop()
		var rec endedRecorder
		e.core.OnGrantEnded(rec.add)
		e.approveWindow(secretsReq("laptop", "npm-token"), 1)
		pre := e.grant(preSecrets("laptop", 3, 0, time.Hour, "db-password"), 2)
		tok := newToken(t)
		std := e.grant(standReq("laptop", tok, "npm-token"), 3)

		if n := e.core.RevokeAll(); n != 3 {
			t.Fatalf("RevokeAll ended %d grants, want 3", n)
		}
		synctest.Wait()
		got := rec.all()
		if len(got) != 2 {
			t.Fatalf("ended entries %+v, want 2", got)
		}
		ids := map[string]bool{}
		for _, ev := range got {
			if ev.Cause != audit.EndRevoked {
				t.Errorf("entry %+v, want cause revoked", ev)
			}
			ids[ev.GrantID] = true
		}
		if !ids[pre.GrantID] || !ids[std.GrantID] {
			t.Errorf("ended entries %+v, want the grants %s and %s", got, pre.GrantID, std.GrantID)
		}
		for _, n := range []int{2, 3} {
			ups := e.updates(n)
			if end := ups[len(ups)-1].Ending; end.Revoke || end.GrantEnd != audit.EndRevoked {
				t.Errorf("last update of message %d %+v; want the end by revoke, no button", n, end)
			}
		}
		if hashes, _, _, _ := e.core.StandingGrants("laptop"); len(hashes) != 0 {
			t.Errorf("standing grants after RevokeAll: %d, want 0", len(hashes))
		}
		e.needsTap(secretsReq("laptop", "npm-token"), 4)
		e.needsMessage(secretsReq("laptop", "db-password"), 5)
		// A second RevokeAll finds nothing.
		if n := e.core.RevokeAll(); n != 0 {
			t.Errorf("a second RevokeAll ended %d grants, want 0", n)
		}
	})
}

// TestRevokeAllWithNoGrant: with no grant it ends nothing and writes no
// entry; a request is still asked for as before.
func TestRevokeAllWithNoGrant(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		var rec endedRecorder
		e.core.OnGrantEnded(rec.add)
		if n := e.core.RevokeAll(); n != 0 {
			t.Fatalf("RevokeAll ended %d grants, want 0", n)
		}
		synctest.Wait()
		if got := rec.all(); len(got) != 0 {
			t.Fatalf("ended entries %+v, want none", got)
		}
		e.needsTap(secretsReq("laptop", "github-token"), 1)
	})
}
