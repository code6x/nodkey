package approval_test

import (
	"maps"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// copyConfig returns a copy of cfg whose maps can change without changing
// cfg, as a reload loads a new config.
func copyConfig(cfg *config.Broker) *config.Broker {
	next := *cfg
	next.Clients = maps.Clone(cfg.Clients)
	next.Secrets = maps.Clone(cfg.Secrets)
	next.Keys = maps.Clone(cfg.Keys)
	return &next
}

// sameKeys says that every key file holds the key it held before.
func sameKeys(string) bool { return true }

// TestReloadKeepsMatchingGrants: a reload keeps a scheduled grant that the
// new config allows in the same way, with the same uses left and the same
// end, also when another client is added to its secret. A grant for a
// secret that the new config removed ends at once, with cause
// config_changed and its uses left.
func TestReloadKeepsMatchingGrants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		var rec endedRecorder
		e.core.OnGrantEnded(rec.add)
		a := e.grant(preSecrets("laptop", 5, 0, time.Hour, "github-token"), 1)
		b := e.grant(preSecrets("laptop", 2, 0, time.Hour, "npm-token"), 2)
		req := secretsReq("laptop", "github-token")
		e.uses(req, a.GrantID)

		next := copyConfig(e.cfg)
		delete(next.Secrets, "npm-token")
		s := next.Secrets["github-token"]
		s.Clients = append(s.Clients[:len(s.Clients):len(s.Clients)], "ci")
		next.Secrets["github-token"] = s
		if n := e.core.Reload(next, sameKeys); n != 1 {
			t.Fatalf("Reload ended %d grants, want 1", n)
		}
		synctest.Wait()
		got := rec.all()
		if len(got) != 1 || got[0].GrantID != b.GrantID || got[0].Cause != audit.EndConfig || got[0].UsesLeft != 2 {
			t.Fatalf("ended %+v; want the npm-token grant, with cause config_changed and 2 uses left", got)
		}
		// The same uses left: 4 of 5.
		for range 4 {
			e.uses(req, a.GrantID)
		}
		e.needsMessage(req, 3)
		// The same end: a new grant ends at the old time.
		c := e.grant(preSecrets("laptop", 5, 0, time.Hour, "github-token"), 4)
		e.clock.Advance(time.Hour - time.Nanosecond)
		e.uses(req, c.GrantID)
		e.clock.Advance(time.Nanosecond)
		e.needsMessage(req, 5)
	})
}

// TestReloadEndsChangedGrants: a reload ends each grant whose client has a
// new pin, whose secret has another store item or rule, or whose key may
// no longer log in to the host of the grant. Each such request needs a
// message again. A grant that still matches stays.
func TestReloadEndsChangedGrants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		h := e.hosts
		e.approveWindow(secretsReq("laptop", "github-token"), 1)
		e.approveWindow(secretsReq("build", "github-token"), 2)
		e.approveWindow(secretsReq("laptop", "npm-token"), 3)
		e.approveWindow(loginReq("laptop", "web", h.web1, "deploy"), 4)
		e.approveWindow(loginReq("laptop", "web", h.web2, "deploy"), 5)

		next := copyConfig(e.cfg)
		next.Clients["build"] = config.Client{Name: "build", Pin: config.Pin{1}} // a new pin
		s := next.Secrets["npm-token"]
		s.ID = "other-item"
		next.Secrets["npm-token"] = s
		k := next.Keys["web"]
		k.Hosts = []string{"web-1"}
		next.Keys["web"] = k
		if n := e.core.Reload(next, sameKeys); n != 3 {
			t.Fatalf("Reload ended %d grants, want 3", n)
		}
		checkAllowed(t, e.now(secretsReq("laptop", "github-token")))
		checkAllowed(t, e.now(loginReq("laptop", "web", h.web1, "deploy")))
		e.needsTap(secretsReq("build", "github-token"), 6)
		e.needsTap(secretsReq("laptop", "npm-token"), 7)
		// web-2 is no longer a host of the key: the core refuses it.
		checkDenied(t, e.now(loginReq("laptop", "web", h.web2, "deploy")), audit.CauseNotAllowed)
	})
}

// TestReloadEndsGrantsOfChangedKeyFile: a key file that holds another key
// after a reload ends the grants of its key.
func TestReloadEndsGrantsOfChangedKeyFile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		h := e.hosts
		e.approveWindow(loginReq("laptop", "deploy", h.web1, "deploy"), 1)
		e.approveWindow(loginReq("laptop", "web", h.web1, "deploy"), 2)
		n := e.core.Reload(copyConfig(e.cfg), func(name string) bool { return name != "deploy" })
		if n != 1 {
			t.Fatalf("Reload ended %d grants, want 1", n)
		}
		checkAllowed(t, e.now(loginReq("laptop", "web", h.web1, "deploy")))
		e.needsTap(loginReq("laptop", "deploy", h.web1, "deploy"), 3)
	})
}

// TestReloadRemovedClient: a client that the new config does not have
// loses its grants and is refused at once.
func TestReloadRemovedClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		e.approveWindow(secretsReq("build", "github-token"), 1)
		next := copyConfig(e.cfg)
		delete(next.Clients, "build")
		s := next.Secrets["github-token"]
		s.Clients = []string{"laptop"}
		next.Secrets["github-token"] = s
		if n := e.core.Reload(next, sameKeys); n != 1 {
			t.Fatalf("Reload ended %d grants, want 1", n)
		}
		e.refuses(secretsReq("build", "github-token"), audit.CauseNotAllowed)
	})
}

// TestReloadDuringWait: a request that waits for a tap during a reload is
// still decided, but its "Approve N min" starts no grant: the core checked
// it with the old config.
func TestReloadDuringWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()
		ch := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch)
		e.asked(1)
		e.core.Reload(copyConfig(e.cfg), sameKeys)
		e.tap(1, audit.AnswerApproveWindow)
		res := mustResult(t, ch)
		checkAllowed(t, res)
		res.StartGrants()
		if !res.SkippedByReload() {
			t.Error("SkippedByReload is false")
		}
		e.needsTap(secretsReq("laptop", "github-token"), 2)
	})
}

// TestReloadDuringWaitPreapprove: a scheduled grant approved after a
// reload does not start.
func TestReloadDuringWaitPreapprove(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := preEnv(t)
		defer e.stop()
		ch := e.decide(preSecrets("laptop", 2, 0, time.Hour, "github-token"))
		mustWait(t, ch)
		e.asked(1)
		e.core.Reload(copyConfig(e.cfg), sameKeys)
		e.tap(1, audit.AnswerApproveOnce)
		res := mustResult(t, ch)
		checkAllowed(t, res)
		res.StartGrants()
		if res.GrantStarted() {
			t.Fatal("a grant approved after a reload started")
		}
	})
}
