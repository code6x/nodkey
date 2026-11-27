package approval_test

// Tests of Restore (DESIGN.md section 8, "Grants after a restart").

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// recordLog collects the entries of a broker, in order, as the records
// that audit.ReadRecords returns.
type recordLog struct {
	clock interface{ Wall() time.Time }
	recs  []audit.Record
}

func (l *recordLog) add(evs ...audit.Event) uint64 {
	for _, ev := range evs {
		l.recs = append(l.recs, audit.Record{Seq: uint64(len(l.recs) + 1), Time: l.clock.Wall(), Event: ev})
	}
	return uint64(len(l.recs))
}

// seqOf returns the seq of the first record of the event name.
func (l *recordLog) seqOf(t *testing.T, match func(audit.Event) bool) uint64 {
	t.Helper()
	for _, r := range l.recs {
		if match(r.Event) {
			return r.Seq
		}
	}
	t.Fatal("no such record")
	return 0
}

func isDecision(ev audit.Event) bool { _, ok := ev.(audit.Decision); return ok }

// restoreEnv runs a broker that makes a scheduled grant for 3 uses of
// github-token, from noon to two hours later, and uses it once. A second
// use has its grant_used but no secret_sent: the broker stopped before it
// sent the secret. It returns the log and the grant ID.
func restoreEnv(t *testing.T) (*recordLog, string) {
	t.Helper()
	e := preEnv(t)
	defer e.stop()
	log := &recordLog{clock: e.clock}
	res := e.grant(preSecrets("laptop", 3, 0, 2*time.Hour, "github-token"), 1)
	log.add(res.Events()...)
	u := e.uses(secretsReq("laptop", "github-token"), res.GrantID)
	log.add(u.Events()...)
	log.add(audit.SecretSent{Subject: u.Subject})
	u = e.uses(secretsReq("laptop", "github-token"), res.GrantID)
	log.add(u.Events()...)
	log.add(audit.BrokerStopped{})
	return log, res.GrantID
}

// TestRestoreScheduled: after a restart the grant has the same end and
// the same uses left. A use without its secret_sent does not count.
func TestRestoreScheduled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log, id := restoreEnv(t)
		e := preEnv(t)
		defer e.stop()
		e.clock.Advance(time.Hour)
		open, dropped, err := e.core.Restore(log.recs, log.seqOf(t, isDecision))
		if err != nil || len(open) != 1 || len(dropped) != 0 || open[0].UsesLeft != 2 || open[0].Subject.GrantID != id {
			t.Fatalf("Restore = %+v, %+v, %v; want one grant with 2 uses left", open, dropped, err)
		}
		e.uses(secretsReq("laptop", "github-token"), id)
		e.uses(secretsReq("laptop", "github-token"), id)
		ch := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch) // no use is left: the person is asked
		if _, _, err := e.core.Restore(log.recs, log.seqOf(t, isDecision)); err == nil {
			t.Error("a second Restore: no error")
		}
	})
}

// TestRestoreScheduledEnd: the grant ends at its end, as before.
func TestRestoreScheduledEnd(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log, _ := restoreEnv(t)
		e := preEnv(t)
		defer e.stop()
		e.clock.Advance(2*time.Hour - time.Second)
		if open, _, _ := e.core.Restore(log.recs, log.seqOf(t, isDecision)); len(open) != 1 {
			t.Fatalf("Restore opened %d grants, want 1", len(open))
		}
		e.clock.Advance(time.Second)
		ch := e.decide(secretsReq("laptop", "github-token"))
		mustWait(t, ch) // the end has come: the person is asked
	})
}

// TestRestoreScheduledDrops: the grants that Restore does not open, and
// why.
func TestRestoreScheduledDrops(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance time.Duration
		edit    func(*config.Broker)
		change  func(*recordLog, string) uint64 // returns the head; 0 means the decision
		reason  approval.DropReason             // "" means neither open nor dropped
	}{
		{name: "end passed", advance: 2 * time.Hour, reason: approval.DropEnded},
		{name: "client gone", edit: func(c *config.Broker) { delete(c.Clients, "laptop") }, reason: approval.DropClient},
		{name: "secret gone", edit: func(c *config.Broker) { delete(c.Secrets, "github-token") }, reason: approval.DropConfig},
		{name: "rule no longer allows it", edit: func(c *config.Broker) {
			s := c.Secrets["github-token"]
			s.Rule.Preapprove = false
			c.Secrets["github-token"] = s
		}, reason: approval.DropConfig},
		{name: "ended", change: func(l *recordLog, id string) uint64 {
			l.add(audit.GrantEnded{Subject: audit.Subject{RequestID: l.recs[0].Event.(audit.Request).RequestID, GrantID: id,
				Client: "laptop", Kind: audit.KindPreapprove}, Cause: audit.EndRevoked})
			return 0
		}},
		{name: "the tap made no grant", change: func(l *recordLog, _ string) uint64 {
			for _, r := range l.recs {
				if d, ok := r.Event.(audit.Decision); ok {
					l.add(audit.Denied{Subject: d.Subject, Cause: audit.CauseLimit})
					break
				}
			}
			return 0
		}},
		{name: "after the head", change: func(*recordLog, string) uint64 { return 1 }},
		{name: "before a grants_reset", change: func(l *recordLog, _ string) uint64 {
			l.add(audit.GrantsReset{Cause: audit.ResetChain})
			return 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				log, id := restoreEnv(t)
				head := log.seqOf(t, isDecision)
				if tc.change != nil {
					if h := tc.change(log, id); h != 0 {
						head = h
					}
				}
				e := preEnv(t, func(c *config.Broker) {
					if tc.edit != nil {
						tc.edit(c)
					}
				})
				defer e.stop()
				e.clock.Advance(tc.advance)
				open, dropped, err := e.core.Restore(log.recs, head)
				if err != nil || len(open) != 0 {
					t.Fatalf("Restore = %+v, %v; want no open grant", open, err)
				}
				switch {
				case tc.reason == "" && len(dropped) != 0:
					t.Errorf("dropped %+v, want none", dropped)
				case tc.reason != "" && (len(dropped) != 1 || dropped[0].Reason != tc.reason || dropped[0].Subject.GrantID != id):
					t.Errorf("dropped %+v, want the grant with reason %s", dropped, tc.reason)
				}
				ch := e.decide(secretsReq("laptop", "github-token"))
				if tc.name == "client gone" || tc.name == "secret gone" {
					checkDenied(t, mustResult(t, ch), audit.CauseNotAllowed)
					return
				}
				mustWait(t, ch) // no grant: the person is asked
			})
		})
	}
}
