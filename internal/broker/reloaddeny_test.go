package broker

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// TestLoginReloadDenyOneEntry: a reload during the fetch after the tap
// denies a login and a login pre-approval with exactly one denied entry
// (#220). Before, a reload that took the pin away wrote two: one by the
// reload check, and one by the caller. A reload that changes only the
// rule or the clients of the item is still denied by the caller, with one
// entry.
func TestLoginReloadDenyOneEntry(t *testing.T) {
	// takePin gives the client laptop another pin.
	takePin := func(t *testing.T, l *loginTest) {
		next := *l.svc.view().cfg
		next.Clients = maps.Clone(next.Clients)
		c := next.Clients["laptop"]
		c.Pin[0] ^= 0xff // another key
		next.Clients["laptop"] = c
		if _, err := l.svc.Reload(&next, l.svc.view().keys, strings.Repeat("a", 64)); err != nil {
			t.Error(err)
		}
	}
	// changeRule makes the rule of the section web stricter.
	changeRule := func(t *testing.T, l *loginTest) {
		next := *l.svc.view().cfg
		next.Logins = maps.Clone(next.Logins)
		w := next.Logins["web"]
		w.Rule.Window = 4 * time.Hour
		w.Rule.Ask = config.AskWindow
		next.Logins["web"] = w
		if _, err := l.svc.Reload(&next, l.svc.view().keys, strings.Repeat("a", 64)); err != nil {
			t.Error(err)
		}
	}
	// addClient lets one more client ask for the logins of web. The rule
	// stays the same, so only the check of the clients in
	// stillAllowedLogin sees the change.
	addClient := func(t *testing.T, l *loginTest) {
		next := *l.svc.view().cfg
		next.Logins = maps.Clone(next.Logins)
		w := next.Logins["web"]
		w.Clients = append(slices.Clone(w.Clients), "ci")
		next.Logins["web"] = w
		if _, err := l.svc.Reload(&next, l.svc.view().keys, strings.Repeat("a", 64)); err != nil {
			t.Error(err)
		}
	}
	login := func(l *loginTest) *result {
		return l.approveLogin(itemShop, pageShop, audit.AnswerApproveOnce)
	}
	pre := func(l *loginTest) *result {
		p := l.start(l.laptp, api.PathPreapprove, api.PreapproveRequest{Login: itemShop, URL: pageShop, Uses: 1})
		pr := l.waitAsked(1)[0].Prompt
		l.tap(pr.RequestID, audit.AnswerApproveOnce)
		return p.wait(t)
	}
	cases := []struct {
		name   string
		reload func(*testing.T, *loginTest)
		ask    func(*loginTest) *result
	}{
		{"login: the pin is taken away", takePin, login},
		{"pre-approval: the pin is taken away", takePin, pre},
		{"login: the rule changed", changeRule, login},
		{"pre-approval: the rule changed", changeRule, pre},
		{"login: the clients changed", addClient, login},
		{"pre-approval: the clients changed", addClient, pre},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newLoginEnv(t, nil)
			l.vs.lmu.Lock()
			l.vs.onFetch = func(n int) {
				if n == 2 { // the fetch after the tap
					c.reload(t, l)
				}
			}
			l.vs.lmu.Unlock()
			mustStatus(t, c.ask(l), http.StatusForbidden)
			// The caller wrote its entry after the answer: wait until
			// the broker is done with the request.
			l.svc.waitIdle(t, "laptop")
			events := l.audit.all()
			got := requestEvents(events, lastRequestID(t, events))
			mustEvents(t, got, "request decision:approve_once denied:not_allowed")
			if n := l.svc.rememberedCount(); n != 0 {
				t.Errorf("the broker keeps %d logins", n)
			}
			l.noGrant()
			l.vs.checkCleared(t)
		})
	}
}
