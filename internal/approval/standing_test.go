package approval_test

// Tests of the request for a standing grant (DESIGN.md section 8). Times
// are relative to noon, the start of the fake clock.

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/grantkey"
)

// standEnv starts a core with [standing] on and standing = true on the
// secrets github-token and npm-token.
func standEnv(t *testing.T, edit ...func(*config.Broker)) *env {
	t.Helper()
	return newEnv(t, func(cfg *config.Broker) {
		cfg.Standing = config.DefaultStanding()
		cfg.Standing.MaxUses = 3
		for _, name := range []string{"github-token", "npm-token"} {
			s := cfg.Secrets[name]
			s.Rule.Standing = true
			cfg.Secrets[name] = s
		}
		for _, f := range edit {
			f(cfg)
		}
	})
}

func night() []approval.WindowSpec {
	return []approval.WindowSpec{{From: 3 * time.Hour, To: 5 * time.Hour}}
}

// standReq asks for a standing grant for 30 days from noon, with the hash
// of tok.
func standReq(client string, tok grantkey.Token, names ...string) *approval.Request {
	return &approval.Request{
		Client: client, Kind: audit.KindStanding, Secrets: names, Uses: 2, Windows: night(),
		NotBefore: noon, NotAfter: noon.Add(30 * 24 * time.Hour), TokenHash: grantkey.Hash(tok),
		Claim: approval.Claim{Reason: "job nightly-backup"},
	}
}

func newToken(t *testing.T) grantkey.Token {
	t.Helper()
	tok, err := grantkey.New()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestStandingGrantKeepsOnlyTheHash: an approved request makes a standing
// grant that holds the hash of the token, no old hashes, and the windows.
func TestStandingGrantKeepsOnlyTheHash(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := standEnv(t)
		defer e.stop()
		tok := newToken(t)
		res := e.grant(standReq("laptop", tok, "github-token"), 1)
		p := e.fake.Asked()[0].Prompt
		if p.Kind != audit.KindStanding || p.Uses != 2 || len(p.Windows) != 1 || p.Windows[0] != "daily 03:00-05:00" || !p.Once {
			t.Errorf("the prompt is %+v", p)
		}
		if res.Subject.Kind != audit.KindStanding || res.Subject.Uses != 2 || len(res.Subject.Windows) != 1 {
			t.Errorf("the subject is %+v", res.Subject)
		}
		hashes, old, ws, per := e.core.StandingGrants("laptop")
		if len(hashes) != 1 || hashes[0] != grantkey.Hash(tok) || old[0] != 0 || ws[0] != 1 || per[0] != 2 {
			t.Errorf("the grant: %d hashes, %v old, %v windows, %v per window", len(hashes), old, ws, per)
		}
	})
}

// TestStandingRefused: each check is a deny without a message.
func TestStandingRefused(t *testing.T) {
	tests := []struct {
		name string
		edit func(*approval.Request)
		cfg  func(*config.Broker)
	}{
		{"no [standing]", nil, func(c *config.Broker) { c.Standing = config.StandingLimits{} }},
		{"a rule without standing", func(r *approval.Request) { r.Secrets = []string{"db-password"} }, nil},
		{"a never rule", func(r *approval.Request) { r.Secrets = []string{"backup-token"}; r.Client = "ci" }, nil},
		{"a key", func(r *approval.Request) { r.Key, r.RemoteUser, r.Hosts = "web", "deploy", []string{"web-1"} }, nil},
		{"no windows", func(r *approval.Request) { r.Windows = nil }, nil},
		{"8 windows", func(r *approval.Request) {
			r.Windows = nil
			for range 8 {
				r.Windows = append(r.Windows, night()[0])
			}
		}, nil},
		{"no token hash", func(r *approval.Request) { r.TokenHash = [32]byte{} }, nil},
		{"over max_uses", func(r *approval.Request) { r.Uses = 4 }, nil},
		{"no uses", func(r *approval.Request) { r.Uses = 0 }, nil},
		{"over max_days", func(r *approval.Request) { r.NotAfter = noon.Add(91 * 24 * time.Hour) }, nil},
		{"no end", func(r *approval.Request) { r.NotAfter = time.Time{} }, nil},
		{"the end has passed", func(r *approval.Request) { r.NotBefore = noon.Add(-2 * time.Hour); r.NotAfter = noon.Add(-time.Hour) }, nil},
		{"the end is before the start", func(r *approval.Request) { r.NotBefore = noon.Add(40 * 24 * time.Hour) }, nil},
		{"part of a second", func(r *approval.Request) { r.NotAfter = r.NotAfter.Add(time.Millisecond) }, nil},
		{"a window over max_window", func(r *approval.Request) {
			r.Windows = []approval.WindowSpec{{From: time.Hour, To: 9*time.Hour + time.Minute}}
		}, nil},
		{"a window that is backwards", func(r *approval.Request) {
			r.Windows = []approval.WindowSpec{{From: 5 * time.Hour, To: 3 * time.Hour}}
		}, nil},
		{"a window past midnight", func(r *approval.Request) {
			r.Windows = []approval.WindowSpec{{From: 20 * time.Hour, To: 25 * time.Hour}}
		}, nil},
		{"a window with part of a minute", func(r *approval.Request) {
			r.Windows = []approval.WindowSpec{{From: time.Hour, To: 2*time.Hour + time.Second}}
		}, nil},
		{"windows that overlap", func(r *approval.Request) {
			r.Windows = []approval.WindowSpec{{From: 3 * time.Hour, To: 5 * time.Hour}, {From: 4 * time.Hour, To: 6 * time.Hour}}
		}, nil},
		{"a window twice", func(r *approval.Request) { r.Windows = append(night(), night()...) }, nil},
		{"a bad day", func(r *approval.Request) {
			r.Windows = []approval.WindowSpec{{Days: []time.Weekday{7}, From: time.Hour, To: 2 * time.Hour}}
		}, nil},
		{"a day twice", func(r *approval.Request) {
			r.Windows = []approval.WindowSpec{{Days: []time.Weekday{time.Monday, time.Monday}, From: time.Hour, To: 2 * time.Hour}}
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := standEnv(t, func(c *config.Broker) {
					if tt.cfg != nil {
						tt.cfg(c)
					}
				})
				defer e.stop()
				r := standReq("laptop", newToken(t), "github-token")
				if tt.edit != nil {
					tt.edit(r)
				}
				e.refuses(r, audit.CauseNotAllowed)
			})
		})
	}
}

// TestStandingMaxGrants: a client with max_grants live standing grants
// gets a deny with cause limit for the next, before any message.
func TestStandingMaxGrants(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := standEnv(t, func(c *config.Broker) { c.Standing.MaxGrants = 2 })
		defer e.stop()
		e.grant(standReq("laptop", newToken(t), "github-token"), 1)
		e.grant(standReq("laptop", newToken(t), "npm-token"), 2)
		e.refuses(standReq("laptop", newToken(t), "github-token"), audit.CauseLimit)
	})
}
