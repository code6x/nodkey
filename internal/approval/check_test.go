package approval_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/claim"
)

// canary stands for text that the agent chose, such as a secret pasted
// into a name by mistake. It must not reach the audit subject.
const canary = "CANARY-made-up-name-7c2e"

// checkKeys are the host keys a check case uses: the hosts of the test
// config, and a host key that is not in known_hosts.
type checkKeys struct {
	hosts
	unknown ssh.PublicKey
}

type checkCase struct {
	name string
	req  func(k checkKeys) *approval.Request
	want func(k checkKeys) audit.Subject // without the RequestID
}

// TestChecksDeny checks that the core denies a request that fails a check,
// without a message, and that the audit subject keeps only what passed
// (DESIGN.md section 9).
func TestChecksDeny(t *testing.T) {
	login := func(client, key string, hk func(checkKeys) ssh.PublicKey, user string, change func(*approval.Request)) func(checkKeys) *approval.Request {
		return func(k checkKeys) *approval.Request {
			var hostKey ssh.PublicKey
			if hk != nil {
				hostKey = hk(k)
			}
			r := loginReq(client, key, hostKey, user)
			if change != nil {
				change(r)
			}
			return r
		}
	}
	secrets := func(client string, names []string, change func(*approval.Request)) func(checkKeys) *approval.Request {
		return func(checkKeys) *approval.Request {
			r := secretsReq(client, names...)
			if change != nil {
				change(r)
			}
			return r
		}
	}
	web1 := func(k checkKeys) ssh.PublicKey { return k.web1 }
	web2 := func(k checkKeys) ssh.PublicKey { return k.web2 }
	unknown := func(k checkKeys) ssh.PublicKey { return k.unknown }
	same := func(s audit.Subject) func(checkKeys) audit.Subject { return func(checkKeys) audit.Subject { return s } }
	// loginWant is the subject of a login by client: hk is the host key,
	// and the empty key, user or host is left out.
	loginWant := func(client, key, user, host string, hk func(checkKeys) ssh.PublicKey) func(checkKeys) audit.Subject {
		return func(k checkKeys) audit.Subject {
			c := loginReq("", "", nil, "").Claim
			s := audit.Subject{Client: client, Kind: audit.KindSSHLogin, Key: key, RemoteUser: user, Command: c.Command, Reason: c.Reason}
			if host != "" {
				s.Hosts = []string{host}
			}
			if hk != nil {
				s.HostKey = ssh.FingerprintSHA256(hk(k))
			}
			return s
		}
	}
	gh := []string{"github-token"}

	tests := []checkCase{
		{"no request", func(checkKeys) *approval.Request { return nil }, same(audit.Subject{})},
		{"unknown client", secrets("phone", gh, nil), same(withClient(secretsSubject("github-token"), "", nil))},
		{"no client", secrets("", gh, nil), same(withClient(secretsSubject("github-token"), "", nil))},
		{"unknown kind", secrets("laptop", gh, func(r *approval.Request) { r.Kind = "other" }),
			same(audit.Subject{Client: "laptop"})},
		{"no kind", secrets("laptop", gh, func(r *approval.Request) { r.Kind = "" }),
			same(audit.Subject{Client: "laptop"})},

		{"no secret", secrets("laptop", nil, nil), same(secretsSubject())},
		{"unknown secret", secrets("laptop", []string{"github-token", canary}, nil), same(secretsSubject("github-token"))},
		{"secret of another client", secrets("laptop", []string{"backup-token"}, nil), same(secretsSubject())},
		{"secrets with a key", secrets("laptop", gh, func(r *approval.Request) { r.Key = "deploy" }),
			same(secretsSubject("github-token"))},
		{"secrets with a host key", func(k checkKeys) *approval.Request {
			r := secretsReq("laptop", gh...)
			r.HostKey = k.web1
			return r
		}, same(secretsSubject("github-token"))},
		{"secrets with a remote user", secrets("laptop", gh, func(r *approval.Request) { r.RemoteUser = "deploy" }),
			same(secretsSubject("github-token"))},
		{"secrets with hosts", secrets("laptop", gh, func(r *approval.Request) { r.Hosts = []string{"web-1"} }),
			same(secretsSubject("github-token"))},
		{"secrets with a time", secrets("laptop", gh, func(r *approval.Request) { r.For = time.Minute }),
			same(secretsSubject("github-token"))},

		{"unknown key", login("laptop", canary, web1, "deploy", nil), loginWant("laptop", "", "deploy", "", web1)},
		{"key of another client", login("build", "admin", web1, "deploy", nil), loginWant("build", "", "deploy", "", web1)},
		{"no host key", login("laptop", "deploy", nil, "deploy", nil), loginWant("laptop", "deploy", "deploy", "", nil)},
		{"unknown host key", login("laptop", "deploy", unknown, "deploy", nil),
			loginWant("laptop", "deploy", "deploy", "", unknown)},
		{"host not in the key's hosts", login("laptop", "admin", web2, "deploy", nil),
			loginWant("laptop", "admin", "deploy", "", web2)},
		{"no remote user", login("laptop", "deploy", web1, "", nil), loginWant("laptop", "deploy", "", "web-1", web1)},
		{"login with secrets", login("laptop", "deploy", web1, "deploy", func(r *approval.Request) { r.Secrets = gh }),
			loginWant("laptop", "deploy", "deploy", "web-1", web1)},
		{"login with hosts", login("laptop", "deploy", web1, "deploy", func(r *approval.Request) { r.Hosts = []string{"web-1"} }),
			loginWant("laptop", "deploy", "deploy", "web-1", web1)},
		{"login with a time", login("laptop", "deploy", web1, "deploy", func(r *approval.Request) { r.For = time.Minute }),
			loginWant("laptop", "deploy", "deploy", "web-1", web1)},
	}
	// Remote user names that break the rule of DESIGN.md section 6.
	for _, user := range []string{"-deploy", "root;", "de ploy", "d\u00ebploy", strings.Repeat("a", 33), "deploy\n", canary + "/x"} {
		tests = append(tests, checkCase{"remote user " + user, login("laptop", "deploy", web1, user, nil),
			loginWant("laptop", "deploy", "", "web-1", web1)})
	}
	// Claimed text that the caller did not make clean. The subject leaves
	// out the claimed command and reason.
	for name, text := range map[string]string{
		"a newline":            "line one\nline two",
		"a direction mark":     "deploy \u202e1-bew",
		"a tab":                "a\tb",
		"a space at the start": " reason",
		"two spaces":           "a  b",
		"a mark at the start":  "\u0301reason",
		"too long":             strings.Repeat("a", claim.MaxInput+1),
	} {
		for _, field := range []string{"vars", "command", "dir", "reason"} {
			tests = append(tests, checkCase{"claimed " + field + " with " + name,
				secrets("laptop", gh, func(r *approval.Request) {
					switch field {
					case "vars":
						r.Claim.Vars = text
					case "command":
						r.Claim.Command = text
					case "dir":
						r.Claim.Dir = text
					case "reason":
						r.Claim.Reason = text
					}
				}),
				same(audit.Subject{Client: "laptop", Kind: audit.KindSecrets, Secrets: gh})})
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := newEnv(t, nil)
				defer e.stop()
				k := checkKeys{hosts: e.hosts, unknown: newEd25519Key(t)}
				onWait := false
				req := tt.req(k)
				if req != nil {
					req.OnWait = func(string) { onWait = true }
				}
				r := e.now(req)
				checkDenied(t, r, audit.CauseNotAllowed)
				checkEvents(t, r, "request", "denied:not_allowed")
				e.asked(0)
				if onWait {
					t.Error("OnWait was called for a request that was denied at once")
				}
				if len(r.RequestID) != 22 || r.Subject.RequestID != r.RequestID {
					t.Errorf("request ID %q, in the subject %q; want the same 22 characters", r.RequestID, r.Subject.RequestID)
				}
				got := r.Subject
				got.RequestID = ""
				if want := tt.want(k); !reflect.DeepEqual(got, want) {
					t.Errorf("subject\n%+v\nwant\n%+v", got, want)
				}
				data, err := json.Marshal(r.Events())
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), canary) {
					t.Error("the audit entries hold text from the agent that failed a check")
				}
			})
		})
	}
}

// TestChecksPass checks requests that pass every check, with what the
// message and the subject show.
func TestChecksPass(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, nil)
		defer e.stop()

		// One secret for two variables counts once.
		req := secretsReq("laptop", "github-token", "npm-token", "github-token")
		var code string
		req.OnWait = func(c string) { code = c }
		ch := e.decide(req)
		mustWait(t, ch)
		p := e.asked(1)[0].Prompt
		if code == "" || code != p.ShortCode {
			t.Errorf("OnWait got %q, the message shows %q; want the same short code", code, p.ShortCode)
		}
		if !reflect.DeepEqual(p.Secrets, []string{"github-token", "npm-token"}) || p.Client != "laptop" ||
			p.Kind != audit.KindSecrets || p.Claim != req.Claim || p.Key != "" || len(p.Hosts) != 0 {
			t.Errorf("prompt %+v; want the two secrets of laptop and the claim", p)
		}
		if p.TimeLeft != secretsTimeout || !p.Expires.Equal(noon.Add(secretsTimeout)) {
			t.Errorf("expires %v, time left %v; want %v and %v", p.Expires, p.TimeLeft, noon.Add(secretsTimeout), secretsTimeout)
		}
		e.tap(1, audit.AnswerApproveOnce)
		r := mustResult(t, ch)
		checkAllowed(t, r)
		want := secretsSubject("github-token", "npm-token")
		want.RequestID = r.RequestID
		if !reflect.DeepEqual(r.Subject, want) || r.ShortCode != code {
			t.Errorf("subject %+v, short code %q; want %+v and %q", r.Subject, r.ShortCode, want, code)
		}

		// An SSH login shows the host from known_hosts and its host key.
		ch = e.decide(loginReq("laptop", "deploy", e.hosts.web1ecdsa, "deploy"))
		mustWait(t, ch)
		p = e.asked(2)[1].Prompt
		if p.Kind != audit.KindSSHLogin || p.Key != "deploy" || !reflect.DeepEqual(p.Hosts, []string{"web-1"}) ||
			p.HostKey != ssh.FingerprintSHA256(e.hosts.web1ecdsa) || p.RemoteUser != "deploy" || len(p.Secrets) != 0 {
			t.Errorf("prompt %+v; want deploy@web-1 with its ECDSA host key", p)
		}
		if p.TimeLeft != sshTimeout {
			t.Errorf("an SSH login has %v, want %v", p.TimeLeft, sshTimeout)
		}
		e.tap(2, audit.AnswerDeny)
		mustResult(t, ch)
	})
}

func secretsSubject(names ...string) audit.Subject {
	c := secretsReq("laptop").Claim
	return audit.Subject{Client: "laptop", Kind: audit.KindSecrets, Secrets: names, Command: c.Command, Reason: c.Reason}
}

// withClient returns s with another client, and other secrets.
func withClient(s audit.Subject, client string, secrets []string) audit.Subject {
	s.Client = client
	s.Secrets = secrets
	return s
}
