package approval

import (
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/config"
)

// remoteUserPattern is the rule for remote user names (DESIGN.md section
// 6). The broker checks it first; the core checks it again, because the
// name is a verified line in the message and part of a grant's scope.
var remoteUserPattern = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$`)

// check checks r against the config and fills p: the items with their
// rules, the buttons, and the audit subject. It reports whether every
// check passed. The subject gets only the names that passed, and only
// claimed text that is one clean line (DESIGN.md section 9).
//
// It denies, among others:
//
//   - a client, secret, key or host that is not in the config, and a
//     secret or key that the client may not use;
//   - a rule whose ask is not "always", "window" or "never", also the
//     empty value; a "window" rule whose window is not from
//     config.MinWindow to config.MaxWindow; a "never" rule that does not
//     name exactly one client; a "never" rule for a key that has no hosts;
//   - fields of another kind of request, such as a host key in a secrets
//     request.
func (c *Core) check(r *Request, p *pending) bool {
	ok := true
	if _, known := c.cfg.Clients[r.Client]; known {
		p.client = r.Client
		p.subject.Client = r.Client
	} else {
		ok = false
	}
	switch r.Kind {
	case audit.KindSecrets, audit.KindSSHLogin, audit.KindSSHGrant:
		p.kind = r.Kind
		p.subject.Kind = r.Kind
	default:
		return false
	}
	ok = c.checkClaim(r.Claim, p) && ok
	switch r.Kind {
	case audit.KindSecrets:
		ok = c.checkSecrets(r, p) && ok
	case audit.KindSSHLogin:
		ok = c.checkLogin(r, p) && ok
	case audit.KindSSHGrant:
		ok = c.checkGrant(r, p) && ok
	}
	return ok
}

// checkClaim checks that each claimed field is one clean line, as
// claim.Line makes it. The claimed text goes into the message and the
// audit log; a newline or a direction mark there could fake the look of
// the message (THREAT-MODEL.md T3).
func (c *Core) checkClaim(cl Claim, p *pending) bool {
	ok := true
	for _, f := range []string{cl.Vars, cl.Command, cl.Dir, cl.Reason} {
		ok = isClean(f) && ok
	}
	if !ok {
		return false
	}
	p.claim = cl
	p.subject.Command = cl.Command
	p.subject.Reason = cl.Reason
	return true
}

// isClean reports whether claim.Line leaves s as it is: one line, with no
// control or invisible characters, at most claim.MaxInput bytes.
func isClean(s string) bool {
	return len(s) <= claim.MaxInput && claim.Line(s, utf8.RuneCountInString(s)+1) == s
}

func (c *Core) checkSecrets(r *Request, p *pending) bool {
	ok := r.Key == "" && r.HostKey == nil && r.RemoteUser == "" && len(r.Hosts) == 0 && r.For == 0
	if len(r.Secrets) == 0 {
		ok = false
	}
	seen := make(map[string]bool)
	for _, name := range r.Secrets {
		if seen[name] {
			continue // two variables for one secret
		}
		seen[name] = true
		s, known := c.cfg.Secrets[name]
		if !known || p.client == "" || !slices.Contains(s.Clients, p.client) {
			ok = false
			continue
		}
		if !validRule(s.Rule, s.Clients) {
			ok = false
			continue
		}
		p.items = append(p.items, item{ref: ref{name: name}, rule: s.Rule})
		p.subject.Secrets = append(p.subject.Secrets, name)
	}
	if !ok {
		return false
	}
	p.once = true
	p.windowMinutes = windowMinutes(p.items)
	return true
}

func (c *Core) checkLogin(r *Request, p *pending) bool {
	ok := len(r.Secrets) == 0 && len(r.Hosts) == 0 && r.For == 0
	k, keyOK := c.checkKey(r.Key, p)
	ok = keyOK && ok
	if keyOK && k.Rule.Ask == config.AskNever && len(k.Hosts) == 0 {
		ok = false // a "never" key rule must list its hosts
	}
	ok = c.checkUser(r.RemoteUser, p) && ok
	if r.HostKey == nil {
		return false
	}
	p.hostKey = string(r.HostKey.Marshal())
	p.subject.HostKey = ssh.FingerprintSHA256(r.HostKey)
	host, known := c.cfg.KnownHosts.NameFor(r.HostKey)
	if !known || !keyOK || (len(k.Hosts) > 0 && !slices.Contains(k.Hosts, host)) {
		return false
	}
	p.subject.Hosts = []string{host}
	if !ok {
		return false
	}
	p.once = true
	p.windowMinutes = windowMinutes(p.items)
	return true
}

func (c *Core) checkGrant(r *Request, p *pending) bool {
	ok := len(r.Secrets) == 0 && r.HostKey == nil
	k, keyOK := c.checkKey(r.Key, p)
	// An SSH grant is an "Approve N min" for many hosts at once, so the
	// key must have the "window" rule (DESIGN.md section 13).
	if keyOK && k.Rule.Ask != config.AskWindow {
		keyOK = false
	}
	ok = keyOK && ok
	ok = c.checkUser(r.RemoteUser, p) && ok

	var hosts []string
	seen := make(map[string]bool)
	for _, h := range r.Hosts {
		if seen[h] {
			continue
		}
		seen[h] = true
		if hosts = append(hosts, h); len(hosts) > MaxGrantHosts {
			break
		}
	}
	if len(hosts) == 0 || len(hosts) > MaxGrantHosts {
		return false // the hosts are left out of the subject
	}
	for _, h := range hosts {
		keys := c.cfg.KnownHosts.KeysFor(h)
		if len(keys) == 0 || !keyOK || (len(k.Hosts) > 0 && !slices.Contains(k.Hosts, h)) {
			ok = false
			continue
		}
		p.subject.Hosts = append(p.subject.Hosts, h)
		// One tap makes a grant for each host key of each host (a host
		// can have one host key of each key type).
		for _, hk := range keys {
			p.grantHostKeys = append(p.grantHostKeys, string(hk.Marshal()))
		}
	}

	// The grants last whole minutes: at least 1, and at most the key's
	// window.
	minutes := int(r.For / time.Minute)
	if r.For <= 0 || minutes < 1 || !keyOK || r.For > k.Rule.Window {
		ok = false
	}
	if !ok {
		return false
	}
	p.windowMinutes = minutes
	// The message shows the end to the second. The grants end at the
	// start of that second, not later.
	p.grantEnds = p.start.add(time.Duration(minutes) * time.Minute).wholeSecond()
	return true
}

// checkKey checks that the key exists, that the client may use it and
// that its rule is valid. It adds the key to p.
func (c *Core) checkKey(name string, p *pending) (config.Key, bool) {
	k, known := c.cfg.Keys[name]
	if !known || p.client == "" || !slices.Contains(k.Clients, p.client) || !validRule(k.Rule, k.Clients) {
		return config.Key{}, false
	}
	p.items = []item{{ref: ref{key: true, name: name}, rule: k.Rule}}
	p.subject.Key = name
	return k, true
}

// checkUser checks the remote user name.
func (c *Core) checkUser(user string, p *pending) bool {
	if !remoteUserPattern.MatchString(user) {
		return false
	}
	p.user = user
	p.subject.RemoteUser = user
	return true
}

// validRule reports whether r is one of the three rules, with valid
// values (config.Rule says how code must use a rule). clients are the
// clients of its secret or key.
func validRule(r config.Rule, clients []string) bool {
	switch r.Ask {
	case config.AskAlways:
		return true
	case config.AskWindow:
		return r.Window >= config.MinWindow && r.Window <= config.MaxWindow
	case config.AskNever:
		// A "never" rule is an open door for one client only (DESIGN.md
		// section 12).
		return len(clients) == 1 && r.MaxPerDay >= 0
	default:
		return false
	}
}

// windowMinutes returns N for the "Approve N min" button: the shortest
// window of the items, in whole minutes, rounded down so a grant is never
// longer than a window. It returns 0, no button, when an item has no
// "window" rule. A valid window is at least config.MinWindow, so N is then
// at least 1.
func windowMinutes(items []item) int {
	n := 0
	for i, it := range items {
		if it.rule.Ask != config.AskWindow {
			return 0
		}
		m := int(it.rule.Window / time.Minute)
		if i == 0 || m < n {
			n = m
		}
	}
	return n
}
