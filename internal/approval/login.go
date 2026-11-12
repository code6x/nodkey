package approval

import (
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/code6x/nodkey/internal/claim"
	"github.com/code6x/nodkey/internal/config"
)

// LoginPreapproveTime is how long a pre-approval of one login lasts after
// the tap (DESIGN.md section 21). The time starts at the tap, not when
// the request was made: the person may take long to tap.
const LoginPreapproveTime = 60 * time.Second

// maxLoginText is the most runes of an item name or a user name in a
// message. A longer text is cut.
const maxLoginText = 128

// noLoginName stands for an item name that is empty after cleaning.
const noLoginName = "(no name)"

var (
	// loginOriginPattern is the form of an origin that the broker made
	// from a checked page URL: https, a host name or an IP address, and
	// perhaps a port. It is also the form that the audit log takes.
	loginOriginPattern = regexp.MustCompile(`^https://([a-z0-9][a-z0-9.-]{0,252}|\[[0-9a-f:]{2,45}\])(:[0-9]{1,5})?$`)
	// loginItemPattern is a Bitwarden item ID in lower case.
	loginItemPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// loginRef returns the ref of the login item with the ID item.
func loginRef(item string) ref { return ref{login: true, name: strings.ToLower(item)} }

// checkLoginScope checks the login of r against the config of p, and
// fills what both kinds of login request share: the item, the subject,
// the origin and the text of the message. It does not look at the kind.
func (c *Core) checkLoginScope(r *Request, p *pending) (rule config.Rule, ok bool) {
	l := r.Login
	if l == nil || p.client == "" {
		return config.Rule{}, false
	}
	if !slices.Contains(l.Clients, p.client) || !validRule(l.Rule, l.Clients) || l.Rule.Ask == config.AskNever {
		return config.Rule{}, false
	}
	if !loginOriginPattern.MatchString(l.Origin) || !loginItemPattern.MatchString(l.Item) {
		return config.Rule{}, false
	}
	// The config of the checks must still have the section, and give the
	// rule that the broker used: else a reload came in between.
	sec, found := p.cfg.Logins[l.Section]
	if !found {
		return config.Rule{}, false
	}
	clients, cfgRule, known := sec.RuleFor(l.Item)
	if !known || !slices.Equal(clients, l.Clients) || !sameLoginRule(cfgRule, l.Rule) {
		return config.Rule{}, false
	}
	p.items = []item{{ref: loginRef(l.Item), rule: l.Rule}}
	p.origin = l.Origin
	p.subject.Logins, p.subject.Item, p.subject.Origin = l.Section, l.Item, l.Origin
	p.login = &LoginPrompt{Name: loginText(l.Name, noLoginName), Username: loginText(l.Username, ""), Origin: l.Origin}
	return l.Rule, true
}

// sameLoginRule reports whether got is the configured rule cfg, or cfg
// made stricter for an item with a re-prompt: the broker then asks every
// time, which is "always".
func sameLoginRule(cfg, got config.Rule) bool {
	if got.Ask == config.AskAlways && cfg.Ask != config.AskAlways {
		cfg.Ask, cfg.Window = config.AskAlways, got.Window
	}
	return reflect.DeepEqual(cfg, got)
}

// loginText cleans text from the vault for a message: one line, no
// control or direction characters, at most maxLoginText runes.
func loginText(s, empty string) string {
	if t := claim.Line(s, maxLoginText); t != "" {
		return t
	}
	return empty
}

// checkWebLogin checks a KindWebLogin request (DESIGN.md section 21).
func (c *Core) checkWebLogin(r *Request, p *pending) bool {
	ok := r.Key == "" && r.HostKey == nil && r.RemoteUser == "" && len(r.Hosts) == 0 && len(r.Secrets) == 0 &&
		r.For == 0 && r.Uses == 0 && r.NotBefore.IsZero() && r.NotAfter.IsZero() && len(r.Windows) == 0
	if _, good := c.checkLoginScope(r, p); !good || !ok {
		p.items = nil
		return false
	}
	p.once = true
	p.windowMinutes = windowMinutes(p.items)
	return true
}

// checkLoginPreapprove checks a KindPreapprove request for one login: one
// use, no times, and a rule with preapprove = true.
func (c *Core) checkLoginPreapprove(r *Request, p *pending) bool {
	ok := r.Key == "" && r.HostKey == nil && r.RemoteUser == "" && len(r.Hosts) == 0 && len(r.Secrets) == 0 &&
		r.For == 0 && r.Uses == 1 && r.NotBefore.IsZero() && r.NotAfter.IsZero()
	rule, good := c.checkLoginScope(r, p)
	if !good || !ok || !rule.Preapprove || rule.Ask == config.AskNever {
		p.items, p.login = nil, nil
		return false
	}
	p.login.For = LoginPreapproveTime
	p.once = true // the one "Approve" button
	p.subject.Uses = 1
	p.plan = &grant{
		kind: kindScheduled, client: p.client, refs: []ref{p.items[0].ref}, uses: 1,
		loginOrigin: r.Login.Origin,
	}
	return true
}

// LoginGranted reports whether a live "Approve N min" grant covers the
// login item for client now (DESIGN.md section 21). The broker uses it
// for TOTP codes, after it has checked the rule of the item. A
// pre-approval does not count: it covers one login.
func (c *Core) LoginGranted(client, item string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.granted(grantKey{client: client, ref: loginRef(item)}, c.now())
}

// keepsLogin reports whether the login grant g of the config old is
// allowed in the same way by the config next: the same sections, each
// with the same store and collection, and for the item the same clients
// and the same rule.
func keepsLogin(old, next *config.Broker, item, client string) bool {
	if len(old.Logins) != len(next.Logins) {
		return false
	}
	for name, o := range old.Logins {
		n, ok := next.Logins[name]
		if !ok || o.Store != n.Store || o.Collection != n.Collection {
			return false
		}
		oc, or, ok1 := o.RuleFor(item)
		nc, nr, ok2 := n.RuleFor(item)
		if !ok1 || !ok2 || !slices.Equal(oc, nc) || !reflect.DeepEqual(or, nr) {
			return false
		}
		if slices.Contains(oc, client) != slices.Contains(nc, client) {
			return false
		}
	}
	return true
}
