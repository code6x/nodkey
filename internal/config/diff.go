package config

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// The diff of two broker configs by meaning (nodkey broker config-diff,
// issue #174, DESIGN.md section 15). It compares two configs that
// LoadBroker's parser read, not their text: comments, order and spaces do
// not count. A change that widens access or weakens a control is marked.
// So is every change that this code does not know as narrowing: a new
// part of the config is marked until someone decides otherwise here.

// Change is one change from an old config to a new one.
type Change struct {
	// Group sorts the changes: "broker", "client", "store", "secret",
	// "key" or "known_hosts".
	Group string
	// Name is the name of the section in the group, or "" for the top.
	Name string
	// Text says what changed, in plain words. Text from the config in it
	// is quoted with strconv.Quote.
	Text string
	// Widens is true when the change widens access or weakens a control,
	// or is of a kind that Diff does not know as narrowing.
	Widens bool
}

// String is the line of the change: "⚠ " before a change that widens,
// two spaces before one that narrows.
func (c Change) String() string {
	if c.Widens {
		return "⚠ " + c.Text
	}
	return "  " + c.Text
}

// groups is the order of the groups in the output.
var groups = []string{"broker", "client", "store", "secret", "logins", "key", "known_hosts"}

// Diff returns the changes from old to next, by group and then by name,
// in a fixed order. No change means the two configs mean the same.
func Diff(old, next *Broker) []Change {
	d := &differ{}
	d.top(old, next)
	d.clients(old, next)
	d.stores(old, next)
	d.secrets(old, next)
	d.logins(old, next)
	d.keys(old, next)
	d.knownHosts(old.KnownHosts, next.KnownHosts)
	d.unknown(old, next)
	order := func(g string) int { return slices.Index(groups, g) }
	slices.SortStableFunc(d.out, func(a, b Change) int {
		if x, y := order(a.Group), order(b.Group); x != y {
			return x - y
		}
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	return d.out
}

type differ struct{ out []Change }

func (d *differ) add(group, name string, widens bool, format string, args ...any) {
	d.out = append(d.out, Change{Group: group, Name: name, Text: fmt.Sprintf(format, args...), Widens: widens})
}

func q(s string) string { return strconv.Quote(s) }

func dur(t time.Duration) string { return formatDuration(t) }

// top compares the top keys and the sections that are not named:
// [telegram], [ntfy], [updates], [preapprove] and [standing].
func (d *differ) top(old, next *Broker) {
	if old.Listen != next.Listen {
		d.add("broker", "", true, "listen: changed from %s to %s", q(old.Listen.String()), q(next.Listen.String()))
	}
	for _, p := range []struct{ key, old, new string }{
		{"tls_key", old.TLSKey, next.TLSKey},
		{"audit_log", old.AuditLog, next.AuditLog},
		{"known_hosts", old.KnownHostsFile, next.KnownHostsFile},
	} {
		if p.old != p.new {
			d.add("broker", "", true, "%s: changed from %s to %s", p.key, q(p.old), q(p.new))
		}
	}
	d.channel(old, next)
	if old.Updates.Check != next.Updates.Check {
		// The check for a newer release tells the owner about security
		// fixes: off weakens a control.
		d.add("broker", "", !next.Updates.Check, "[updates] check: changed from %t to %t",
			old.Updates.Check, next.Updates.Check)
	}
	o, n := old.Preapprove, next.Preapprove
	d.durLimit("[preapprove] max_ahead", o.MaxAhead, n.MaxAhead)
	d.durLimit("[preapprove] max_open", o.MaxOpen, n.MaxOpen)
	d.intLimit("[preapprove] max_uses", o.MaxUses, n.MaxUses)
	d.intLimit("[preapprove] max_grants", o.MaxGrants, n.MaxGrants)
	os, ns := old.Standing, next.Standing
	switch {
	case !os.Enabled && ns.Enabled:
		d.add("broker", "", true, "[standing]: new: standing grants are allowed")
	case os.Enabled && !ns.Enabled:
		d.add("broker", "", false, "[standing]: removed: no standing grants")
	case os.Enabled:
		d.intLimit("[standing] max_days", os.MaxDays, ns.MaxDays)
		d.durLimit("[standing] max_window", os.MaxWindow, ns.MaxWindow)
		d.intLimit("[standing] max_uses", os.MaxUses, ns.MaxUses)
		d.intLimit("[standing] max_grants", os.MaxGrants, ns.MaxGrants)
		if os.WarnDays != ns.WarnDays {
			// Fewer days of warning weaken a control.
			d.add("broker", "", ns.WarnDays < os.WarnDays, "[standing] warn_days: changed from %d to %d",
				os.WarnDays, ns.WarnDays)
		}
		if os.SummaryDay != ns.SummaryDay || os.SummaryMinute != ns.SummaryMinute {
			d.add("broker", "", true, "[standing] summary: changed from %s to %s",
				summaryText(os.SummaryDay, os.SummaryMinute), summaryText(ns.SummaryDay, ns.SummaryMinute))
		}
	}
}

func summaryText(day time.Weekday, minute int) string {
	return fmt.Sprintf("%q", fmt.Sprintf("%.3s %02d:%02d", day.String(), minute/60, minute%60))
}

// durLimit and intLimit add a change of a limit: a higher limit widens.
func (d *differ) durLimit(key string, old, next time.Duration) {
	if old != next {
		d.add("broker", "", next > old, "%s: changed from %s to %s", key, dur(old), dur(next))
	}
}

func (d *differ) intLimit(key string, old, next int) {
	if old != next {
		d.add("broker", "", next > old, "%s: changed from %d to %d", key, old, next)
	}
}

// channel compares the approval channel. Every change of the approver or
// of where the notices go widens, but a shorter timeout.
func (d *differ) channel(old, next *Broker) {
	switch {
	case old.Ntfy == nil && next.Ntfy != nil:
		d.add("broker", "", true, "the approval channel: changed from [telegram] to [ntfy] (server %s)", q(next.Ntfy.Server))
		return
	case old.Ntfy != nil && next.Ntfy == nil:
		d.add("broker", "", true, "the approval channel: changed from [ntfy] to [telegram] (user_id %d)", next.Telegram.UserID)
		return
	}
	timeouts := func(sec string, ot, os, nt, ns time.Duration) {
		if ot != nt {
			d.add("broker", "", nt > ot, "%s timeout: changed from %s to %s", sec, dur(ot), dur(nt))
		}
		if os != ns {
			d.add("broker", "", ns > os, "%s ssh_timeout: changed from %s to %s", sec, dur(os), dur(ns))
		}
	}
	if old.Ntfy != nil {
		o, n := *old.Ntfy, *next.Ntfy
		for _, p := range []struct{ key, old, new string }{
			{"server", o.Server, n.Server},
			{"request_topic", o.RequestTopic, n.RequestTopic},
			{"answer_topic", o.AnswerTopic, n.AnswerTopic},
			{"token_file", o.TokenFile, n.TokenFile},
		} {
			if p.old != p.new {
				d.add("broker", "", true, "[ntfy] %s: changed from %s to %s", p.key, q(p.old), q(p.new))
			}
		}
		timeouts("[ntfy]", o.Timeout, o.SSHTimeout, n.Timeout, n.SSHTimeout)
		return
	}
	o, n := old.Telegram, next.Telegram
	if o.TokenFile != n.TokenFile {
		d.add("broker", "", true, "[telegram] token_file: changed from %s to %s", q(o.TokenFile), q(n.TokenFile))
	}
	if o.UserID != n.UserID {
		d.add("broker", "", true, "[telegram] user_id: the approver changed from %d to %d", o.UserID, n.UserID)
	}
	if o.NoticeChatID != n.NoticeChatID {
		d.add("broker", "", true, "[telegram] notice_chat_id: the notices go to %d, not %d", n.NoticeChatID, o.NoticeChatID)
	}
	timeouts("[telegram]", o.Timeout, o.SSHTimeout, n.Timeout, n.SSHTimeout)
}

func (d *differ) clients(old, next *Broker) {
	for _, name := range sortedUnion(old.Clients, next.Clients) {
		o, inOld := old.Clients[name]
		n, inNew := next.Clients[name]
		sec := q(sectionName("client", name))
		switch {
		case !inOld:
			d.add("client", name, true, "client %s: new client", q(name))
		case !inNew:
			d.add("client", name, false, "client %s: removed", q(name))
		case o.Pin != n.Pin:
			d.add("client", name, true, "client %s: new pin %s (in %s)", q(name), n.Pin, sec)
		}
	}
}

func (d *differ) stores(old, next *Broker) {
	for _, name := range sortedUnion(old.Stores, next.Stores) {
		o, inOld := old.Stores[name]
		n, inNew := next.Stores[name]
		switch {
		case !inOld:
			d.add("store", name, true, "store %s: new store of type %s", q(name), q(string(n.Type)))
			continue
		case !inNew:
			d.add("store", name, false, "store %s: removed", q(name))
			continue
		}
		for _, p := range []struct{ key, old, new string }{
			{"type", string(o.Type), string(n.Type)},
			{"program", o.Program, n.Program},
			{"token_file", o.TokenFile, n.TokenFile},
			{"password_file", o.PasswordFile, n.PasswordFile},
			{"vault", o.Vault, n.Vault},
			{"server", o.Server, n.Server},
			{"client_id", o.ClientID, n.ClientID},
			{"client_secret_file", o.ClientSecretFile, n.ClientSecretFile},
		} {
			if p.old != p.new {
				d.add("store", name, true, "store %s: %s changed from %s to %s", q(name), p.key, q(p.old), q(p.new))
			}
		}
	}
}

func (d *differ) secrets(old, next *Broker) {
	for _, name := range sortedUnion(old.Secrets, next.Secrets) {
		o, inOld := old.Secrets[name]
		n, inNew := next.Secrets[name]
		what := "secret " + q(name)
		switch {
		case !inOld:
			d.add("secret", name, true, "%s: new secret in store %s, %s", what, q(n.Store), ruleText(n.Rule))
			for _, c := range n.Clients {
				d.add("secret", name, true, "%s: client %s may now ask for it", what, q(c))
			}
			continue
		case !inNew:
			d.add("secret", name, false, "%s: removed", what)
			continue
		}
		for _, p := range []struct{ key, old, new string }{
			{"store", o.Store, n.Store},
			{"id", o.ID, n.ID},
			{"field", o.Field, n.Field},
			{"project", o.Project, n.Project},
			{"environment", o.Environment, n.Environment},
			{"path", o.Path, n.Path},
			{"name", o.SecretName, n.SecretName},
		} {
			if p.old != p.new {
				d.add("secret", name, true, "%s: now another item: %s changed from %s to %s", what, p.key, q(p.old), q(p.new))
			}
		}
		d.clientList("secret", name, what, "ask for it", o.Clients, n.Clients)
		d.rule("secret", name, what, o.Rule, n.Rule)
	}
}

// logins compares the [logins.*] sections. A new or removed rule of an
// item is marked as widening: the item's rule replaces the collection's,
// and either one can be the looser (DESIGN.md section 21.2).
func (d *differ) logins(old, next *Broker) {
	for _, name := range sortedUnion(old.Logins, next.Logins) {
		o, inOld := old.Logins[name]
		n, inNew := next.Logins[name]
		what := "logins " + q(name)
		switch {
		case !inOld:
			d.add("logins", name, true, "%s: new website logins of collection %s in store %s, %s",
				what, q(n.Collection), q(n.Store), ruleText(n.Rule))
			for _, c := range n.Clients {
				d.add("logins", name, true, "%s: client %s may now ask for a login", what, q(c))
			}
			for _, id := range slices.Sorted(maps.Keys(n.Items)) {
				d.add("logins", name, true, "%s: item %s has its own rule: %s", what, q(id), ruleText(n.Items[id].Rule))
			}
			continue
		case !inNew:
			d.add("logins", name, false, "%s: removed", what)
			continue
		}
		for _, p := range []struct{ key, old, new string }{
			{"store", o.Store, n.Store},
			{"collection", o.Collection, n.Collection},
		} {
			if p.old != p.new {
				d.add("logins", name, true, "%s: now other logins: %s changed from %s to %s", what, p.key, q(p.old), q(p.new))
			}
		}
		d.clientList("logins", name, what, "ask for a login", o.Clients, n.Clients)
		d.rule("logins", name, what, o.Rule, n.Rule)
		for _, id := range sortedUnion(o.Items, n.Items) {
			oi, inO := o.Items[id]
			ni, inN := n.Items[id]
			iw := what + " item " + q(id)
			switch {
			case !inO:
				d.add("logins", name, true, "%s: has its own rule now, in place of the collection's: %s", iw, ruleText(ni.Rule))
				for _, c := range ni.Clients {
					d.add("logins", name, !slices.Contains(o.Clients, c), "%s: client %s may ask for it", iw, q(c))
				}
			case !inN:
				d.add("logins", name, true, "%s: its own rule is removed; the collection's rule applies now: %s",
					iw, ruleText(n.Rule))
			default:
				d.clientList("logins", name, iw, "ask for it", oi.Clients, ni.Clients)
				d.rule("logins", name, iw, oi.Rule, ni.Rule)
			}
		}
	}
}

func (d *differ) keys(old, next *Broker) {
	for _, name := range sortedUnion(old.Keys, next.Keys) {
		o, inOld := old.Keys[name]
		n, inNew := next.Keys[name]
		what := "SSH key " + q(name)
		switch {
		case !inOld:
			d.add("key", name, true, "%s: new key, %s, %s", what, hostsText(n.Hosts), ruleText(n.Rule))
			for _, c := range n.Clients {
				d.add("key", name, true, "%s: client %s may now use it", what, q(c))
			}
			continue
		case !inNew:
			d.add("key", name, false, "%s: removed", what)
			continue
		}
		if o.File != n.File {
			d.add("key", name, true, "%s: file changed from %s to %s", what, q(o.File), q(n.File))
		}
		d.clientList("key", name, what, "use it", o.Clients, n.Clients)
		switch {
		case len(o.Hosts) > 0 && len(n.Hosts) == 0:
			d.add("key", name, true, "%s: may now log in to every host in known_hosts", what)
		case len(o.Hosts) == 0 && len(n.Hosts) > 0:
			d.add("key", name, false, "%s: may now log in only to %s", what, hostsText(n.Hosts))
		default:
			for _, h := range n.Hosts {
				if !slices.Contains(o.Hosts, h) {
					d.add("key", name, true, "%s: new host %s", what, q(h))
				}
			}
			for _, h := range o.Hosts {
				if !slices.Contains(n.Hosts, h) {
					d.add("key", name, false, "%s: host %s removed", what, q(h))
				}
			}
		}
		d.rule("key", name, what, o.Rule, n.Rule)
	}
}

func hostsText(hosts []string) string {
	if len(hosts) == 0 {
		return "every host in known_hosts"
	}
	s := "hosts"
	for _, h := range hosts {
		s += " " + q(h)
	}
	return s
}

// clientList compares the clients of a secret or a key. verb is "ask
// for it" or "use it".
func (d *differ) clientList(group, name, what, verb string, old, next []string) {
	for _, c := range next {
		if !slices.Contains(old, c) {
			d.add(group, name, true, "%s: client %s may now %s", what, q(c), verb)
		}
	}
	for _, c := range old {
		if !slices.Contains(next, c) {
			d.add(group, name, false, "%s: client %s may no longer %s", what, q(c), verb)
		}
	}
}

// askLevel orders the ask values from the strictest: always, window,
// never. An ask that is none of them is the most open, so a change to it
// widens.
func askLevel(a Ask) int {
	switch a {
	case AskAlways:
		return 0
	case AskWindow:
		return 1
	case AskNever:
		return 2
	}
	return 3
}

func ruleText(r Rule) string {
	s := "ask = " + q(string(r.Ask))
	if r.Ask == AskWindow {
		s += ", window = " + q(dur(r.Window))
	}
	if r.Preapprove {
		s += ", preapprove = true"
	}
	if r.Standing {
		s += ", standing = true"
	}
	return s
}

// rule compares the rules of a secret or a key.
func (d *differ) rule(group, name, what string, o, n Rule) {
	if o.Ask != n.Ask {
		widens := askLevel(n.Ask) > askLevel(o.Ask)
		text := "ask changed from %s to %s"
		if n.Ask == AskNever {
			text = "new rule: never ask (ask changed from %s to %s)"
		}
		extra := ""
		if n.Ask == AskNever {
			extra = neverText(n)
		}
		d.add(group, name, widens, "%s: "+text+"%s", what, q(string(o.Ask)), q(string(n.Ask)), extra)
	}
	if o.Window != n.Window && (o.Ask == AskWindow || n.Ask == AskWindow) {
		d.add(group, name, n.Window > o.Window, "%s: window changed from %s to %s", what, dur(o.Window), dur(n.Window))
	}
	if o.Preapprove != n.Preapprove {
		d.add(group, name, n.Preapprove, "%s: preapprove changed from %t to %t", what, o.Preapprove, n.Preapprove)
	}
	if o.Standing != n.Standing {
		d.add(group, name, n.Standing, "%s: standing changed from %t to %t", what, o.Standing, n.Standing)
	}
	// notify, max_per_day and hours apply only to a "never" rule. When
	// only one side is "never", the ask line above says it.
	if o.Ask != AskNever || n.Ask != AskNever {
		return
	}
	if o.Notify != n.Notify {
		d.add(group, name, !n.Notify, "%s: notify changed from %t to %t", what, o.Notify, n.Notify)
	}
	if o.MaxPerDay != n.MaxPerDay {
		// 0 is no limit.
		widens := n.MaxPerDay == 0 || (o.MaxPerDay != 0 && n.MaxPerDay > o.MaxPerDay)
		d.add(group, name, widens, "%s: max_per_day changed from %s to %s", what, perDay(o.MaxPerDay), perDay(n.MaxPerDay))
	}
	if !reflect.DeepEqual(o.Hours, n.Hours) {
		d.add(group, name, wider(o.Hours, n.Hours), "%s: hours changed from %s to %s", what, hoursText(o.Hours), hoursText(n.Hours))
	}
}

// neverText is the part of a "never" rule after the ask line.
func neverText(r Rule) string {
	return fmt.Sprintf(", with notify %t, max_per_day %s, hours %s", r.Notify, perDay(r.MaxPerDay), hoursText(r.Hours))
}

func perDay(n int) string {
	if n == 0 {
		return "no limit"
	}
	return strconv.Itoa(n)
}

func hoursText(h *Hours) string {
	if h == nil {
		return "any time"
	}
	clock := func(t time.Duration) string {
		return fmt.Sprintf("%02d:%02d", int(t/time.Hour), int(t%time.Hour/time.Minute))
	}
	return q(clock(h.From) + "-" + clock(h.To))
}

// wider reports whether the hours next allow a minute that old does not.
// nil is any time.
func wider(old, next *Hours) bool {
	if old == nil {
		return false
	}
	if next == nil {
		return true
	}
	day := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	for m := range 24 * 60 {
		t := day.Add(time.Duration(m) * time.Minute)
		if next.Contains(t) && !old.Contains(t) {
			return true
		}
	}
	return false
}

func (d *differ) knownHosts(old, next *KnownHosts) {
	names := func(k *KnownHosts) map[string][]ssh.PublicKey {
		if k == nil {
			return nil
		}
		return k.byName
	}
	o, n := names(old), names(next)
	for _, host := range sortedUnion(o, n) {
		ok := keySet(o[host])
		nk := keySet(n[host])
		switch {
		case len(ok) == 0:
			d.add("known_hosts", host, true, "known_hosts: new host %s", q(host))
			continue
		case len(nk) == 0:
			d.add("known_hosts", host, false, "known_hosts: host %s removed", q(host))
			continue
		}
		for _, k := range slices.Sorted(maps.Keys(nk)) {
			if !ok[k] {
				d.add("known_hosts", host, true, "known_hosts: host %s has a new host key %s", q(host), k)
			}
		}
		for _, k := range slices.Sorted(maps.Keys(ok)) {
			if !nk[k] {
				d.add("known_hosts", host, false, "known_hosts: host %s: host key %s removed", q(host), k)
			}
		}
	}
}

// keySet returns the SHA-256 fingerprints of keys.
func keySet(keys []ssh.PublicKey) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[ssh.FingerprintSHA256(k)] = true
	}
	return m
}

func sortedUnion[V any](a, b map[string]V) []string {
	names := slices.Collect(maps.Keys(a))
	for name := range b {
		if _, ok := a[name]; !ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// unknown marks a change that the code above does not compare. In copies
// of the two configs, it zeros every field that the code above compares
// (compared), keeps only the names that both configs have, and compares
// the rest. So a field that is added to one of these types later is
// marked as a change that widens, until it is added above and to
// compared.
func (d *differ) unknown(old, next *Broker) {
	x, y := *old, *next
	x.Clients, y.Clients = common(old.Clients, next.Clients)
	x.Stores, y.Stores = common(old.Stores, next.Stores)
	x.Secrets, y.Secrets = common(old.Secrets, next.Secrets)
	x.Keys, y.Keys = common(old.Keys, next.Keys)
	x.Logins, y.Logins = common(old.Logins, next.Logins)
	for name, l := range x.Logins {
		// Item rules that only one side has are compared in logins.
		m := y.Logins[name]
		l.Items, m.Items = common(l.Items, m.Items)
		x.Logins[name], y.Logins[name] = l, m
	}
	if (x.Ntfy == nil) != (y.Ntfy == nil) {
		x.Ntfy, y.Ntfy = nil, nil // a change of the channel is compared above
	}
	zeroCompared(reflect.ValueOf(&x).Elem())
	zeroCompared(reflect.ValueOf(&y).Elem())
	if !reflect.DeepEqual(x, y) {
		d.add("broker", "", true, "a change that config-diff does not know; read the two configs")
	}
}

// compared names the fields of each type that Diff compares, or that are
// not part of the meaning (Path, Sum, Name). A field of these types that
// is not here is compared by unknown.
var compared = map[reflect.Type][]string{
	reflect.TypeFor[Broker]():           {"Path", "Sum", "Listen", "TLSKey", "AuditLog", "KnownHostsFile", "KnownHosts"},
	reflect.TypeFor[Telegram]():         {"TokenFile", "UserID", "NoticeChatID", "Timeout", "SSHTimeout"},
	reflect.TypeFor[Ntfy]():             {"Server", "RequestTopic", "AnswerTopic", "TokenFile", "Timeout", "SSHTimeout"},
	reflect.TypeFor[Updates]():          {"Check"},
	reflect.TypeFor[PreapproveLimits](): {"MaxAhead", "MaxOpen", "MaxUses", "MaxGrants"},
	reflect.TypeFor[StandingLimits](): {"Enabled", "MaxDays", "MaxWindow", "MaxUses", "MaxGrants", "WarnDays",
		"SummaryDay", "SummaryMinute"},
	reflect.TypeFor[Client](): {"Name", "Pin"},
	reflect.TypeFor[Store](): {"Name", "Type", "Program", "TokenFile", "PasswordFile", "Vault", "Server", "ClientID",
		"ClientSecretFile"},
	reflect.TypeFor[Secret](): {"Name", "Store", "ID", "Field", "Project", "Environment", "Path", "SecretName",
		"Clients"},
	reflect.TypeFor[Key]():           {"Name", "File", "Clients", "Hosts"},
	reflect.TypeFor[Logins]():        {"Name", "Store", "Collection", "Clients"},
	reflect.TypeFor[LoginItemRule](): {"ID", "Clients"},
	reflect.TypeFor[Rule]():          {"Ask", "Window", "Preapprove", "Standing", "Notify", "MaxPerDay", "Hours"},
}

// zeroCompared zeros the fields in compared, in v and in each struct,
// pointer and map below it. v must be settable. Pointers and maps are
// copied first, so the configs themselves do not change.
func zeroCompared(v reflect.Value) {
	switch v.Kind() {
	case reflect.Struct:
		names := compared[v.Type()]
		for i := range v.NumField() {
			f := v.Field(i)
			if !f.CanSet() {
				continue // an unexported field: DeepEqual compares it
			}
			if slices.Contains(names, v.Type().Field(i).Name) {
				f.SetZero()
			} else {
				zeroCompared(f)
			}
		}
	case reflect.Pointer:
		if !v.IsNil() {
			c := reflect.New(v.Type().Elem())
			c.Elem().Set(v.Elem())
			zeroCompared(c.Elem())
			v.Set(c)
		}
	case reflect.Map:
		if !v.IsNil() {
			m := reflect.MakeMapWithSize(v.Type(), v.Len())
			for it := v.MapRange(); it.Next(); {
				c := reflect.New(v.Type().Elem()).Elem()
				c.Set(it.Value())
				zeroCompared(c)
				m.SetMapIndex(it.Key(), c)
			}
			v.Set(m)
		}
	}
}

// common returns copies of a and b with only the names that both have.
// A name that only one has is a new or a removed section, compared above.
func common[V any](a, b map[string]V) (map[string]V, map[string]V) {
	x, y := make(map[string]V), make(map[string]V)
	for name, v := range a {
		if w, ok := b[name]; ok {
			x[name], y[name] = v, w
		}
	}
	return x, y
}
