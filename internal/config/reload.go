package config

import (
	"fmt"
	"reflect"
	"slices"

	"golang.org/x/crypto/ssh"
)

// The rules of a reload (DESIGN.md section 14, "Reload"). A reload may
// change the clients, the secrets, the SSH keys and the known hosts. Every
// other part needs a restart: the broker refuses a reload that changes
// one, and keeps the config it has.

// ReloadFixed checks that next changes only the parts of b that a reload
// may change. It returns an error that names the first part that needs a
// restart, or nil.
func (b *Broker) ReloadFixed(next *Broker) error {
	// All but the parts that a reload may change must be equal. So a part
	// that is added to Broker later needs a restart, until someone decides
	// otherwise here.
	x, y := *b, *next
	for _, c := range []*Broker{&x, &y} {
		c.Path, c.Sum, c.KnownHostsFile, c.KnownHosts = "", "", "", nil
		c.Clients, c.Secrets, c.Keys = nil, nil, nil
	}
	type part struct {
		name     string
		old, new any
	}
	parts := []part{
		{"listen", b.Listen, next.Listen},
		{"tls_key", b.TLSKey, next.TLSKey},
		{"audit_log", b.AuditLog, next.AuditLog},
		{"[telegram]", b.Telegram, next.Telegram},
		{"[ntfy]", b.Ntfy, next.Ntfy},
		{"[updates]", b.Updates, next.Updates},
		{"[preapprove]", b.Preapprove, next.Preapprove},
		{"[standing]", b.Standing, next.Standing},
		{"[store.*]", b.Stores, next.Stores},
		// Until the broker serves logins and keeps their grants per item
		// (DESIGN.md section 21.7), a change of them needs a restart.
		{"[logins.*]", b.Logins, next.Logins},
	}
	parts = append(parts, part{"the config", x, y}) // a part that is not named above
	for _, p := range parts {
		if !reflect.DeepEqual(p.old, p.new) {
			return fmt.Errorf("%s: is changed, and a reload cannot change it; restart the broker to use the new "+
				"config, or undo the change (DESIGN.md section 14, \"Reload\")", p.name)
		}
	}
	return nil
}

// SameClient reports whether the client name has the same TLS pin in b and
// in next. A client that next does not have, or that has a new pin, is
// not the same: its grants end.
func (b *Broker) SameClient(next *Broker, name string) bool {
	old, ok1 := b.Clients[name]
	cur, ok2 := next.Clients[name]
	return ok1 && ok2 && old == cur
}

// SameSecret reports whether client may still use the secret name in
// next as it could in b: the client is the same (SameClient), next lists it
// in the section, and the section is the same in all else (its store, its
// item and its rule). Another client added to or removed from the list does
// not count.
func (b *Broker) SameSecret(next *Broker, name, client string) bool {
	old, ok1 := b.Secrets[name]
	cur, ok2 := next.Secrets[name]
	if !ok1 || !ok2 || !b.SameClient(next, client) || !slices.Contains(old.Clients, client) ||
		!slices.Contains(cur.Clients, client) {
		return false
	}
	old.Clients, cur.Clients = nil, nil
	return reflect.DeepEqual(old, cur)
}

// SameKey reports whether client may still use the SSH key name in next as
// it could in b: the client is the same (SameClient), next lists it in the
// section, and the file and the rule are the same. The hosts may change;
// check each host with KeyHost. It does not read the key file: the caller
// must also check that the file holds the same key.
func (b *Broker) SameKey(next *Broker, name, client string) bool {
	old, ok1 := b.Keys[name]
	cur, ok2 := next.Keys[name]
	if !ok1 || !ok2 || !b.SameClient(next, client) || !slices.Contains(old.Clients, client) ||
		!slices.Contains(cur.Clients, client) {
		return false
	}
	old.Clients, cur.Clients, old.Hosts, cur.Hosts = nil, nil, nil, nil
	return reflect.DeepEqual(old, cur)
}

// KeyHost reports whether the SSH key name of b may log in to the host
// whose host key is hostKey, in SSH wire form: known_hosts names the
// host key, and the section's hosts list the name, or are empty.
func (b *Broker) KeyHost(name string, hostKey []byte) bool {
	k, ok := b.Keys[name]
	if !ok || b.KnownHosts == nil {
		return false
	}
	pub, err := ssh.ParsePublicKey(hostKey)
	if err != nil {
		return false
	}
	host, ok := b.KnownHosts.NameFor(pub)
	return ok && (len(k.Hosts) == 0 || slices.Contains(k.Hosts, host))
}
