package config

import (
	"maps"
	"strings"
	"testing"
	"time"
)

func reloadBase() *Broker {
	return &Broker{
		Telegram: Telegram{UserID: 1, Timeout: time.Minute},
		Clients:  map[string]Client{"laptop": {Name: "laptop", Pin: Pin{1}}, "ci": {Name: "ci", Pin: Pin{2}}},
		Stores:   map[string]Store{"main": {Name: "main", Type: StoreBWS}},
		Secrets: map[string]Secret{"token": {Name: "token", Store: "main", ID: "a", Clients: []string{"laptop"},
			Rule: Rule{Ask: AskWindow, Window: time.Minute}}},
		Keys: map[string]Key{"deploy": {Name: "deploy", File: "/k", Clients: []string{"laptop"}, Hosts: []string{"web-1"},
			Rule: Rule{Ask: AskAlways}}},
	}
}

func reloadCopy(b *Broker) *Broker {
	n := *b
	n.Clients, n.Stores, n.Secrets, n.Keys = maps.Clone(b.Clients), maps.Clone(b.Stores), maps.Clone(b.Secrets), maps.Clone(b.Keys)
	return &n
}

// TestReloadFixed: a reload refuses a change of each part that needs a
// restart, and takes changes of clients, secrets and keys.
func TestReloadFixed(t *testing.T) {
	old := reloadBase()
	for name, change := range map[string]func(*Broker){
		"tls_key":      func(b *Broker) { b.TLSKey = "/other" },
		"audit_log":    func(b *Broker) { b.AuditLog = "/other" },
		"[telegram]":   func(b *Broker) { b.Telegram.Timeout = 2 * time.Minute },
		"[ntfy]":       func(b *Broker) { b.Ntfy = &Ntfy{} },
		"[updates]":    func(b *Broker) { b.Updates.Check = true },
		"[preapprove]": func(b *Broker) { b.Preapprove.MaxUses = 9 },
		"[standing]":   func(b *Broker) { b.Standing.Enabled = true },
		"[store.*]":    func(b *Broker) { b.Stores["main"] = Store{Name: "main", Type: StoreBWS, Program: "/x"} },
	} {
		next := reloadCopy(old)
		change(next)
		if err := old.ReloadFixed(next); err == nil || !strings.HasPrefix(err.Error(), name+": is changed") {
			t.Errorf("%s: %v", name, err)
		}
	}
	next := reloadCopy(old)
	delete(next.Secrets, "token")
	delete(next.Keys, "deploy")
	next.Clients["new"] = Client{Name: "new", Pin: Pin{3}}
	if err := old.ReloadFixed(next); err != nil {
		t.Errorf("clients, secrets and keys: %v", err)
	}
}

// TestReloadSame: SameSecret and SameKey are true only for the same client
// with the same pin, still in the list, and the same section in all else.
func TestReloadSame(t *testing.T) {
	old := reloadBase()
	if !old.SameSecret(reloadCopy(old), "token", "laptop") || !old.SameKey(reloadCopy(old), "deploy", "laptop") {
		t.Fatal("the same config is not the same")
	}
	if old.SameSecret(reloadCopy(old), "token", "ci") || old.SameKey(reloadCopy(old), "deploy", "ci") {
		t.Error("a client that is not in the list")
	}
	type tc struct {
		name   string
		change func(*Broker)
		secret bool // the change keeps the secret
		key    bool // the change keeps the key
	}
	for _, c := range []tc{
		{"a new pin", func(b *Broker) { b.Clients["laptop"] = Client{Name: "laptop", Pin: Pin{9}} }, false, false},
		{"no client", func(b *Broker) { delete(b.Clients, "laptop") }, false, false},
		{"another client added", func(b *Broker) {
			s := b.Secrets["token"]
			s.Clients = []string{"laptop", "ci"}
			b.Secrets["token"] = s
			k := b.Keys["deploy"]
			k.Clients = []string{"ci", "laptop"}
			b.Keys["deploy"] = k
		}, true, true},
		{"another item", func(b *Broker) { s := b.Secrets["token"]; s.ID = "b"; b.Secrets["token"] = s }, false, true},
		{"another store", func(b *Broker) { s := b.Secrets["token"]; s.Store = "x"; b.Secrets["token"] = s }, false, true},
		{"a longer window", func(b *Broker) {
			s := b.Secrets["token"]
			s.Rule.Window = time.Hour
			b.Secrets["token"] = s
		}, false, true},
		{"the client removed", func(b *Broker) {
			s := b.Secrets["token"]
			s.Clients = []string{"ci"}
			b.Secrets["token"] = s
			k := b.Keys["deploy"]
			k.Clients = nil
			b.Keys["deploy"] = k
		}, false, false},
		{"another key file", func(b *Broker) { k := b.Keys["deploy"]; k.File = "/j"; b.Keys["deploy"] = k }, true, false},
		{"other hosts", func(b *Broker) { k := b.Keys["deploy"]; k.Hosts = nil; b.Keys["deploy"] = k }, true, true},
		{"gone", func(b *Broker) { delete(b.Secrets, "token"); delete(b.Keys, "deploy") }, false, false},
	} {
		next := reloadCopy(old)
		c.change(next)
		if got := old.SameSecret(next, "token", "laptop"); got != c.secret {
			t.Errorf("%s: SameSecret %v", c.name, got)
		}
		if got := old.SameKey(next, "deploy", "laptop"); got != c.key {
			t.Errorf("%s: SameKey %v", c.name, got)
		}
	}
}
