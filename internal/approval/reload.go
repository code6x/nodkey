package approval

import (
	"time"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// Reload makes next the config of the core (DESIGN.md section 14,
// "Reload"). next must come from config.LoadBroker, and must pass
// ReloadFixed against the config that the core has now; nothing may change
// it later. sameKey reports whether the key file of the [key.*] section
// name holds the same key as before; the core cannot read key files.
//
// Every grant that the new config does not allow in the same way ends at
// once: its client, a secret or the key is gone or changed, the client
// lost access to it, or a host of a key grant is no longer allowed. The
// other grants stay, with the same uses left and the same end. The entries
// of the scheduled and standing grants that end (cause config_changed) go
// to the function of OnGrantEnded, and their messages lose the Revoke
// button.
//
// A request that the core checked with the old config, and that waits
// for a tap, is still decided, but its approval starts no grant. The
// broker checks it again before it hands out a value or signs.
//
// Reload returns how many grants ended.
func (c *Core) Reload(next *config.Broker, sameKey func(name string) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.conf()
	c.cfgp.Store(next)
	n := 0
	c.queueEnded(c.endWhere(func(g *grant) audit.EndCause {
		if keeps(old, next, sameKey, g) {
			return ""
		}
		n++
		return audit.EndConfig
	}))
	return n
}

// Config returns the config that the core used to check the request of
// r. The broker compares it with the config of now before it hands out
// anything (DESIGN.md section 14, "Reload").
func (r *Result) Config() *config.Broker {
	if r == nil {
		return nil
	}
	return r.cfg
}

// UsedGrantID returns the ID of the scheduled or standing grant whose use
// allowed the request of r, or "" when no such grant allowed it (a tap, a
// window grant or a "never ask" rule). The broker uses it to find the
// login that it fetched at the tap of a login pre-approval (DESIGN.md
// section 21.3).
func (r *Result) UsedGrantID() string {
	if r == nil || !r.Allowed {
		return ""
	}
	return r.usedID
}

// SinceTap returns how long ago the core decided the request of r (the
// tap, for a request that the person approved), on the core's monotonic
// clock. A wall clock that is set back does not change it. With no core
// it returns LoginPreapproveTime: the broker then keeps no login (DESIGN.md
// section 21.3).
func (r *Result) SinceTap() time.Duration {
	if r == nil || r.core == nil || r.tap.mono.IsZero() {
		return LoginPreapproveTime
	}
	return max(r.core.clock.Now().Sub(r.tap.mono), 0)
}

// SkippedByReload reports whether StartGrants started nothing because a
// reload came after the core checked the request of r.
func (r *Result) SkippedByReload() bool {
	if r == nil || r.core == nil {
		return false
	}
	r.core.mu.Lock()
	defer r.core.mu.Unlock()
	return r.reloaded
}

// keeps reports whether the grant g of the config old is allowed in the
// same way by the config next.
func keeps(old, next *config.Broker, sameKey func(string) bool, g *grant) bool {
	if !old.SameClient(next, g.client) || len(g.refs) == 0 {
		return false
	}
	for _, r := range g.refs {
		if r.login {
			if !keepsLogin(old, next, r.name, g.client) {
				return false
			}
			continue
		}
		if r.project {
			if !keepsProject(old, next, r, g.client) {
				return false
			}
			continue
		}
		if !r.key {
			if !old.SameSecret(next, r.name, g.client) {
				return false
			}
			continue
		}
		if sameKey == nil || !sameKey(r.name) || !old.SameKey(next, r.name, g.client) {
			return false
		}
		for _, hk := range g.hostKeys {
			if !next.KeyHost(r.name, []byte(hk)) {
				return false
			}
		}
	}
	return true
}
