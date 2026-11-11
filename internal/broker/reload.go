package broker

import (
	"bytes"
	"errors"
	"log/slog"
	"maps"
	"net/http"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/sshauth"
)

// ErrNotRecorded is the error of Reload when the new config is in use, but
// its config_reloaded entry could not be written.
var ErrNotRecorded = errors.New("broker: the new config is in use, but its config_reloaded entry is not in the " +
	"audit log; check the disk and the journal")

// Reload makes cfg and keys the config and the keys of the Service, and
// of the core of Run (DESIGN.md section 14, "Reload"). nodkey broker loads
// them as at the start, and checks them with config.Broker.ReloadFixed.
// Reload checks that they fit the stores of the Service, which a reload
// cannot change, as New does. On an error nothing changes.
//
// The core ends every grant that the new config does not allow in the same
// way (approval.Core.Reload). A request that started before the reload is
// checked again before it hands out a value or signs (stillAllowed). Then
// Reload writes a config_reloaded entry with sum, the SHA-256 of the new
// config file in hex. It returns how many grants ended.
//
// The caller must change the clients of the server (transport.Server.
// SetClients) before it calls Reload, so a removed client has no new
// request by then.
func (s *Service) Reload(cfg *config.Broker, keys map[string]sshauth.Key, sum string) (int, error) {
	if cfg == nil {
		return 0, errors.New("broker: Reload needs the config")
	}
	if err := checkStores(cfg, s.stores); err != nil {
		return 0, err
	}
	keysOf, err := checkKeys(cfg, keys)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	core, closed := s.core, s.closed
	s.mu.Unlock()
	if core == nil || closed || s.coreStopped.Load() {
		return 0, errors.New("broker: the service does not run, so it cannot take a new config")
	}
	old := s.view()
	next := &view{cfg: cfg, keys: maps.Clone(keys), keysOf: keysOf}
	s.addClients(cfg)
	// The core first: its grants that the new config takes away end before
	// any request sees the new config. A request that takes the old view
	// after this is checked again against the new one (stillAllowed).
	ended := core.Reload(cfg, func(name string) bool { return sameKey(old, next, name) })
	s.cur.Store(next)
	if _, err := s.append(audit.ConfigReloaded{ConfigSHA256: sum, GrantsEnded: ended}); err != nil {
		// The new config is in use already; the failed write is logged,
		// and after audit.ErrBroken every request is denied.
		return ended, ErrNotRecorded
	}
	return ended, nil
}

// cfgOrNil returns the config of v, or nil for no view.
func (v *view) cfgOrNil() *config.Broker {
	if v == nil {
		return nil
	}
	return v.cfg
}

// sameKey reports whether the [key.*] section name holds the same public
// key in both views.
func sameKey(old, next *view, name string) bool {
	a, ok1 := old.keys[name]
	b, ok2 := next.keys[name]
	return ok1 && ok2 && a.PublicKey() != nil && b.PublicKey() != nil &&
		bytes.Equal(a.PublicKey().Marshal(), b.PublicKey().Marshal())
}

// stillAllowed checks, before a value is fetched or a login signed, and
// again before the answer, that no reload since the start of the request
// took away what it uses: the client and the pin of its key, each of the
// secrets, or the key and the host (hostKey in SSH wire form). It compares
// the config of now with the config of the start of the request (rq.v)
// and with the config that the core decided with (decided). When the
// request may not go on, it is denied (cause not_allowed, 403) and the
// broker logs why; it reports false.
func (rq *request) stillAllowed(decided *config.Broker, secrets []string, key string, hostKey []byte) bool {
	cur := rq.s.view()
	ok := rq.v != nil && decided != nil && rq.hasPin
	if ok {
		c, known := cur.cfg.Clients[rq.client]
		ok = known && c.Pin == rq.pin
	}
	for _, from := range []*config.Broker{rq.v.cfgOrNil(), decided} {
		if !ok || from == cur.cfg {
			continue
		}
		ok = from.SameClient(cur.cfg, rq.client)
		for _, name := range secrets {
			ok = ok && from.SameSecret(cur.cfg, name, rq.client)
		}
		if key != "" {
			ok = ok && from.SameKey(cur.cfg, key, rq.client) && cur.cfg.KeyHost(key, hostKey)
		}
	}
	if ok && key != "" && rq.v != cur {
		ok = sameKey(rq.v, cur, key)
	}
	if ok {
		return true
	}
	rq.s.log.Warn("broker: a reload of the config took away what an approved request uses; the request is denied",
		slog.String("request_id", rq.sub.RequestID), slog.String("client", rq.client))
	rq.ended = true
	_, _ = rq.s.append(audit.Denied{Subject: rq.sub, Cause: audit.CauseNotAllowed})
	rq.answer(http.StatusForbidden)
	return false
}
