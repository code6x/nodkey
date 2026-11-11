package broker

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// TestStillAllowed: before a value goes out, the request needs the pin
// that the config of now has for its client, and its secret must be the
// same from the config of its start and from the config that the core
// decided with, to the config of now. Each failure is a deny with 403 and
// an entry.
func TestStillAllowed(t *testing.T) {
	e := newEnv(t, envOptions{})
	cfg := e.svc.view().cfg
	pin := cfg.Clients["laptop"].Pin
	otherItem := *cfg
	otherItem.Secrets = maps.Clone(cfg.Secrets)
	s := otherItem.Secrets["github-token"]
	s.ID = "00000000-0000-4000-8000-0000000000ff"
	otherItem.Secrets["github-token"] = s
	for _, c := range []struct {
		name    string
		hasPin  bool
		pin     config.Pin
		decided *config.Broker
		want    bool
	}{
		{"all the same", true, pin, cfg, true},
		{"no pin from the server", false, pin, cfg, false},
		{"another pin", true, config.Pin{7}, cfg, false},
		{"no decided config", true, pin, nil, false},
		{"the core decided with another item", true, pin, &otherItem, false},
	} {
		w := httptest.NewRecorder()
		rq := &request{s: e.svc, v: e.svc.view(), w: w, client: "laptop", kind: audit.KindSecrets,
			hasPin: c.hasPin, pin: c.pin}
		if got := rq.stillAllowed(c.decided, []string{"github-token"}, "", nil); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		if !c.want && w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", c.name, w.Code)
		}
	}
}
