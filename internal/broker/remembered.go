package broker

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/code6x/nodkey/internal/store"
)

// The login of a one-use login pre-approval (DESIGN.md section 21.3).
//
// When the person approves "nodkey preapprove --login", the broker
// fetches the item once, checks it, and keeps it in memory with the grant
// of the pre-approval. The login that uses the pre-approval is answered
// from memory, with no run of bw: on a slow host, bw cannot sync and get
// an item in the time that agent-browser waits. The broker keeps the
// login until its use, the end of the grant, LoginPreapproveTime after
// the tap, a reload that changes [logins.*], or the stop: never longer.

// maxRememberedLogins is the most logins that the broker keeps for login
// pre-approvals, of all clients. One more pre-approval is denied (limit).
const maxRememberedLogins = 64

// slowStoreStep is the time after which a run of a store program is
// logged at info level, not only at debug level: a store this slow can
// make a login miss the time limit of agent-browser.
const slowStoreStep = 2 * time.Second

// rememberedLogin is the login that the broker fetched at the tap of a
// login pre-approval. Service.logins.mu guards it.
type rememberedLogin struct {
	client, item, origin string
	// from is the store the login came from.
	from string
	// sel is what the checks found at the tap.
	sel loginSel
	// login holds the password and the TOTP seed: the broker's own copy,
	// cleared when the entry goes.
	login store.Login
	// end is LoginPreapproveTime after the tap.
	end   time.Time
	timer *time.Timer
}

// rememberedMeta is what a request may see of a remembered login before
// it uses it: no password and no seed.
type rememberedMeta struct {
	from string
	sel  loginSel
}

// copyLogin returns a copy of l with its own bytes: clearing one does not
// clear the other.
func copyLogin(l store.Login) store.Login {
	out := store.Login{LoginItem: l.LoginItem}
	out.URIs = slices.Clone(l.URIs)
	out.Collections = slices.Clone(l.Collections)
	out.Password = store.NewValue(bytes.Clone(l.Password.Bytes()))
	if b := l.TOTP.Bytes(); len(b) > 0 {
		out.TOTP = store.NewValue(bytes.Clone(b))
	}
	return out
}

// dropLocked removes the entry id and clears its login. The caller holds
// s.logins.mu.
func (s *Service) dropLocked(id string) {
	r, ok := s.logins.remembered[id]
	if !ok {
		return
	}
	delete(s.logins.remembered, id)
	if r.timer != nil {
		r.timer.Stop()
	}
	r.login.Clear()
}

// sweepLocked drops every entry whose end has come. The caller holds
// s.logins.mu.
func (s *Service) sweepLocked(now time.Time) {
	for id, r := range s.logins.remembered {
		if !now.Before(r.end) {
			s.dropLocked(id)
		}
	}
}

// notKept says why remember kept nothing; "" when it kept the login.
type notKept string

const (
	keptNothingStop = notKept("the broker stops")
	keptNothingLate = notKept("the store took longer than the 60 seconds of the pre-approval; " +
		"see docs/agent-browser.md, \"A slow store\"")
	keptNothingFull = notKept("the broker keeps the most logins of pre-approvals that it may; " +
		"use the pre-approvals that wait, or wait a minute")
)

// remember keeps the login l of the pre-approval grant id. It keeps
// nothing, and says why, when the broker stops, when the end has come, or
// when it keeps maxRememberedLogins already. The caller clears its own l
// in every case: remember keeps a copy.
func (s *Service) remember(id string, r rememberedLogin, l store.Login) notKept {
	now := s.nowTime()
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	if s.logins.remembered == nil {
		s.logins.remembered = make(map[string]*rememberedLogin)
	}
	s.sweepLocked(now)
	switch {
	case s.stopping() || s.coreStopped.Load() || id == "":
		return keptNothingStop
	case !now.Before(r.end):
		return keptNothingLate
	case len(s.logins.remembered) >= maxRememberedLogins:
		return keptNothingFull
	}
	s.dropLocked(id)
	e := &r
	e.login = copyLogin(l)
	s.logins.remembered[id] = e
	// The real clock clears the entry at its end, also when no request
	// comes after it.
	e.timer = time.AfterFunc(r.end.Sub(now), func() {
		s.logins.mu.Lock()
		defer s.logins.mu.Unlock()
		if s.logins.remembered[id] == e {
			s.dropLocked(id)
		}
	})
	return ""
}

// rememberedFor returns what the checks found at the tap of a remembered
// login of client for item at origin, if one is kept now.
func (s *Service) rememberedFor(client, item, origin string) (rememberedMeta, bool) {
	now := s.nowTime()
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	s.sweepLocked(now)
	for _, r := range s.logins.remembered {
		if r.client == client && r.item == item && r.origin == origin {
			return rememberedMeta{from: r.from, sel: r.sel}, true
		}
	}
	return rememberedMeta{}, false
}

// takeLogin takes the remembered login of the grant id, if it is for
// client, item and origin and its end has not come. The entry is gone
// after, in every case: a pre-approval covers one login. The caller must
// clear the login.
func (s *Service) takeLogin(id, client, item, origin string) (store.Login, bool) {
	now := s.nowTime()
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	r, ok := s.logins.remembered[id]
	if !ok {
		return store.Login{}, false
	}
	delete(s.logins.remembered, id)
	if r.timer != nil {
		r.timer.Stop()
	}
	if r.client != client || r.item != item || r.origin != origin || !now.Before(r.end) {
		r.login.Clear()
		return store.Login{}, false
	}
	return r.login, true
}

// forgetLogin drops the remembered login of the grant id, if there is one.
func (s *Service) forgetLogin(id string) {
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	s.dropLocked(id)
}

// forgetLogins drops every remembered login: at a reload that changes
// [logins.*], and at the stop.
func (s *Service) forgetLogins() {
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	for id := range s.logins.remembered {
		s.dropLocked(id)
	}
}

// rememberedCount returns how many logins the broker keeps now.
func (s *Service) rememberedCount() int {
	s.logins.mu.Lock()
	defer s.logins.mu.Unlock()
	return len(s.logins.remembered)
}

// timeSteps returns ctx with a store.StepTimer that logs each run of a
// store program of the request of client: at debug level, and at info
// level when it was slow (slowStoreStep). The line names the store and
// the step, never an argument or a value.
func (s *Service) timeSteps(ctx context.Context, client string) context.Context {
	return store.WithStepTimer(ctx, func(name, step string, took time.Duration, failed bool) {
		level := slog.LevelDebug
		msg := "broker: a store step ended"
		if took >= slowStoreStep {
			level = slog.LevelInfo
			msg = "broker: a store step was slow; a website login may then take too long for agent-browser; " +
				"see docs/agent-browser.md, \"A slow store\""
		}
		s.log.Log(ctx, level, msg, slog.String("client", client), slog.String("store", name),
			slog.String("step", step), slog.Duration("took", took), slog.Bool("failed", failed))
	})
}
