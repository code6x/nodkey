package broker

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/version"
)

// securityInfo is the newest security release that one lookup of the
// broker's check found.
type securityInfo struct {
	newest version.Release
	gen    uint64 // its round of notices (SetSecurity)
}

// securityNote is where the broker is with the notice about a security
// release for one client of the config. Service.mu guards it.
type securityNote struct {
	sending bool      // a try runs now
	sentGen uint64    // the round whose notice went out; 0 for none
	failed  time.Time // when the last try failed; zero for none
}

// securityRound is the shortest time from one round of notices about a
// security release to the next one for the same release. It is a bit
// shorter than the 24 hours between two checks that worked, so the next
// daily check starts the next round. A check that comes sooner, such as
// one after a failed notice of the broker, starts none.
const securityRound = 23 * time.Hour

// SetSecurity sets the newest security release that the broker's check
// found, with ok set, or none with ok false (release.Check.OnSecurity).
// The broker then puts it in the header api.SecurityUpdateHeader of each
// answer to a client that claims an older release (checkSecurity).
//
// A call starts a new round of notices for another release than the last
// round's, or for the same one securityRound after its last round: so the
// daily check gives one round a day. Each older client gets at most one
// notice in a round. A call with ok false starts none, so a false answer
// of GitHub that comes and goes does not start more rounds.
func (s *Service) SetSecurity(newest version.Release, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ok {
		s.security.Store(nil)
		return
	}
	now := s.now()
	if s.securityGen == 0 || newest != s.securityNewest || now.Sub(s.securityAt) >= securityRound {
		s.securityGen++
		s.securityNewest, s.securityAt = newest, now
	}
	s.security.Store(&securityInfo{newest: newest, gen: s.securityGen})
}

// checkSecurity sets the header api.SecurityUpdateHeader of the answer w
// when the check found a security release that is newer than the release
// that client claims in h, the header of its request (DESIGN.md section
// 10). The claim and the flag are hints: they change no answer, no check
// and no audit entry, and the request never waits for them.
//
// A claim that is not a release, such as none or "dev", gets no header
// and no notice: it cannot be compared, and such a client could not read
// the header anyway. nodkey before 0.2 sends no version, and gets the
// notice about its version instead (version.go). A false claim of a newer
// release hides only the flag of that client.
//
// For an older client, the broker also tries to send one notice that
// names it, once in each round (SetSecurity), with the same tries as the
// notice about the version: one try at a time, and the next try after a
// failed one comes with a request of that client at least versionRetry
// later. The notice has no sound: the broker's own security notice has
// one, so a false answer of GitHub makes the phone ring at most once a
// day (THREAT-MODEL.md T34).
func (s *Service) checkSecurity(client string, w, h http.Header) {
	sec := s.security.Load()
	if sec == nil {
		return
	}
	claimed, ok := version.ParseRelease(api.Version(h))
	if !ok || claimed.Compare(sec.newest) >= 0 {
		return
	}
	w.Set(api.SecurityUpdateHeader, sec.newest.String())
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.securityNotes[client]
	switch {
	case n == nil || n.sentGen == sec.gen || n.sending || s.notice == nil || s.closed || s.coreStopped.Load():
		return
	case !n.failed.IsZero() && s.now().Sub(n.failed) < versionRetry:
		return
	}
	n.sending = true
	s.bg.Add(1)
	go s.noteSecurity(s.notice, n, client, claimed, *sec)
}

// noteSecurity makes one try of the notice that client, which claims the
// release claimed, is older than the security release of sec. It runs in
// a goroutine of its own, as noteVersion does.
func (s *Service) noteSecurity(notice NoticeFunc, n *securityNote, client string, claimed version.Release,
	sec securityInfo,
) {
	defer s.bg.Done()
	sent := false
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		n.sending = false
		if sent {
			n.sentGen = sec.gen
		} else {
			n.failed = s.now()
		}
	}()
	defer s.recoverGoroutine("sending a notice about a security release")
	ctx, cancel := context.WithTimeout(s.stopCtx, alertTimeout)
	defer cancel()
	if err := notice(ctx, securityText(client, claimed, sec.newest)); err != nil {
		next := "a request of the client a minute later or more tries again"
		if s.stopping() || s.coreStopped.Load() {
			next = "the broker is stopping, so no new try comes"
		}
		s.log.Warn("broker: the notice about a security release for a client did not go out; "+next,
			slog.String("client", client), slog.String("error", errorText(err)))
		return
	}
	sent = true
	s.log.Warn("broker: a client says that it runs a nodkey older than a security release; update nodkey there",
		slog.String("client", client), slog.String("client_version", claimed.String()),
		slog.String("newest_security", sec.newest.String()))
}

// securityText returns the text of the notice that client, which claims
// the release claimed, is older than the security release newest. The
// client name comes from the config, and the versions are release
// versions, which hold only digits and dots.
func securityText(client string, claimed, newest version.Release) string {
	return "SECURITY UPDATE: the client " + client + " says that it runs nodkey " + claimed.String() +
		", which is older than nodkey " + newest.String() + ", a security release. This flag comes from " +
		"GitHub's answer and is not checked: read the checked notes with nodkey update --notes. To update " +
		client + ", run there as root: nodkey update. This notice comes again after the next daily check " +
		"while " + client + " runs an older nodkey."
}
