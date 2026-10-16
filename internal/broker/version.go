package broker

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/version"
)

// versionRetry is the shortest time from a failed try of the notice about
// the version of a client to its next try.
const versionRetry = time.Minute

// versionNote is where the broker is with the notice about the version of
// one client of the config, in this start. Service.mu guards it.
type versionNote struct {
	logged  bool      // the log line about the version is written
	sending bool      // a try runs now
	sent    bool      // a notice went out: no more tries in this start
	failed  time.Time // when the last try failed; zero for none
}

// checkVersion compares the version that client claims in the header of
// its request (api.VersionHeader) with the broker's own version (DESIGN.md
// section 10). Anyone with the client's key can claim any version, so the
// claim decides nothing: it changes no answer, no check and no audit
// entry, and the request never waits for it. A broker that is a build
// from the source compares nothing, and a claim of a build from the
// source is not compared either.
//
// When the claim is missing, or names another release than the broker's,
// the broker writes one log line, once for each client in each start, and
// tries to send one notice (noteVersion). Only a notice that went out
// ends the tries for that client in this start, so a notice that a limit
// stopped, or that Telegram could not take, goes out later. A client has
// at most one try at a time, and the next try after a failed one comes
// with a request of that client at least versionRetry after the failure.
// There is no timer. However many versions a client claims, it gets one
// notice that went out (THREAT-MODEL.md T33), rarely more than one: a
// try can fail after Telegram took the message, and then the next try
// sends it again. The real bound is one try a minute for each client.
//
// A try needs the notice function of Run. So none starts before Run,
// after the approver stopped, or once Close has begun.
func (s *Service) checkVersion(client string, h http.Header) {
	claimed := api.Version(h)
	diff := version.Check(s.version, claimed)
	if diff == version.NoDiff {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.versionNotes[client]
	switch {
	case n == nil || n.sent || n.sending || s.notice == nil || s.closed || s.coreStopped.Load():
		return
	case !n.failed.IsZero() && s.now().Sub(n.failed) < versionRetry:
		return
	}
	n.sending = true
	first := !n.logged
	n.logged = true
	s.bg.Add(1)
	go s.noteVersion(s.notice, n, client, claimed, diff, first)
}

// noteVersion makes one try of the notice about the version that client
// claimed, with notice, and writes the log line about the version first
// when first is set. It runs in a goroutine of its own, so the request
// does not wait for it, and Close waits for it and cancels it. A try that
// fails is only logged, and is noted in n, for the next try. Once Close
// has begun or the approver stopped, no next try comes, and the log line
// says so. claimed is a release version, or "" for none.
func (s *Service) noteVersion(notice NoticeFunc, n *versionNote, client, claimed string, diff version.Diff,
	first bool,
) {
	defer s.bg.Done()
	sent := false
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		n.sending, n.sent = false, sent
		if !sent {
			n.failed = s.now()
		}
	}()
	defer s.recoverGoroutine("sending a notice about a version")
	line, text := versionTexts(client, claimed, s.version, diff)
	if first {
		attrs := []any{slog.String("client", client)}
		if claimed != "" {
			attrs = append(attrs, slog.String("client_version", claimed))
		}
		attrs = append(attrs, slog.String("broker_version", s.version))
		s.log.Warn(line, attrs...)
	}
	ctx, cancel := context.WithTimeout(s.stopCtx, alertTimeout)
	defer cancel()
	if err := notice(ctx, text); err != nil {
		next := "a request of the client a minute later or more tries again"
		if s.stopping() || s.coreStopped.Load() {
			next = "the broker is stopping, so no new try comes"
		}
		s.log.Warn("broker: the notice about the version of a client did not go out; "+next,
			slog.String("client", client), slog.String("error", errorText(err)))
		return
	}
	sent = true
}

// versionTexts returns the log line and the text of the notice about the
// version that client claimed. claimed and own are release versions, so
// they hold only digits and dots; claimed is "" when the client sent no
// version. The client name comes from the config. A client that sends no
// version runs nodkey 0.1, which has no nodkey update: the text points to
// the steps of docs/setup.md instead.
func versionTexts(client, claimed, own string, diff version.Diff) (line, text string) {
	switch diff {
	case version.NotSent:
		return "broker: a client sent no version of nodkey, so it may run an older nodkey; update nodkey there",
			"The client " + client + " sent no version of nodkey, so it may run an older nodkey. The broker " +
				"runs nodkey " + own + ". To update " + client + ", follow section 13 of docs/setup.md."
	case version.OtherOlder:
		return "broker: a client says that it runs an older nodkey than the broker; update nodkey there",
			"The client " + client + " says that it runs nodkey " + claimed + ", which is older than nodkey " +
				own + " on the broker. To update it, run there: sudo nodkey update"
	default: // version.OtherNewer
		return "broker: a client says that it runs a newer nodkey than the broker; update nodkey on the broker host",
			"The client " + client + " says that it runs nodkey " + claimed + ", which is newer than nodkey " +
				own + " on the broker. To update the broker, run as root on the broker host: nodkey update"
	}
}
