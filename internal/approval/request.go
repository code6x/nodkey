package approval

import (
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/audit"
)

// Request is one request, after the broker's own checks (DESIGN.md
// sections 5, 6 and 13). The core checks it again against the config.
type Request struct {
	// Client is the client name. It comes only from the client's pinned
	// TLS key.
	Client string
	// Kind says what the request asks for.
	Kind audit.Kind

	// Secrets are the secret names of a KindSecrets request. A name may
	// be there more than once, such as for two variables; it counts once.
	Secrets []string

	// Key is the key name of a KindSSHLogin or KindSSHGrant request.
	Key string
	// HostKey is the host key of a KindSSHLogin request, from the
	// session-bind whose signature the broker has checked.
	HostKey ssh.PublicKey
	// RemoteUser is the remote user name of a KindSSHLogin or KindSSHGrant
	// request.
	RemoteUser string
	// Hosts are the host names of a KindSSHGrant request, as in the
	// broker's known_hosts. A name may be there more than once; it counts
	// once.
	Hosts []string
	// For is how long the grants of a KindSSHGrant request should last
	// (nodkey ssh-grant --for). The core uses whole minutes.
	For time.Duration

	// Uses, NotBefore and NotAfter are the number of uses and the span
	// of a KindPreapprove request, which names its secrets in Secrets, or
	// its key, remote user and hosts in Key, RemoteUser and Hosts. The
	// times are whole seconds. The core checks them against the limits of
	// the config.
	Uses                int
	NotBefore, NotAfter time.Time

	// Windows and TokenHash are for a KindStanding request, which names
	// secrets only. Uses is then the number of uses in each window.
	// TokenHash is the SHA-256 hash of the token that the broker made for
	// the grant (grantkey.Hash); the core never sees the token.
	Windows   []WindowSpec
	TokenHash [32]byte

	// Claim is the claimed text, made safe by the caller (see Claim).
	Claim Claim

	// OnWait, if set, is called once, with the short code, when the
	// request starts to wait for the person: when it goes into the queue
	// or its message is about to be sent. The client prints the code. It
	// must not block for long.
	OnWait func(shortCode string)
}

// WindowSpec is one daily or weekly window of a KindStanding request, in
// the broker's local time. It does not pass midnight: From is before To,
// and To is at most 24 hours.
type WindowSpec struct {
	// Days are the weekdays of a weekly window. Empty means every day.
	Days     []time.Weekday
	From, To time.Duration // time of day
}

// Result is the decision about one request. Anything that is not a clear
// approval is a deny.
type Result struct {
	// RequestID is the request's random ID: 16 bytes in base64url without
	// padding. It is empty only when no ID could be made.
	RequestID string
	// ShortCode is the code for people, such as "k3f9".
	ShortCode string

	// Allowed is true when the broker may hand out the secrets, sign, or,
	// for an SSH grant, call StartGrants.
	Allowed bool
	// Answer is the person's answer, if the person answered.
	Answer audit.Answer
	// UserID is the Telegram user ID that answered.
	UserID int64
	// Channel is "ntfy:TOPIC" for an answer through ntfy, else empty.
	Channel string
	// WindowMinutes is the length of the grants of an approve_window
	// answer.
	WindowMinutes int

	// Cause says why the request was denied. It is empty when Allowed.
	Cause audit.Cause
	// ErrorCode says what failed, when Cause is audit.CauseError.
	ErrorCode audit.Code
	// Err is the error behind audit.CauseError, for the broker's own log.
	Err error

	// Message is the exact text of the message the person saw, if one was
	// sent.
	Message string
	// Subject names the request in audit entries. It holds only names
	// that passed the checks, and claimed text that is one clean line.
	Subject audit.Subject

	// GrantID, GrantFrom and GrantUntil describe the scheduled grant of an
	// approved KindPreapprove request: its ID, and its span in the
	// broker's local time. They are empty for any other result.
	GrantID               string
	GrantFrom, GrantUntil time.Time

	core     *Core
	at       time.Time // when the request was decided, on the wall clock
	plan     *grant    // the scheduled grant of an approved KindPreapprove request
	msg      MessageID // with plan: the message of the request, and its prompt
	prompt   Prompt
	su       *standingUse       // the use path of a standing grant
	usedID   string             // the scheduled grant that allowed the request
	ended    []audit.GrantEnded // entries of grants that this request ended
	vias     []audit.Via        // what allowed each secret or key without a tap
	grants   []grantKey         // the grants of an approve_window answer
	grantEnd moment
	seq      uint64 // the number of the answer (see Core.decisions)
	started  bool   // StartGrants ran; under core.mu
	live     bool   // the scheduled grant started; under core.mu
	stopped  bool   // the scheduled grant did not start: the core had stopped; under core.mu
}

// Events returns the audit entries of the request, in order (DESIGN.md
// section 9). The broker appends each one, and denies the request if one
// cannot be written:
//
//   - first, always, a request entry, with the message text if a message
//     was sent;
//   - if the person answered, a decision entry; after a Deny also a
//     denied entry with cause approver;
//   - if a grant, a "never ask" rule or a scheduled grant allowed it, a
//     grant_used entry for each of the three that was used, with the
//     secrets it covered;
//   - if it was denied without an answer, for cause error an error entry,
//     then a denied entry.
//
// The grant_ended entries of the scheduled grants that this request ended
// (the use that took the last use, or the Deny of the person) come last in
// Events, so they follow the entries above. For an allowed request, the
// broker writes secret_sent or signed later, once it has handed out the
// values or the signature: so for the last use, grant_ended comes after
// grant_used and before secret_sent or signed.
func (r *Result) Events() []audit.Event {
	events := r.mainEvents()
	if r.su != nil && r.su.alarm != "" {
		s := r.Subject
		s.GrantID = r.su.grantID
		events = append(events, audit.GrantAlarm{Subject: s, Cause: r.su.alarm})
	}
	for _, ev := range r.ended {
		events = append(events, ev)
	}
	return events
}

// mainEvents returns the entries of Events but the ends of grants.
func (r *Result) mainEvents() []audit.Event {
	events := []audit.Event{audit.Request{Subject: r.Subject, Message: r.Message}}
	switch {
	case r.Answer != "":
		events = append(events, audit.Decision{
			Subject: r.Subject, UserID: r.UserID, Channel: r.Channel, Answer: r.Answer, WindowMinutes: r.WindowMinutes,
		})
		if !r.Allowed {
			events = append(events, audit.Denied{Subject: r.Subject, Cause: r.Cause})
		}
	case r.Allowed:
		for _, via := range []audit.Via{audit.ViaGrant, audit.ViaNeverRule, audit.ViaScheduled, audit.ViaStanding} {
			used := false
			var secrets []string
			for i, v := range r.vias {
				if v != via {
					continue
				}
				used = true
				if r.Subject.Kind == audit.KindSecrets && i < len(r.Subject.Secrets) {
					secrets = append(secrets, r.Subject.Secrets[i])
				}
			}
			if !used {
				continue
			}
			s := r.Subject
			if s.Kind == audit.KindSecrets {
				s.Secrets = secrets
			}
			gu := audit.GrantUsed{Subject: s, Via: via}
			if via == audit.ViaScheduled || via == audit.ViaStanding {
				gu.GrantID = r.usedID
			}
			if via == audit.ViaStanding {
				gu.NewTokenHash = r.newTokenHash()
			}
			events = append(events, gu)
		}
	default:
		if r.Cause == audit.CauseError && r.ErrorCode != "" {
			events = append(events, audit.Failure{Subject: r.Subject, Code: r.ErrorCode})
		}
		events = append(events, audit.Denied{Subject: r.Subject, Cause: r.Cause})
	}
	return events
}

// GrantStopped reports whether StartGrants started no scheduled grant
// because the core had stopped. Then the request is an error, not a limit.
func (r *Result) GrantStopped() bool {
	if r == nil || r.core == nil {
		return false
	}
	r.core.mu.Lock()
	defer r.core.mu.Unlock()
	return r.stopped
}

// GrantStarted reports whether StartGrants started the scheduled grant of
// an approved KindPreapprove request. It is false before StartGrants, for
// any other result, and when the grant did not start.
func (r *Result) GrantStarted() bool {
	if r == nil || r.core == nil {
		return false
	}
	r.core.mu.Lock()
	defer r.core.mu.Unlock()
	return r.live
}

// StartGrants starts the grants of an "Approve N min" answer, of an
// approved SSH grant, or of an approved scheduled grant (DESIGN.md
// sections 8 and 13). Call it after the decision entry from Events is on
// disk, and before the broker hands out anything. If that entry cannot be
// written, do not call it; the grants then never start. So a grant never
// exists without its record.
//
// The grants end when the answer said: N minutes after the tap, or at the
// end shown in the message of an SSH grant or a scheduled grant, each cut
// to the start of its second, as a message shows a time. Calling
// StartGrants later does not make them last longer. For an SSH grant and a
// scheduled grant, the broker does not call it when the client hung up
// after the tap: the grants are all they give. A grant for a secret or key
// that the person denied after this tap does not start: a Deny ends the
// client's grants for it, also those that have not started yet. A
// scheduled grant also does not start when its client has too many. For
// any other result, and on a second call, StartGrants does nothing.
func (r *Result) StartGrants() {
	if r == nil || r.core == nil || !r.Allowed || (len(r.grants) == 0 && r.plan == nil) {
		return
	}
	c := r.core
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.started {
		return
	}
	r.started = true
	now := c.now()
	if r.plan != nil {
		c.startScheduled(r, now)
		return
	}
	if !now.before(r.grantEnd) {
		return
	}
	c.sweepGrants(now)
	for _, k := range r.grants {
		if c.client(k.client).denied[k.ref] > r.seq {
			continue // a Deny came after the tap
		}
		// A grant of the same scope from a later tap stays as it is.
		c.addWindowGrant(k, r.grantEnd)
	}
}
