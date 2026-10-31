package ntfy

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/claim"
)

// This file makes the plain text of each message, with the same lines as
// on Telegram (DESIGN.md section 7). The title is the first line:
//
//	🔐 SSH login · request k3f9
//
// and the message has the rest:
//
//	✅ machine: laptop
//	✅ key: deploy
//	✅ host: web-1 (host key SHA256:pX2c…)
//	✅ remote user: deploy
//	— claimed by the agent —
//	command: ssh deploy@web-1 ← ansible-playbook site.yml
//	expires 14:03:10 (90 s)
//
// ntfy shows no Markdown here: the message is sent as plain text.

const (
	// maxMessageBytes is the longest message text. ntfy sends a message
	// over 4,096 bytes as an attachment, which the approver never does.
	maxMessageBytes = 4096
	// lastLineRoom is the room that a message keeps for its last lines:
	// the expiry, or the result after the request ended.
	lastLineRoom = 300
	clockFormat  = "15:04:05"
	// dateTimeFormat shows a date and a time, for a scheduled grant.
	dateTimeFormat = "2006-01-02 15:04:05 MST"
	claimedHead    = "— claimed by the agent —"
)

var (
	namePattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	remoteUserPattern = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$`)
	hostKeyPattern    = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	shortCodePattern  = regexp.MustCompile(`^[2-9a-hjkmnp-z]{4}$`)
	windowPattern     = regexp.MustCompile(`^(daily|(mon|tue|wed|thu|fri|sat|sun)(,(mon|tue|wed|thu|fri|sat|sun)){0,6}) ([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]$`)
)

// validRequestID reports whether id is a request ID: 16 bytes in
// base64url without padding, in the one canonical form.
func validRequestID(id string) bool {
	if len(id) != 22 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(id)
	return err == nil && len(b) == 16
}

func allNames(names []string, pattern *regexp.Regexp) bool {
	for _, n := range names {
		if !pattern.MatchString(n) {
			return false
		}
	}
	return true
}

// checkPrompt checks the fields of p that the message shows, so that it
// cannot show more or other than it should. The core made p; this is a
// cheap second check. notice is true for the prompt of Notify.
func checkPrompt(p approval.Prompt, notice bool) error {
	bad := func(what string) error { return errors.New("ntfy: the prompt is not valid: " + what) }
	switch {
	case !validRequestID(p.RequestID):
		return bad("the request ID")
	case !shortCodePattern.MatchString(p.ShortCode):
		return bad("the short code")
	case !namePattern.MatchString(p.Client):
		return bad("the client name")
	case !allNames(p.Secrets, namePattern), !allNames(p.Hosts, namePattern), !allNames(p.Windows, windowPattern):
		return bad("a name")
	case p.Key != "" && !namePattern.MatchString(p.Key):
		return bad("the key")
	case p.RemoteUser != "" && !remoteUserPattern.MatchString(p.RemoteUser):
		return bad("the remote user")
	case p.HostKey != "" && !hostKeyPattern.MatchString(p.HostKey):
		return bad("the host key")
	case p.GrantID != "" && !validRequestID(p.GrantID):
		return bad("the grant ID")
	case p.WindowMinutes < 0 || p.Uses < 0 || p.UsesLeft < 0:
		return bad("a number")
	}
	switch p.Kind {
	case audit.KindSecrets:
		if len(p.Secrets) == 0 {
			return bad("no secrets")
		}
	case audit.KindSSHLogin:
		if len(p.Hosts) != 1 || p.Key == "" || p.HostKey == "" || p.RemoteUser == "" {
			return bad("the fields of an SSH login")
		}
	case audit.KindSSHGrant:
		if len(p.Hosts) == 0 || p.Key == "" || p.RemoteUser == "" || p.GrantEnds.IsZero() {
			return bad("the fields of an SSH grant")
		}
	case audit.KindPreapprove, audit.KindStanding:
		if p.Uses < 1 || p.From.IsZero() || !p.From.Before(p.Until) {
			return bad("the fields of a scheduled grant")
		}
		if len(p.Secrets) == 0 && (p.Key == "" || len(p.Hosts) == 0 || p.RemoteUser == "") {
			return bad("the fields of a scheduled grant")
		}
	default:
		return bad("the kind")
	}
	if notice {
		if p.Once || p.WindowMinutes != 0 {
			return bad("a notice has buttons")
		}
		return nil
	}
	if p.Expires.IsZero() || p.TimeLeft <= 0 {
		return bad("the expiry")
	}
	return nil
}

// title returns the first line of a message or a notice of p.
func title(p approval.Prompt, notice bool) string {
	icon, name := "🔑", "Secrets"
	switch p.Kind {
	case audit.KindSSHLogin:
		icon, name = "🔐", "SSH login"
	case audit.KindSSHGrant:
		icon, name = "🔐", "SSH grant"
	case audit.KindPreapprove:
		icon, name = "🗓", "Pre-approval"
	case audit.KindStanding:
		icon, name = "🗓", "Standing grant"
	}
	if notice {
		icon = "🔔"
	}
	return icon + " " + name + " · request " + p.ShortCode
}

// caps are the most runes of each claimed field. When a message does not
// fit, the caps are halved, down to minCommandCap.
type caps struct{ vars, command, dir, reason int }

var fullCaps = caps{vars: 200, command: 1000, dir: 300, reason: 500}

const minCommandCap = 60

// errTooLong: the verified part alone is too long for one message.
var errTooLong = errors.New("ntfy: the message does not fit in one ntfy message, even with short claimed fields")

// claimedValue returns the claimed field s masked and as one clean line.
// The caller did this already; it is a cheap second check.
func claimedValue(s string, limit int) string {
	return claim.Line(claim.Mask(s), limit)
}

// body returns the verified and the claimed lines of p, with the claimed
// fields cut to c.
func body(p approval.Prompt, notice bool, c caps) string {
	var b strings.Builder
	line := func(s string) {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s)
	}
	if notice {
		switch {
		case p.GrantID != "":
			line("not used: grant " + p.GrantID + " ended with " + strconv.Itoa(p.UsesLeft) + " of " +
				strconv.Itoa(p.Uses) + " uses left")
		case p.Via == audit.ViaStanding:
			line("allowed by a standing grant, without a tap")
		case p.Via == audit.ViaScheduled:
			line("allowed by a scheduled grant, without a tap")
		default:
			line(`allowed by a "never ask" rule, without a tap`)
		}
	}
	verified := func(label, value string) { line("✅ " + label + ": " + value) }
	verified("machine", p.Client)
	if len(p.Secrets) > 0 {
		verified("secrets", strings.Join(p.Secrets, ", "))
	}
	if p.Key != "" {
		verified("key", p.Key)
	}
	switch {
	case p.Kind == audit.KindSSHLogin:
		verified("host", p.Hosts[0]+" (host key "+p.HostKey[:len("SHA256:")+4]+"…)")
	case len(p.Hosts) > 0:
		verified("hosts", strings.Join(p.Hosts, ", "))
	}
	if p.RemoteUser != "" {
		verified("remote user", p.RemoteUser)
	}
	switch p.Kind {
	case audit.KindSSHGrant:
		verified("grants end", p.GrantEnds.Format(clockFormat)+" ("+strconv.Itoa(p.WindowMinutes)+" min)")
	case audit.KindPreapprove:
		verified("uses", strconv.Itoa(p.Uses))
		verified("from", p.From.Format(dateTimeFormat))
		verified("until", p.Until.Format(dateTimeFormat))
	case audit.KindStanding:
		for _, w := range p.Windows {
			verified("window", w)
		}
		verified("uses in each window", strconv.Itoa(p.Uses))
		verified("from", p.From.Format(dateTimeFormat))
		verified("until", p.Until.Format(dateTimeFormat))
		line("A Deny of other requests does not end this grant. Use Revoke to end it.")
	}
	fields := []struct {
		label, value string
		limit        int
	}{
		{"as", p.Claim.Vars, c.vars},
		{"command", p.Claim.Command, c.command},
		{"in", p.Claim.Dir, c.dir},
		{"reason", p.Claim.Reason, c.reason},
	}
	head := false
	for _, f := range fields {
		v := claimedValue(f.value, f.limit)
		if v == "" {
			continue
		}
		if !head {
			line(claimedHead)
			head = true
		}
		line(f.label + ": " + v)
	}
	return b.String()
}

// fitBodyWith returns the body of p in at most limit bytes, and, if fits is
// not nil, so that fits says yes (it checks the whole publish body). It cuts the
// claimed fields shorter as needed, never the verified ones: the person
// must see every name they approve.
func fitBodyWith(p approval.Prompt, notice bool, limit int, fits func(string) bool) (string, error) {
	for c := fullCaps; c.command >= minCommandCap; c = c.half() {
		if s := body(p, notice, c); len(s) <= limit && (fits == nil || fits(s)) {
			return s, nil
		}
	}
	return "", errTooLong
}

// expiryLine is the last line of a message that waits for an answer.
func expiryLine(p approval.Prompt) string {
	secs := int64(p.TimeLeft.Round(time.Second) / time.Second)
	return "expires " + p.Expires.Format(clockFormat) + " (" + strconv.FormatInt(secs, 10) + " s)"
}

// buttonLabels returns the labels of the buttons of p, in order, with
// their actions.
func buttonLabels(p approval.Prompt) ([]string, []audit.Answer) {
	var labels []string
	var actions []audit.Answer
	if p.Once {
		label := "Approve once"
		if p.Kind.IsPreapprove() {
			label = "Approve"
		}
		labels, actions = append(labels, label), append(actions, audit.AnswerApproveOnce)
	}
	if p.WindowMinutes > 0 {
		label := "Approve " + strconv.Itoa(p.WindowMinutes) + " min"
		if p.Kind == audit.KindSSHGrant {
			label = "Approve"
		}
		labels, actions = append(labels, label), append(actions, audit.AnswerApproveWindow)
	}
	return append(labels, "Deny"), append(actions, audit.AnswerDeny)
}

// buttonsLine shows labels as one line, as DESIGN.md section 7 does.
func buttonsLine(labels []string) string {
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = "[ " + l + " ]"
	}
	return strings.Join(parts, " ")
}

// endingBody returns the message of p after its request ended: the same
// lines, with the result instead of the expiry.
//
// fits says whether a whole message text may be published; see fitBodyWith.
func endingBody(p approval.Prompt, e approval.Ending, fits func(string) bool) string {
	last := "\n" + resultLine(p, e)
	var s string
	if checkPrompt(p, false) == nil {
		s, _ = fitBodyWith(p, false, maxMessageBytes-lastLineRoom, func(b string) bool { return fits(b + last) })
	}
	if s == "" {
		s = "This request has ended."
	}
	return s + last
}

// resultLine says how the request of p ended (DESIGN.md section 7).
func resultLine(p approval.Prompt, e approval.Ending) string {
	at := e.At.Format(clockFormat)
	if e.GrantEnd != "" {
		approved := resultLine(p, approval.Ending{Answer: e.Answer, At: e.Approved})
		return approved + "\n" + grantEndLine(p, e)
	}
	switch e.Answer {
	case audit.AnswerApproveOnce:
		switch p.Kind {
		case audit.KindStanding:
			return "👍 approved by you at " + at + ", for " + strconv.Itoa(p.Uses) + " use(s) in each window until " +
				p.Until.Format(dateTimeFormat)
		case audit.KindPreapprove:
			return "👍 approved by you at " + at + ", for " + strconv.Itoa(p.Uses) + " use(s) until " +
				p.Until.Format(dateTimeFormat)
		}
		return "👍 approved once by you at " + at
	case audit.AnswerApproveWindow:
		if p.Kind == audit.KindSSHGrant {
			return "👍 approved by you at " + at + ", until " + p.GrantEnds.Format(clockFormat)
		}
		return "👍 approved for " + strconv.Itoa(e.WindowMinutes) + " min by you at " + at
	case audit.AnswerDeny:
		return "⛔ denied by you at " + at
	}
	switch e.Cause {
	case audit.CauseExpired:
		return "⌛ expired — denied"
	case audit.CauseCancelled:
		return "⛔ cancelled by the client"
	case audit.CauseError:
		return "⛔ denied: the broker stopped taking answers"
	}
	return "⛔ denied"
}

// grantEndLine says how and when the scheduled grant of p ended.
func grantEndLine(p approval.Prompt, e approval.Ending) string {
	at := e.At.Format(dateTimeFormat)
	left := " with " + strconv.Itoa(e.UsesLeft) + " use(s) left"
	if p.Kind == audit.KindStanding {
		left = ""
	}
	switch e.GrantEnd {
	case audit.EndUsedUp:
		return "✅ all " + strconv.Itoa(p.Uses) + " use(s) used; the grant ended at " + at
	case audit.EndEnded:
		return "⌛ ended at " + at + left
	case audit.EndCancelled:
		return "⛔ cancelled by the client at " + at + left
	case audit.EndDenied:
		return "⛔ ended by a later Deny at " + at + left
	case audit.EndRevoked:
		return "⛔ revoked by you at " + at + left
	case audit.EndAlarm:
		return "🚨 ended by an alarm at " + at
	case audit.EndRenewed:
		return "🔁 renewed at " + at + "; a new grant replaced this one"
	}
	return "⛔ dropped: the broker stopped at " + at + left
}

// cutBytes cuts s to at most limit bytes, at the start of a character,
// with "…" at the end when it cuts.
func cutBytes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	n := limit - len("…")
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func (c caps) half() caps {
	return caps{vars: c.vars / 2, command: c.command / 2, dir: c.dir / 2, reason: c.reason / 2}
}
