package telegram

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
	"github.com/code6x/nodkey/internal/config"
)

// This file makes the text of each message (DESIGN.md section 7):
//
//	🔐 SSH login · request k3f9
//	✅ machine: laptop
//	✅ key: deploy
//	✅ host: web-1 (host key SHA256:pX2c…)
//	✅ remote user: deploy
//	— claimed by the agent —
//	command: ssh deploy@web-1 ← ansible-playbook site.yml
//	reason: apply the nginx fix
//	expires 14:03:10 (90 s)
//	[ Approve once ] [ Approve 15 min ] [ Deny ]
//
// The verified lines come first and start with "✅". The claimed lines
// come after the "claimed by the agent" line, each in a code font. All
// text is HTML-escaped, also text that the caller made safe already.

const (
	// maxTextUnits is the longest message text that Telegram takes: 4096
	// characters after the HTML is parsed. They are counted here in UTF-16
	// code units, which is never fewer.
	maxTextUnits = 4096
	// lastLineRoom is the room that a message keeps for its last line:
	// the expiry, or the result after the request ended.
	lastLineRoom = 100
	// maxAlertUnits is the longest alert text.
	maxAlertUnits = 3000
	// clockFormat shows a time of day in the broker's local time.
	clockFormat = "15:04:05"
	// dateTimeFormat shows a date and a time of day in the broker's local
	// time, with the zone, for a scheduled grant.
	dateTimeFormat = "2006-01-02 15:04:05 MST"
)

// claimedHead is the line before the claimed lines.
const claimedHead = "— claimed by the agent —"

// The second line of a notice of a "never ask" use, and of a use of a
// scheduled grant.
const (
	noticeLine          = `allowed by a "never ask" rule, without a tap`
	scheduledNoticeLine = `allowed by a scheduled grant, without a tap`
	// standingDenyLine is in the message of a standing grant. A Deny of
	// another request does not end the grant (DESIGN.md section 8).
	standingDenyLine = `A Deny of other requests does not end this grant. Use Revoke to end it.`
)

// maxWindowMinutes is the longest "Approve N min" (DESIGN.md section 8).
const maxWindowMinutes = int(config.MaxWindow / time.Minute)

// Patterns for the checked fields of a prompt, as in package audit.
var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	// windowPattern is the form of a window of a standing grant, as
	// the core shows it: "daily 03:00-05:00" or "mon,thu 03:00-05:00".
	windowPattern     = regexp.MustCompile(`^(daily|(mon|tue|wed|thu|fri|sat|sun)(,(mon|tue|wed|thu|fri|sat|sun)){0,6}) ([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]$`)
	remoteUserPattern = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$`)
	hostKeyPattern    = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	// shortCodePattern: 4 characters of 23456789abcdefghjkmnpqrstuvwxyz.
	shortCodePattern = regexp.MustCompile(`^[2-9a-hjkmnp-z]{4}$`)
)

// requestIDLen is the length of a request ID: 16 bytes in base64url
// without padding.
const requestIDLen = 22

// The button data: a prefix and the request ID (DESIGN.md section 7).
const (
	dataOnce   = "o:"
	dataWindow = "w:"
	dataDeny   = "d:"
	// dataRevoke is the Revoke button of a scheduled grant. It carries the
	// ID of the request that made the grant.
	dataRevoke = "r:"
	dataLen    = 2 + requestIDLen
)

// validRequestID reports whether id is a request ID: 22 characters of
// base64url that decode to 16 bytes, in the one canonical form.
func validRequestID(id string) bool {
	if len(id) != requestIDLen {
		return false
	}
	for i := range len(id) {
		if !isBase64URL(id[i]) {
			return false
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(id)
	return err == nil && len(b) == 16
}

// isBase64URL reports whether c is in the base64url alphabet.
func isBase64URL(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// parseData reads button data strictly: "o:", "w:", "d:" or "r:", and a
// request ID. Anything else is not valid.
func parseData(data string) (audit.Answer, string, bool) {
	if len(data) != dataLen {
		return "", "", false
	}
	var action audit.Answer
	switch data[:2] {
	case dataOnce:
		action = audit.AnswerApproveOnce
	case dataWindow:
		action = audit.AnswerApproveWindow
	case dataDeny:
		action = audit.AnswerDeny
	case dataRevoke:
		action = audit.AnswerRevoke
	default:
		return "", "", false
	}
	id := data[2:]
	if !validRequestID(id) {
		return "", "", false
	}
	return action, id, true
}

// messageID names the message msgID in the chat chatID, as
// "CHAT:MESSAGE". The core compares the whole value, so a tap counts only
// on the same message in the same chat.
func messageID(chatID, msgID int64) approval.MessageID {
	return approval.MessageID(strconv.FormatInt(chatID, 10) + ":" + strconv.FormatInt(msgID, 10))
}

// parseMessageID reads a value of messageID. It takes only the form that
// messageID makes.
func parseMessageID(m approval.MessageID) (chatID, msgID int64, ok bool) {
	c, n, found := strings.Cut(string(m), ":")
	if !found {
		return 0, 0, false
	}
	chatID, err1 := strconv.ParseInt(c, 10, 64)
	msgID, err2 := strconv.ParseInt(n, 10, 64)
	if err1 != nil || err2 != nil || chatID == 0 || msgID <= 0 || messageID(chatID, msgID) != m {
		return 0, 0, false
	}
	return chatID, msgID, true
}

// text is a message text in two forms: HTML for Telegram, and the plain
// text that the person sees.
type text struct {
	html, plain strings.Builder
}

// write adds s. The HTML form gets it escaped.
func (t *text) write(s string) {
	t.html.WriteString(claim.HTML(s))
	t.plain.WriteString(s)
}

// code adds s in a code font.
func (t *text) code(s string) {
	t.html.WriteString("<code>")
	t.write(s)
	t.html.WriteString("</code>")
}

// units returns the length of the text that the person sees, in UTF-16
// code units.
func (t *text) units() int { return utf16Len(t.plain.String()) }

// utf16Len returns the length of s in UTF-16 code units.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// cutUnits cuts s to at most limit UTF-16 code units, with "…" at the
// end when it cuts (limit >= 1).
func cutUnits(s string, limit int) string {
	if utf16Len(s) <= limit {
		return s
	}
	n := 0
	for i, r := range s {
		u := 1
		if r >= 0x10000 {
			u = 2
		}
		if n+u > limit-1 {
			return strings.TrimRight(s[:i], " ") + "…"
		}
		n += u
	}
	return s
}

// caps are the most UTF-16 code units of each claimed field in a message.
// A field is cut to its cap, with "…" at the end. When a message does not
// fit even so, the caps are halved, down to minCommandCap.
type caps struct{ vars, command, dir, reason int }

var fullCaps = caps{vars: 200, command: 1000, dir: 300, reason: 500}

// minCommandCap is the smallest cap of the command.
const minCommandCap = 60

func (c caps) half() caps {
	return caps{vars: c.vars / 2, command: c.command / 2, dir: c.dir / 2, reason: c.reason / 2}
}

// errTooLong: the verified part alone is too long for one message.
var errTooLong = errors.New("telegram: the message does not fit in one Telegram message, even with short claimed fields")

// checkPrompt checks that p is a prompt the core makes, so that the
// message cannot show more or other than it should. notice is true for
// the prompt of Notify.
func checkPrompt(p approval.Prompt, notice bool) error {
	bad := func(what string) error { return errors.New("telegram: the prompt is not valid: " + what) }
	switch {
	case !validRequestID(p.RequestID):
		return bad("the request ID")
	case !shortCodePattern.MatchString(p.ShortCode):
		return bad("the short code")
	case !namePattern.MatchString(p.Client):
		return bad("the client name")
	}
	if !p.Kind.IsPreapprove() && (p.Uses != 0 || !p.From.IsZero() || !p.Until.IsZero() ||
		p.GrantID != "" || p.UsesLeft != 0) {
		return bad("a span of uses outside a scheduled grant")
	}
	if p.Kind != audit.KindStanding && len(p.Windows) != 0 {
		return bad("windows outside a standing grant")
	}
	switch {
	case notice && p.Via != "" && p.Via != audit.ViaScheduled, !notice && p.Via != "":
		return bad("the via")
	}
	switch p.Kind {
	case audit.KindSecrets:
		if len(p.Secrets) == 0 || !allNames(p.Secrets) || p.Key != "" || len(p.Hosts) != 0 || p.HostKey != "" ||
			p.RemoteUser != "" || !p.GrantEnds.IsZero() {
			return bad("the fields of a secrets request")
		}
	case audit.KindSSHLogin:
		if len(p.Secrets) != 0 || !namePattern.MatchString(p.Key) || len(p.Hosts) != 1 || !allNames(p.Hosts) ||
			!hostKeyPattern.MatchString(p.HostKey) || !remoteUserPattern.MatchString(p.RemoteUser) || !p.GrantEnds.IsZero() {
			return bad("the fields of an SSH login")
		}
	case audit.KindSSHGrant:
		if notice || len(p.Secrets) != 0 || !namePattern.MatchString(p.Key) || len(p.Hosts) == 0 ||
			len(p.Hosts) > approval.MaxGrantHosts || !allNames(p.Hosts) || p.HostKey != "" ||
			!remoteUserPattern.MatchString(p.RemoteUser) || p.GrantEnds.IsZero() || p.Once || p.WindowMinutes < 1 {
			return bad("the fields of an SSH grant")
		}
	case audit.KindPreapprove:
		named := len(p.Secrets) > 0 && allNames(p.Secrets) && p.Key == "" && len(p.Hosts) == 0 && p.RemoteUser == ""
		keyed := len(p.Secrets) == 0 && namePattern.MatchString(p.Key) && len(p.Hosts) > 0 &&
			len(p.Hosts) <= approval.MaxGrantHosts && allNames(p.Hosts) && remoteUserPattern.MatchString(p.RemoteUser)
		if (!named && !keyed) || p.HostKey != "" || !p.GrantEnds.IsZero() || p.WindowMinutes != 0 ||
			p.Uses < 1 || p.From.IsZero() || !p.From.Before(p.Until) || p.Via != "" {
			return bad("the fields of a scheduled grant")
		}
		// The notice that a grant ended with uses left names the grant;
		// the message of the request does not.
		if notice != validRequestID(p.GrantID) || (notice && (p.UsesLeft < 1 || p.UsesLeft > p.Uses)) ||
			(!notice && (p.GrantID != "" || p.UsesLeft != 0 || !p.Once)) {
			return bad("the fields of a scheduled grant")
		}
	case audit.KindStanding:
		if notice || len(p.Secrets) == 0 || !allNames(p.Secrets) || p.Key != "" || len(p.Hosts) != 0 ||
			p.RemoteUser != "" || p.HostKey != "" || !p.GrantEnds.IsZero() || p.WindowMinutes != 0 ||
			p.Uses < 1 || p.From.IsZero() || !p.From.Before(p.Until) || p.Via != "" ||
			p.GrantID != "" || p.UsesLeft != 0 || !p.Once || len(p.Windows) < 1 ||
			len(p.Windows) > approval.MaxStandingWindows {
			return bad("the fields of a standing grant")
		}
		for _, w := range p.Windows {
			if !windowPattern.MatchString(w) {
				return bad("a window")
			}
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
	if p.WindowMinutes < 0 || p.WindowMinutes > maxWindowMinutes {
		return bad("the window")
	}
	return nil
}

func allNames(names []string) bool {
	for _, n := range names {
		if !namePattern.MatchString(n) {
			return false
		}
	}
	return true
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

// shortHostKey shows a host key fingerprint as DESIGN.md section 7 does:
// "SHA256:" and its first 4 characters, then "…". The host name before it
// is what the broker checked.
func shortHostKey(fp string) string {
	const keep = len("SHA256:") + 4
	return fp[:keep] + "…"
}

// claimedValue returns the claimed field s masked and as one clean line,
// not cut yet. The caller made it safe with package claim already: it
// masked it, and made it one clean line. This is done again as a cheap
// extra check, so the message never depends on the caller. Mask comes
// before Line, as package claim says.
func claimedValue(s string) string {
	m := claim.Mask(s)
	return claim.Line(m, utf8.RuneCountInString(m)+1)
}

// claimedValues are the claimed fields of a prompt, made with
// claimedValue: Vars, Command, Dir and Reason.
type claimedValues [4]string

func claimedOf(p approval.Prompt) claimedValues {
	return claimedValues{
		claimedValue(p.Claim.Vars), claimedValue(p.Claim.Command),
		claimedValue(p.Claim.Dir), claimedValue(p.Claim.Reason),
	}
}

// body writes the title, the verified lines and the claimed lines of p,
// which checkPrompt passed. cv are the claimed fields of p; they are cut
// to c.
func body(p approval.Prompt, notice bool, cv claimedValues, c caps) *text {
	t := &text{}
	t.write(title(p, notice))
	if notice {
		if p.Kind == audit.KindPreapprove {
			t.write("\nnot used: grant " + p.GrantID + " ended with " + strconv.Itoa(p.UsesLeft) + " of " +
				strconv.Itoa(p.Uses) + " uses left")
		} else if p.Via == audit.ViaScheduled {
			t.write("\n" + scheduledNoticeLine)
		} else {
			t.write("\n" + noticeLine)
		}
	}
	verified := func(label, value string) { t.write("\n✅ " + label + ": " + value) }
	verified("machine", p.Client)
	switch p.Kind {
	case audit.KindSecrets:
		verified("secrets", strings.Join(p.Secrets, ", "))
	case audit.KindSSHLogin:
		verified("key", p.Key)
		verified("host", p.Hosts[0]+" (host key "+shortHostKey(p.HostKey)+")")
		verified("remote user", p.RemoteUser)
	case audit.KindSSHGrant:
		verified("key", p.Key)
		verified("hosts", strings.Join(p.Hosts, ", "))
		verified("remote user", p.RemoteUser)
		verified("grants end", p.GrantEnds.Format(clockFormat)+" ("+strconv.Itoa(p.WindowMinutes)+" min)")
	case audit.KindPreapprove:
		if len(p.Secrets) > 0 {
			verified("secrets", strings.Join(p.Secrets, ", "))
		} else {
			verified("key", p.Key)
			verified("hosts", strings.Join(p.Hosts, ", "))
			verified("remote user", p.RemoteUser)
		}
		verified("uses", strconv.Itoa(p.Uses))
		verified("from", p.From.Format(dateTimeFormat))
		verified("until", p.Until.Format(dateTimeFormat))
	case audit.KindStanding:
		verified("secrets", strings.Join(p.Secrets, ", "))
		for _, w := range p.Windows {
			verified("window", w)
		}
		verified("uses in each window", strconv.Itoa(p.Uses))
		verified("from", p.From.Format(dateTimeFormat))
		verified("until", p.Until.Format(dateTimeFormat))
		t.write("\n" + standingDenyLine)
	}
	fields := []struct {
		label, value string
		limit        int
	}{
		{"as", cv[0], c.vars},
		{"command", cv[1], c.command},
		{"in", cv[2], c.dir},
		{"reason", cv[3], c.reason},
	}
	head := false
	for _, f := range fields {
		v := cutUnits(f.value, f.limit)
		if v == "" {
			continue
		}
		if !head {
			t.write("\n" + claimedHead)
			head = true
		}
		t.write("\n" + f.label + ": ")
		t.code(v)
	}
	return t
}

// fitBody returns the body of p that is at most limit UTF-16 code units
// long. It cuts the claimed fields shorter as needed, never the verified
// ones: the person must see every name they approve.
func fitBody(p approval.Prompt, notice bool, limit int) (*text, error) {
	cv := claimedOf(p)
	for c := fullCaps; c.command >= minCommandCap; c = c.half() {
		if t := body(p, notice, cv, c); t.units() <= limit {
			return t, nil
		}
	}
	return nil, errTooLong
}

// keyboard returns the buttons of p: "Approve once" if p allows it,
// "Approve N min" if p allows it ("Approve" for an SSH grant, whose grants
// end at a fixed time), and always "Deny".
func keyboard(p approval.Prompt) inlineKeyboard {
	var row []inlineButton
	if p.Once {
		label := "Approve once"
		if p.Kind.IsPreapprove() {
			label = "Approve"
		}
		row = append(row, inlineButton{Text: label, CallbackData: dataOnce + p.RequestID})
	}
	if p.WindowMinutes > 0 {
		label := "Approve " + strconv.Itoa(p.WindowMinutes) + " min"
		if p.Kind == audit.KindSSHGrant {
			label = "Approve"
		}
		row = append(row, inlineButton{Text: label, CallbackData: dataWindow + p.RequestID})
	}
	row = append(row, inlineButton{Text: "Deny", CallbackData: dataDeny + p.RequestID})
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{row}}
}

// revokeKeyboard returns the one Revoke button of the message of a
// scheduled grant.
func revokeKeyboard(p approval.Prompt) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: revokeData(p.RequestID)}
}

// revokeData returns the rows of the Revoke button of the request id.
func revokeData(id string) [][]inlineButton {
	return [][]inlineButton{{{Text: "Revoke", CallbackData: dataRevoke + id}}}
}

// buttonsLine shows the buttons of k as one line of text, as DESIGN.md
// section 7 does: "[ Approve once ] [ Deny ]".
func buttonsLine(k inlineKeyboard) string {
	var parts []string
	for _, row := range k.InlineKeyboard {
		for _, b := range row {
			parts = append(parts, "[ "+b.Text+" ]")
		}
	}
	return strings.Join(parts, " ")
}

// expiryLine is the last line of a message that waits for an answer.
func expiryLine(p approval.Prompt) string {
	secs := int64(p.TimeLeft.Round(time.Second) / time.Second)
	return "expires " + p.Expires.Format(clockFormat) + " (" + strconv.FormatInt(secs, 10) + " s)"
}

// bodyLimit is the most UTF-16 code units of the body of the message of
// p. The last lines need room: one, or for a scheduled grant two, because
// its message ends with the line of its approval and the line of its end.
func bodyLimit(p approval.Prompt) int {
	if p.Kind.IsPreapprove() {
		return maxTextUnits - 2*lastLineRoom
	}
	return maxTextUnits - lastLineRoom
}

// promptMessage returns the message that Ask sends for p: its text and
// its buttons.
func promptMessage(p approval.Prompt) (*text, inlineKeyboard, error) {
	if err := checkPrompt(p, false); err != nil {
		return nil, inlineKeyboard{}, err
	}
	t, err := fitBody(p, false, bodyLimit(p))
	if err != nil {
		return nil, inlineKeyboard{}, err
	}
	t.write("\n" + expiryLine(p))
	return t, keyboard(p), nil
}

// endingText returns the text of the message of p after its request
// ended: the lines of the message, with the result instead of the expiry.
func endingText(p approval.Prompt, e approval.Ending) *text {
	var t *text
	if checkPrompt(p, false) == nil {
		t, _ = fitBody(p, false, bodyLimit(p))
	}
	if t == nil {
		// Ask could not have sent a message for p. Show the result anyway.
		t = &text{}
		t.write("This request has ended.")
	}
	t.write("\n" + resultLine(p, e))
	return t
}

// resultLine says how the request of p ended (DESIGN.md section 7).
func resultLine(p approval.Prompt, e approval.Ending) string {
	at := e.At.Format(clockFormat)
	if e.GrantEnd != "" {
		return grantEndLines(p, e)
	}
	switch e.Answer {
	case audit.AnswerApproveOnce:
		if p.Kind == audit.KindStanding {
			return "👍 approved by you at " + at + ", for " + strconv.Itoa(p.Uses) + " use(s) in each window until " +
				p.Until.Format(dateTimeFormat)
		}
		if p.Kind == audit.KindPreapprove {
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

// grantEndLines says how and when the scheduled grant of p ended: the
// line of its approval, then the line of its end.
func grantEndLines(p approval.Prompt, e approval.Ending) string {
	approved := resultLine(p, approval.Ending{Answer: e.Answer, At: e.Approved})
	at := e.At.Format(dateTimeFormat)
	var end string
	if p.Kind == audit.KindStanding {
		return approved + "\n" + standingEndLine(e.GrantEnd, at)
	}
	switch e.GrantEnd {
	case audit.EndUsedUp:
		end = "✅ all " + strconv.Itoa(p.Uses) + " use(s) used; the grant ended at " + at
	case audit.EndEnded:
		end = "⌛ ended at " + at + " with " + strconv.Itoa(e.UsesLeft) + " of " + strconv.Itoa(p.Uses) + " use(s) left"
	case audit.EndCancelled:
		end = "⛔ cancelled by the client at " + at + ", with " + strconv.Itoa(e.UsesLeft) + " use(s) left"
	case audit.EndDenied:
		end = "⛔ ended by a later Deny at " + at + ", with " + strconv.Itoa(e.UsesLeft) + " use(s) left"
	case audit.EndRevoked:
		end = "⛔ revoked by you at " + at + ", with " + strconv.Itoa(e.UsesLeft) + " use(s) left"
	default: // audit.EndStopped
		end = "⛔ dropped: the broker stopped at " + at + ", with " + strconv.Itoa(e.UsesLeft) + " use(s) left"
	}
	return approved + "\n" + end
}

// noticeText returns the text of the notice of a "never ask" use.
func noticeText(p approval.Prompt) (*text, error) {
	if err := checkPrompt(p, true); err != nil {
		return nil, err
	}
	return fitBody(p, true, maxTextUnits)
}

// standingEndLine says how and when a standing grant ended. It has no
// uses left to show: it counts its uses in each window.
func standingEndLine(cause audit.EndCause, at string) string {
	switch cause {
	case audit.EndEnded:
		return "⌛ ended at " + at
	case audit.EndRevoked:
		return "⛔ revoked by you at " + at
	case audit.EndAlarm:
		return "🚨 ended by an alarm at " + at
	case audit.EndRenewed:
		return "🔁 renewed at " + at + "; a new grant replaced this one"
	case audit.EndStopped:
		return "⛔ dropped: the broker stopped at " + at
	}
	return "⛔ ended at " + at
}
