package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"time"

	"github.com/code6x/nodkey/internal/version"
)

// Event is the content of one audit entry: what happened. The events are
// the types of this package that have the Event methods, and no others:
// Append refuses any other type, also a type of another package that
// embeds an event to get its methods. So an entry can never hold a field
// that is not listed here, such as a secret value, a signature, or the
// data that was signed (DESIGN.md section 9).
//
// Pass an event as a value, such as audit.Signed{...}, not as a pointer.
type Event interface {
	// eventName returns the value of the entry's "event" field.
	eventName() string
	// validate checks the fields. Append refuses an event that fails.
	validate() error
}

// Kind says what a request asks for.
type Kind string

// The kinds of request (DESIGN.md sections 5, 6 and 13).
const (
	KindSecrets  Kind = "secrets"   // nodkey run: secrets for one command
	KindSSHLogin Kind = "ssh_login" // nodkey ssh-agent: one SSH signature
	KindSSHGrant Kind = "ssh_grant" // nodkey ssh-grant: a pre-approval for listed hosts
	// KindPreapprove is nodkey preapprove: a scheduled grant for later
	// (DESIGN.md section 8).
	KindPreapprove Kind = "preapprove"
)

// Answer is the button the approver pressed.
type Answer string

// The answers (DESIGN.md section 7).
const (
	AnswerApproveOnce   Answer = "approve_once"
	AnswerApproveWindow Answer = "approve_window"
	AnswerDeny          Answer = "deny"
)

// Via says what allowed a request without a tap.
type Via string

// What can allow a request without a tap (DESIGN.md sections 8 and 12).
const (
	ViaGrant     Via = "grant"      // a grant from an "Approve N min" tap or from nodkey ssh-grant
	ViaNeverRule Via = "never_rule" // a rule with ask = "never"
	ViaScheduled Via = "scheduled"  // a scheduled grant from nodkey preapprove
)

// Cause says why a request was denied.
type Cause string

// The causes of a deny.
const (
	CauseApprover   Cause = "approver"    // the approver pressed Deny
	CauseExpired    Cause = "expired"     // no answer in time
	CauseCancelled  Cause = "cancelled"   // the client hung up
	CauseNotAllowed Cause = "not_allowed" // a check failed: an unknown name, a name this client may not use, bad input
	CauseLimit      Cause = "limit"       // a limit per client, the queue, the pause after a Deny, or a limit of the approver itself (DESIGN.md section 8)
	CauseError      Cause = "error"       // a failure; an error entry says which
)

// EndCause says why a scheduled grant ended (DESIGN.md section 8).
type EndCause string

// The causes of a grant_ended entry.
const (
	EndUsedUp    EndCause = "used_up"   // the last use was taken
	EndEnded     EndCause = "ended"     // the end time came
	EndCancelled EndCause = "cancelled" // the client cancelled it
	EndDenied    EndCause = "denied"    // the person denied a later request for it
	EndStopped   EndCause = "stopped"   // the broker stopped
)

// TapCause says why a button press did not count (DESIGN.md section 7).
// It tells a forged button apart from a person's second tap.
type TapCause string

// The causes of a foreign_tap entry.
const (
	TapOtherUser      TapCause = "other_user"      // not from the approver
	TapOtherChat      TapCause = "other_chat"      // not in the private chat with the approver
	TapInlineMessage  TapCause = "inline_message"  // on an inline message
	TapNoMessage      TapCause = "no_message"      // the press names no message
	TapBadData        TapCause = "bad_data"        // the button data is not valid
	TapEditedMessage  TapCause = "edited_message"  // the message is not as the broker sent it: someone else changed it
	TapUnknownRequest TapCause = "unknown_request" // no request waits for an answer on it: a late or second tap, or one from before a restart
	TapExpired        TapCause = "expired"         // its request has expired
	TapWrongMessage   TapCause = "wrong_message"   // not on the message of its request, such as a copy
	TapNotAllowed     TapCause = "not_allowed"     // its request does not offer this button
	TapRefused        TapCause = "refused"         // the approval core refused it for another reason
)

// Code says what failed. It is a fixed code, never an error message,
// because an error message can hold text from a store program or from the
// client.
type Code string

// The codes of a failure.
const (
	CodeStoreFailed    Code = "store_failed"    // a store program failed
	CodeSignFailed     Code = "sign_failed"     // signing failed
	CodeApproverFailed Code = "approver_failed" // the approver could not be asked or told, such as when Telegram is down
	CodePollConflict   Code = "poll_conflict"   // another program polls with the bot token (DESIGN.md section 7)
)

// Subject names one request. Each event about a request holds it, so an
// entry can be read on its own (DESIGN.md section 9).
//
// Command and Reason hold text from the client. RemoteUser is chosen by
// the client too, but it must match a strict pattern. Every other field
// holds checked data: the request ID that the broker made, and names from
// the broker's own config and known_hosts file. A name that failed the
// broker's checks is left out, so a denied request may have no names.
type Subject struct {
	// RequestID is the request's random ID: 16 bytes in base64url without
	// padding (22 characters). It is required.
	RequestID string `json:"request_id,omitempty"`
	// Client is the client name from the config. The broker knows it from
	// the client's pinned TLS key. It is required.
	Client string `json:"client,omitempty"`
	// Kind says what the request asks for. It is required.
	Kind Kind `json:"kind,omitempty"`
	// Secrets are secret names from the config, for KindSecrets.
	Secrets []string `json:"secrets,omitempty"`
	// Key is the key name from the config, for an SSH request.
	Key string `json:"key,omitempty"`
	// Hosts are host names from the broker's known_hosts file: the one host
	// of an SSH login, or the hosts of nodkey ssh-grant.
	Hosts []string `json:"hosts,omitempty"`
	// HostKey is the SHA256 fingerprint of the host key of an SSH login,
	// such as "SHA256:" and 43 base64 characters.
	HostKey string `json:"host_key,omitempty"`
	// RemoteUser is the remote user name of an SSH request. The client
	// chooses it; the broker checks it against the pattern of DESIGN.md
	// section 6.
	RemoteUser string `json:"remote_user,omitempty"`
	// Command is the claimed command line, cleaned and masked as in
	// DESIGN.md section 7. The client writes it; it is not checked.
	Command string `json:"command,omitempty"`
	// Reason is the claimed reason, cleaned and masked as in DESIGN.md
	// section 7. The client writes it; it is not checked.
	Reason string `json:"reason,omitempty"`
	// GrantID is the ID of a scheduled grant: in the entries of a
	// preapprove request that was approved, in grant_used for a use of it
	// and in grant_ended. The broker makes it: 16 random bytes in base64url
	// without padding.
	GrantID string `json:"grant_id,omitempty"`
	// Uses, NotBefore and NotAfter are the number of uses and the time
	// span that a KindPreapprove request asks for. The times are in UTC,
	// in RFC 3339 form, such as "2026-10-28T01:00:00Z".
	Uses      int    `json:"uses,omitempty"`
	NotBefore string `json:"not_before,omitempty"`
	NotAfter  string `json:"not_after,omitempty"`
}

// BrokerStarted is the first entry of each broker run.
type BrokerStarted struct {
	// Version is the nodkey version, such as "1.2.0" or "dev".
	Version string `json:"version"`
}

// BrokerStopped is the last entry of a broker run that ends cleanly.
type BrokerStopped struct{}

// Request records a new request, after the broker's checks.
type Request struct {
	Subject
	// Message is the exact message text the approver saw. Its claimed part
	// is built from text of the client, cleaned and masked as in DESIGN.md
	// section 7. It is empty when no message was sent: a grant or a "never
	// ask" rule allowed the request, or a check denied it first.
	Message string `json:"message,omitempty"`
}

// Decision records the approver's answer. It is on disk before the broker
// fetches a value or signs. It does not show that anything was handed out:
// the request is still denied if a later step fails, even the sync or the
// journal write of this entry. Only SecretSent and Signed show that.
type Decision struct {
	Subject
	// UserID is the Telegram user ID that answered.
	UserID int64 `json:"user_id"`
	// Answer is the button that was pressed.
	Answer Answer `json:"answer"`
	// WindowMinutes is the length of the grant, for AnswerApproveWindow
	// only.
	WindowMinutes int `json:"window_minutes,omitempty"`
}

// GrantUsed records a request that a grant or a "never ask" rule allowed
// without a tap.
type GrantUsed struct {
	Subject
	// Via says what allowed it.
	Via Via `json:"via"`
}

// GrantEnded records the end of a scheduled grant. Subject is that of the
// preapprove request that made the grant, with its GrantID. A grant that
// was never used and ran out has UsesLeft as it asked.
type GrantEnded struct {
	Subject
	// Cause says why it ended.
	Cause EndCause `json:"cause"`
	// UsesLeft is how many uses were left.
	UsesLeft int `json:"uses_left"`
}

// SecretSent records that the broker sent the values of the secrets
// named in Subject. It never holds a value.
type SecretSent struct {
	Subject
}

// Signed records that the broker signed an SSH login. It never holds the
// signature or the data that was signed.
type Signed struct {
	Subject
}

// Denied records the end of a request that was not allowed.
type Denied struct {
	Subject
	// Cause says why.
	Cause Cause `json:"cause"`
}

// ForeignTap records a button press that the broker refused: from another
// user or chat, on another message, or for a request ID that is not
// waiting (DESIGN.md section 7). Cause says which. One press that counted
// is recorded too: a Deny on a message that someone else changed, with
// cause edited_message. Then the entry shows the edit, next to the
// decision entry of the Deny.
type ForeignTap struct {
	// UserID is the Telegram user ID that pressed the button.
	UserID int64 `json:"user_id"`
	// ChatID is the chat of the message.
	ChatID int64 `json:"chat_id"`
	// MessageID is the message with the button.
	MessageID int64 `json:"message_id"`
	// Data is the button data as Telegram sent it, at most 64 bytes.
	// Anyone who has the bot token can write it (THREAT-MODEL.md T6).
	Data string `json:"data"`
	// Cause says why the press did not count, or for a Deny that counted,
	// that someone else changed its message. It is empty only for an
	// approver that does not say why.
	Cause TapCause `json:"cause,omitempty"`
}

// Failure is an "error" entry: something failed. Subject is empty when the
// failure is not about one request.
type Failure struct {
	Subject
	// Code says what failed.
	Code Code `json:"code"`
}

// logRecovered records a torn last line that Open found. Only Open writes
// it, because only Open knows the torn bytes; so it is not exported.
type logRecovered struct {
	// TornLength is the length of the torn bytes.
	TornLength int `json:"torn_length"`
	// TornSHA256 is the SHA-256 of the torn bytes, in hex.
	TornSHA256 string `json:"torn_sha256"`
}

// The values of the "event" field.
const (
	eventBrokerStarted = "broker_started"
	eventBrokerStopped = "broker_stopped"
	eventRequest       = "request"
	eventDecision      = "decision"
	eventGrantUsed     = "grant_used"
	eventGrantEnded    = "grant_ended"
	eventSecretSent    = "secret_sent"
	eventSigned        = "signed"
	eventDenied        = "denied"
	eventForeignTap    = "foreign_tap"
	eventError         = "error"
	eventLogRecovered  = "log_recovered"
)

func (BrokerStarted) eventName() string { return eventBrokerStarted }
func (BrokerStopped) eventName() string { return eventBrokerStopped }
func (Request) eventName() string       { return eventRequest }
func (Decision) eventName() string      { return eventDecision }
func (GrantUsed) eventName() string     { return eventGrantUsed }
func (GrantEnded) eventName() string    { return eventGrantEnded }
func (SecretSent) eventName() string    { return eventSecretSent }
func (Signed) eventName() string        { return eventSigned }
func (Denied) eventName() string        { return eventDenied }
func (ForeignTap) eventName() string    { return eventForeignTap }
func (Failure) eventName() string       { return eventError }
func (logRecovered) eventName() string  { return eventLogRecovered }

// Patterns for the checked fields.
var (
	// requestIDPattern: 16 bytes in base64url without padding.
	requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	// namePattern is the name rule of DESIGN.md section 14, for clients,
	// secrets, keys and known hosts.
	namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	// remoteUserPattern is the rule for remote user names in DESIGN.md
	// section 6.
	remoteUserPattern = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$`)
	// hostKeyPattern is an OpenSSH SHA256 fingerprint.
	hostKeyPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

// maxTapData is the most bytes of button data that Telegram allows.
const maxTapData = 64

// maxWindowMinutes is the longest window: 8 hours (DESIGN.md section 8).
const maxWindowMinutes = 8 * 60

// validate checks a Subject. A request event needs the request ID, the
// client and the kind; a failure may be about no request at all. The
// other fields are optional, but a field that is set must have the form
// of checked data.
func (s *Subject) validate(needRequest bool) error {
	if !needRequest && reflect.ValueOf(*s).IsZero() {
		return nil
	}
	if !requestIDPattern.MatchString(s.RequestID) {
		return errors.New("request_id must be 16 bytes in base64url without padding")
	}
	if !namePattern.MatchString(s.Client) {
		return errors.New("client must be a name from the config")
	}
	switch s.Kind {
	case KindSecrets:
		if s.Key != "" || len(s.Hosts) > 0 || s.HostKey != "" || s.RemoteUser != "" {
			return errors.New("a secrets request has no key, host or remote user")
		}
	case KindSSHLogin:
		if len(s.Secrets) > 0 || len(s.Hosts) > 1 {
			return errors.New("an SSH login has no secret names and at most one host")
		}
	case KindSSHGrant:
		if len(s.Secrets) > 0 || s.HostKey != "" {
			return errors.New("an SSH grant has no secret names and no single host key")
		}
	case KindPreapprove:
		if s.HostKey != "" || (len(s.Secrets) > 0 && s.Key != "") {
			return errors.New("a preapprove request names secrets or one key, not both, and has no single host key")
		}
	default:
		return errors.New("kind is not known")
	}
	if s.Kind != KindPreapprove && (s.Uses != 0 || s.NotBefore != "" || s.NotAfter != "") {
		return errors.New("only a preapprove request has uses and a time span")
	}
	if s.GrantID != "" && !requestIDPattern.MatchString(s.GrantID) {
		return errors.New("grant_id must be 16 bytes in base64url without padding")
	}
	for _, t := range []string{s.NotBefore, s.NotAfter} {
		if t == "" {
			continue
		}
		if _, err := time.Parse(time.RFC3339, t); err != nil {
			return errors.New("not_before and not_after must be times in RFC 3339 form")
		}
	}
	if s.Uses < 0 {
		return errors.New("uses must not be negative")
	}
	for _, name := range s.Secrets {
		if !namePattern.MatchString(name) {
			return errors.New("secrets must be names from the config")
		}
	}
	if s.Key != "" && !namePattern.MatchString(s.Key) {
		return errors.New("key must be a name from the config")
	}
	for _, name := range s.Hosts {
		if !namePattern.MatchString(name) {
			return errors.New("hosts must be names from the broker's known_hosts file")
		}
	}
	if s.HostKey != "" && !hostKeyPattern.MatchString(s.HostKey) {
		return errors.New("host_key must be a SHA256 fingerprint")
	}
	if s.RemoteUser != "" && !remoteUserPattern.MatchString(s.RemoteUser) {
		return errors.New("remote_user does not follow the rule for remote user names")
	}
	return nil
}

func (e BrokerStarted) validate() error {
	if !version.Valid(e.Version) {
		return errors.New("version must be a version such as 1.2.0 or dev")
	}
	return nil
}

func (BrokerStopped) validate() error { return nil }

func (e Request) validate() error    { return e.Subject.validate(true) }
func (e SecretSent) validate() error { return e.Subject.validate(true) }
func (e Signed) validate() error     { return e.Subject.validate(true) }

func (e Decision) validate() error {
	if err := e.Subject.validate(true); err != nil {
		return err
	}
	if e.UserID <= 0 {
		return errors.New("user_id must be a Telegram user ID")
	}
	switch e.Answer {
	case AnswerApproveOnce, AnswerDeny:
		if e.WindowMinutes != 0 {
			return errors.New("window_minutes is only for approve_window")
		}
	case AnswerApproveWindow:
		if e.WindowMinutes < 1 || e.WindowMinutes > maxWindowMinutes {
			return fmt.Errorf("window_minutes must be 1 to %d", maxWindowMinutes)
		}
	default:
		return errors.New("answer is not known")
	}
	return nil
}

func (e GrantUsed) validate() error {
	if err := e.Subject.validate(true); err != nil {
		return err
	}
	switch e.Via {
	case ViaGrant, ViaNeverRule, ViaScheduled:
		return nil
	}
	return errors.New("via is not known")
}

func (e GrantEnded) validate() error {
	if err := e.Subject.validate(true); err != nil {
		return err
	}
	if e.Kind != KindPreapprove || e.GrantID == "" || e.UsesLeft < 0 {
		return errors.New("it needs a preapprove request, a grant_id and a number of uses left")
	}
	switch e.Cause {
	case EndUsedUp, EndEnded, EndCancelled, EndDenied, EndStopped:
		return nil
	}
	return errors.New("cause is not known")
}

func (e Denied) validate() error {
	if err := e.Subject.validate(true); err != nil {
		return err
	}
	switch e.Cause {
	case CauseApprover, CauseExpired, CauseCancelled, CauseNotAllowed, CauseLimit, CauseError:
		return nil
	}
	return errors.New("cause is not known")
}

func (e ForeignTap) validate() error {
	if len(e.Data) > maxTapData {
		return fmt.Errorf("data is longer than %d bytes", maxTapData)
	}
	switch e.Cause {
	case "", TapOtherUser, TapOtherChat, TapInlineMessage, TapNoMessage, TapBadData, TapEditedMessage,
		TapUnknownRequest, TapExpired, TapWrongMessage, TapNotAllowed, TapRefused:
		return nil
	}
	return errors.New("cause is not known")
}

func (e Failure) validate() error {
	if err := e.Subject.validate(false); err != nil {
		return err
	}
	switch e.Code {
	case CodeStoreFailed, CodeSignFailed, CodeApproverFailed, CodePollConflict:
		return nil
	}
	return errors.New("code is not known")
}

func (e logRecovered) validate() error {
	if e.TornLength < 1 || e.TornLength > MaxLineSize || !isHex64(e.TornSHA256) {
		return errors.New("it does not describe a torn line")
	}
	return nil
}

// encodeEvent checks ev and returns its name and its fields as one JSON
// object. An error never holds the value of a field.
func encodeEvent(ev Event) (string, []byte, error) {
	// Only the event types of this package, as values. A type of another
	// package that embeds an event has the Event methods too, but its
	// own fields would go into the entry: a value, or a second "seq". A
	// pointer has the methods as well, and a nil pointer would panic in
	// them.
	switch ev.(type) {
	case BrokerStarted, BrokerStopped, Request, Decision, GrantUsed, GrantEnded, SecretSent, Signed, Denied, ForeignTap, Failure,
		logRecovered:
	default:
		return "", nil, errors.New("not an event of the audit package; pass an event such as audit.Signed{...} as a value")
	}
	name := ev.eventName()
	if err := ev.validate(); err != nil {
		return "", nil, fmt.Errorf("%s entry: %w", name, err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// The message text holds HTML; keep it readable. Newlines and other
	// control characters are always escaped, so no field can break the
	// line.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ev); err != nil {
		return "", nil, fmt.Errorf("%s entry: cannot encode it", name)
	}
	return name, bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
