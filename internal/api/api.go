// Package api is the protocol between the clients (nodkey run, nodkey
// ssh-agent and nodkey ssh-grant) and the broker (DESIGN.md section 10).
// Both sides use these types, so they agree on every field and every
// limit.
//
// Every request is a POST with a JSON object as its body, on one of the
// paths below. The broker answers 200 with one JSON object, or an error
// status with {"error": "<status text>"} and nothing more. While a request
// waits for the approver, the broker first sends an informational answer,
// 102 Processing, with the short code in the header ShortCodeHeader.
//
// The decoding is strict, on both sides: every field must be there, no
// field may be null, and no other field may be there. Keys must match
// exactly, in lower case. Lists and values have caps (the Max constants);
// a request over a cap is refused.
package api

import (
	"net/http"
	"net/textproto"
	"regexp"
)

// The paths of the broker. Each takes POST only.
const (
	// PathKeys lists the public keys that the client may use (KeysRequest,
	// KeysAnswer). nodkey ssh-agent asks it when ssh asks for the keys.
	PathKeys = "/v1/keys"
	// PathSecrets asks for secrets for one command (SecretsRequest,
	// SecretsAnswer). nodkey run asks it.
	PathSecrets = "/v1/secrets"
	// PathSign asks for one SSH login signature (SignRequest, SignAnswer).
	// nodkey ssh-agent asks it.
	PathSign = "/v1/sign"
	// PathSSHGrant asks for SSH grants for a list of hosts (GrantRequest,
	// GrantAnswer). nodkey ssh-grant asks it.
	PathSSHGrant = "/v1/ssh-grant"
)

// ContentType is the content type of every request and answer body.
const ContentType = "application/json"

// ShortCodeHeader holds the short code of a request, such as "7qd2", in
// the informational answer (102 Processing) that the broker sends when the
// request starts to wait for the approver. The client prints it, so a
// person at the terminal can match it with the message on the phone
// (DESIGN.md section 5). Read it with ShortCode.
const ShortCodeHeader = "Nodkey-Short-Code"

// Caps on a request (DESIGN.md section 10). With them, every valid request
// fits in the 2 MiB that the broker reads (transport.MaxRequestBody); a
// test checks it.
const (
	// MaxText is the most bytes of a claimed text field, such as the
	// reason, that the broker shows (claim.MaxInput). A longer field is
	// not refused, but it is shown and logged only as "[hidden: too long]".
	// The client replaces it with that text before it sends the request.
	MaxText = 64 << 10
	// MaxArgs is the most arguments of one command line. The client
	// replaces a longer command line with one argument "[hidden: too
	// long]". The broker refuses more.
	MaxArgs = 4096
	// MaxCommands is the most command lines of a SignRequest: the command
	// line of ssh and of at most 3 of its parent processes.
	MaxCommands = 4
	// MaxSecrets is the most variables of a SecretsRequest.
	MaxSecrets = 32
	// MaxName is the most bytes of a name: a variable, a secret, a key, a
	// host or a remote user. Valid names are shorter.
	MaxName = 64
	// MaxKey is the most bytes of an SSH public key in SSH wire form. An
	// RSA key of 16384 bits, the largest that OpenSSH accepts, has about
	// 2 KiB.
	MaxKey = 4 << 10
	// MaxData is the most bytes of the data to sign (sshauth.MaxDataLen).
	MaxData = 8 << 10
	// MaxBinds is the most session-bind messages of a SignRequest. The
	// broker accepts exactly one; it refuses two, as for agent
	// forwarding, after it has looked at them.
	MaxBinds = 2
	// MaxBind is the most bytes of one session-bind message
	// (sshauth.MaxBindLen).
	MaxBind = 8 << 10
	// MaxGrantHosts is the most hosts of a GrantRequest
	// (approval.MaxGrantHosts). A host that is listed twice counts twice
	// here.
	MaxGrantHosts = 20
	// MaxKeys is the most keys that one client may use, so that a
	// KeysAnswer stays small. The broker refuses to start with more.
	MaxKeys = 256
)

// Caps on an answer.
const (
	// MaxValue is the most bytes of one secret value that the broker
	// hands out. A longer value is refused, as is a value that the
	// environment of a command cannot hold.
	MaxValue = 64 << 10
	// MaxValues is the most bytes of all the values of one answer
	// together. Linux allows about 2 MiB for the arguments and the
	// environment of a command, so this leaves room for the rest.
	MaxValues = 1 << 20
	// MaxAnswer is the most bytes of an answer body. It holds every valid
	// answer: the values in base64 take 4/3 of MaxValues. A client reads
	// at most this much.
	MaxAnswer = 2 << 20
)

// varPattern is the form of an environment variable name (DESIGN.md
// section 5).
var varPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)

// ValidVar reports whether name is an environment variable name that the
// broker accepts: it matches [A-Z_][A-Z0-9_]{0,63}. The client checks it
// to give a quick error; the broker checks it again.
func ValidVar(name string) bool { return varPattern.MatchString(name) }

// shortCodePattern is the form of a short code: 4 characters from
// 23456789abcdefghjkmnpqrstuvwxyz (DESIGN.md section 7).
var shortCodePattern = regexp.MustCompile(`^[2-9a-hjkmnp-z]{4}$`)

// ValidShortCode reports whether code has the form of a short code, such
// as "7qd2".
func ValidShortCode(code string) bool { return shortCodePattern.MatchString(code) }

// ShortCode returns the short code of an informational answer of the
// broker, with its status and headers, as an HTTP client sees them (for
// example in httptrace.ClientTrace.Got1xxResponse). ok is false for any
// other answer, or a code that does not have the form of a short code.
func ShortCode(status int, h textproto.MIMEHeader) (code string, ok bool) {
	if status != http.StatusProcessing {
		return "", false
	}
	values := h.Values(ShortCodeHeader)
	if len(values) != 1 || !ValidShortCode(values[0]) {
		return "", false
	}
	return values[0], true
}
