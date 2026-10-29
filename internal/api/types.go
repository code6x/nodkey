package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
)

// The requests and the answers. Each type decodes strictly
// (UnmarshalJSON). Most write a nil list as an empty one (MarshalJSON), as
// the other side refuses null. Check checks the caps; UnmarshalJSON calls
// it too, so the broker refuses a request over a cap.

// KeysRequest asks for the public keys that the client may use. It has no
// fields: its body is {}.
type KeysRequest struct{}

// UnmarshalJSON decodes {} strictly.
func (r *KeysRequest) UnmarshalJSON(data []byte) error {
	return decodeObject(data, map[string]field{})
}

// KeysAnswer lists the SSH keys that the client may use, sorted by name:
// at most MaxKeys.
type KeysAnswer struct {
	Keys []Key `json:"keys"`
}

// MarshalJSON writes a nil list as [].
func (a KeysAnswer) MarshalJSON() ([]byte, error) {
	type plain KeysAnswer
	p := plain{Keys: make([]Key, len(a.Keys))}
	for i, k := range a.Keys {
		p.Keys[i] = Key{Name: k.Name, PublicKey: orEmpty(k.PublicKey)}
	}
	return json.Marshal(p)
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (a *KeysAnswer) UnmarshalJSON(data []byte) error {
	var v KeysAnswer
	err := decodeObject(data, map[string]field{
		"keys": list(&v.Keys, MaxKeys, object[Key]()),
	})
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// Key is one SSH key of the broker.
type Key struct {
	// Name is the name of the [key.*] section.
	Name string `json:"name"`
	// PublicKey is the public key in SSH wire form.
	PublicKey []byte `json:"public_key"`
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (k *Key) UnmarshalJSON(data []byte) error {
	var v Key
	err := decodeObject(data, map[string]field{
		"name":       text(&v.Name),
		"public_key": binary(&v.PublicKey),
	})
	if err != nil {
		return err
	}
	if len(v.Name) > MaxName || len(v.PublicKey) > MaxKey {
		return errTooLong
	}
	*k = v
	return nil
}

// SecretsRequest asks for secrets for one command: nodkey run (DESIGN.md
// section 5).
type SecretsRequest struct {
	// Secrets are the variables to set, each with the name of a secret,
	// in the order of --secret. One secret may be there for more than one
	// variable. The broker needs 1 to MaxSecrets of them.
	Secrets []SecretRef `json:"secrets"`
	// Command is the command line that nodkey run starts: the program and
	// its arguments, at most MaxArgs. It is claimed.
	Command []string `json:"command"`
	// Dir is the working directory. It is claimed.
	Dir string `json:"dir"`
	// Reason is the reason from --reason or NODKEY_REASON, or "". It is
	// claimed.
	Reason string `json:"reason"`
}

// Check checks the caps of the request.
func (r *SecretsRequest) Check() error {
	if len(r.Secrets) > MaxSecrets || len(r.Command) > MaxArgs {
		return errTooMany
	}
	for _, s := range r.Secrets {
		if len(s.Var) > MaxName || len(s.Name) > MaxName {
			return errTooLong
		}
	}
	return nil
}

// MarshalJSON writes a nil list as [].
func (r SecretsRequest) MarshalJSON() ([]byte, error) {
	type plain SecretsRequest
	p := plain(r)
	p.Secrets, p.Command = orEmpty(p.Secrets), orEmpty(p.Command)
	return json.Marshal(p)
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (r *SecretsRequest) UnmarshalJSON(data []byte) error {
	var v SecretsRequest
	err := decodeObject(data, map[string]field{
		"secrets": list(&v.Secrets, MaxSecrets, object[SecretRef]()),
		"command": textList(&v.Command, MaxArgs),
		"dir":     text(&v.Dir),
		"reason":  text(&v.Reason),
	})
	if err != nil {
		return err
	}
	if err := v.Check(); err != nil {
		return err
	}
	*r = v
	return nil
}

// SecretRef is one variable of a SecretsRequest.
type SecretRef struct {
	// Var is the environment variable, such as "GH_TOKEN". The broker
	// checks it with ValidVar and DeniedVar. A message shows it as
	// claimed text.
	Var string `json:"var"`
	// Name is the name of a [secret.*] section, such as "github-token".
	Name string `json:"name"`
}

// UnmarshalJSON decodes strictly.
func (s *SecretRef) UnmarshalJSON(data []byte) error {
	var v SecretRef
	err := decodeObject(data, map[string]field{
		"var":  text(&v.Var),
		"name": text(&v.Name),
	})
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// SecretsAnswer holds one value for each variable of the request, in the
// order of the request. The broker writes it with Encode, not with
// encoding/json: json.Marshal would leave a copy of the values in a buffer
// of its pool, which nobody clears.
type SecretsAnswer struct {
	Secrets []SecretValue `json:"secrets"`
	// GrantToken is the new token of a standing grant (DESIGN.md section
	// 8), in the answer to a request with the header GrantTokenHeader, and
	// only there. It is a secret: never print or log it.
	GrantToken string `json:"grant_token"`
}

// Check checks the caps of the answer: at most MaxSecrets values, each at
// most MaxValue bytes, and at most MaxValues bytes together.
func (a *SecretsAnswer) Check() error {
	if len(a.Secrets) > MaxSecrets {
		return errTooMany
	}
	if len(a.GrantToken) > MaxGrantToken {
		return errTooLong
	}
	total := 0
	for _, s := range a.Secrets {
		total += len(s.Value)
		if len(s.Var) > MaxName || len(s.Value) > MaxValue || total > MaxValues {
			return errTooLong
		}
	}
	return nil
}

// MarshalJSON writes no field "grant_token" when there is no token. The
// broker writes the answer with Encode; this is for tests.
func (a SecretsAnswer) MarshalJSON() ([]byte, error) {
	type plain SecretsAnswer
	if a.GrantToken == "" {
		return json.Marshal(struct {
			plain
			GrantToken *struct{} `json:"grant_token,omitempty"`
		}{plain: plain(a)})
	}
	return json.Marshal(plain(a))
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (a *SecretsAnswer) UnmarshalJSON(data []byte) error {
	var v SecretsAnswer
	err := decodeObjectOptional(data, map[string]field{
		"secrets":     list(&v.Secrets, MaxSecrets, object[SecretValue]()),
		"grant_token": text(&v.GrantToken),
	}, map[string]bool{"grant_token": true})
	if err != nil {
		return err
	}
	if err := v.Check(); err != nil {
		v.Clear()
		return err
	}
	*a = v
	return nil
}

// Encode writes the answer as JSON, as json.Marshal would, into a new
// buffer of exactly its size, and returns it. The buffer holds the values
// in base64: the caller must clear it once the answer is written. Encode
// writes the JSON by hand, so that it makes no other copy of the values.
// It checks the caps (Check), and that each variable name is valid
// (ValidVar), so that a name needs no escaping in JSON.
func (a *SecretsAnswer) Encode() ([]byte, error) {
	if err := a.Check(); err != nil {
		return nil, err
	}
	const (
		head  = `{"secrets":[`
		item  = `{"var":"`
		value = `","value":"`
		tail  = `"}`
		end   = `]}`
	)
	const tokenKey = `],"grant_token":"`
	n := len(head) + len(end)
	if a.GrantToken != "" {
		for _, c := range []byte(a.GrantToken) {
			if c != '_' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
				return nil, errBadVar // a token needs no escaping in JSON
			}
		}
		n += len(tokenKey) + len(a.GrantToken) + len(`"}`) - len(end)
	}
	for i, s := range a.Secrets {
		if !ValidVar(s.Var) {
			return nil, errBadVar
		}
		if i > 0 {
			n++ // the comma
		}
		n += len(item) + len(s.Var) + len(value) + base64.StdEncoding.EncodedLen(len(s.Value)) + len(tail)
	}
	// The exact size, so that append never moves the bytes and leaves a
	// copy behind.
	b := make([]byte, 0, n)
	b = append(b, head...)
	for i, s := range a.Secrets {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, item...)
		b = append(b, s.Var...)
		b = append(b, value...)
		b = base64.StdEncoding.AppendEncode(b, s.Value)
		b = append(b, tail...)
	}
	if a.GrantToken != "" {
		b = append(b, tokenKey...)
		b = append(b, a.GrantToken...)
		return append(b, `"}`...), nil
	}
	return append(b, end...), nil
}

// Clear overwrites the values with zeros. Clearing is best effort: the
// decoder and the operating system keep copies that are not cleared.
func (a *SecretsAnswer) Clear() {
	for i := range a.Secrets {
		clear(a.Secrets[i].Value)
	}
}

// String returns a text without the values.
func (a SecretsAnswer) String() string {
	if a.GrantToken != "" {
		return fmt.Sprintf("api.SecretsAnswer{%d values, token hidden}", len(a.Secrets))
	}
	return fmt.Sprintf("api.SecretsAnswer{%d values}", len(a.Secrets))
}

// GoString returns a text without the values.
func (a SecretsAnswer) GoString() string { return a.String() }

// Format writes a text without the values, for every verb.
func (a SecretsAnswer) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// LogValue returns a text without the values, so slog never logs them.
func (a SecretsAnswer) LogValue() slog.Value { return slog.StringValue(a.String()) }

// SecretValue is the value of one variable. It is a secret: fmt and slog
// never show it, and JSON holds it in base64.
type SecretValue struct {
	Var   string `json:"var"`
	Value []byte `json:"value"`
}

// UnmarshalJSON decodes strictly.
func (s *SecretValue) UnmarshalJSON(data []byte) error {
	var v SecretValue
	err := decodeObject(data, map[string]field{
		"var":   text(&v.Var),
		"value": binary(&v.Value),
	})
	if err != nil {
		clear(v.Value)
		return err
	}
	*s = v
	return nil
}

// String returns a text without the value. It leaves out the variable
// name too: the agent chose it.
func (SecretValue) String() string { return "api.SecretValue{[hidden]}" }

// wipe overwrites the value with zeros, for list when a later item fails.
func (s *SecretValue) wipe() { clear(s.Value) }

// GoString returns a text without the value.
func (s SecretValue) GoString() string { return s.String() }

// Format writes a text without the value, for every verb.
func (s SecretValue) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// LogValue returns a text without the value, so slog never logs it.
func (s SecretValue) LogValue() slog.Value { return slog.StringValue(s.String()) }

// SignRequest asks for the signature of one SSH login: nodkey ssh-agent
// (DESIGN.md section 6). The broker checks it with package sshauth.
type SignRequest struct {
	// PublicKey is the key that ssh asked to sign with, in SSH wire form.
	PublicKey []byte `json:"public_key"`
	// Data is the data that ssh asked to sign.
	Data []byte `json:"data"`
	// Flags are the flags of the agent's sign request.
	Flags uint32 `json:"flags"`
	// Binds are the session-bind@openssh.com messages of the agent
	// connection, in order, each without the extension name: at most
	// MaxBinds.
	Binds [][]byte `json:"binds"`
	// Commands are the command lines of ssh and of at most 3 of its parent
	// processes, ssh first. They are claimed.
	Commands [][]string `json:"commands"`
	// Reason is NODKEY_REASON from the environment of ssh, or "". It is
	// claimed.
	Reason string `json:"reason"`
}

// Check checks the caps of the request.
func (r *SignRequest) Check() error {
	if len(r.Binds) > MaxBinds || len(r.Commands) > MaxCommands {
		return errTooMany
	}
	if len(r.PublicKey) > MaxKey || len(r.Data) > MaxData {
		return errTooLong
	}
	for _, b := range r.Binds {
		if len(b) > MaxBind {
			return errTooLong
		}
	}
	for _, c := range r.Commands {
		if len(c) > MaxArgs {
			return errTooMany
		}
	}
	return nil
}

// MarshalJSON writes a nil list as [].
func (r SignRequest) MarshalJSON() ([]byte, error) {
	type plain SignRequest
	p := plain(r)
	p.PublicKey, p.Data = orEmpty(p.PublicKey), orEmpty(p.Data)
	p.Binds = make([][]byte, len(r.Binds))
	for i, b := range r.Binds {
		p.Binds[i] = orEmpty(b)
	}
	p.Commands = make([][]string, len(r.Commands))
	for i, c := range r.Commands {
		p.Commands[i] = orEmpty(c)
	}
	return json.Marshal(p)
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (r *SignRequest) UnmarshalJSON(data []byte) error {
	var v SignRequest
	err := decodeObject(data, map[string]field{
		"public_key": binary(&v.PublicKey),
		"data":       binary(&v.Data),
		"flags":      integer(&v.Flags),
		"binds":      list(&v.Binds, MaxBinds, decodeBinary),
		"commands": list(&v.Commands, MaxCommands, func(raw json.RawMessage, p *[]string) error {
			return decodeTextList(raw, p, MaxArgs)
		}),
		"reason": text(&v.Reason),
	})
	if err != nil {
		return err
	}
	if err := v.Check(); err != nil {
		return err
	}
	*r = v
	return nil
}

// SignAnswer is the signature, for the agent's sign answer.
type SignAnswer struct {
	// Format is the signature algorithm, such as "ssh-ed25519".
	Format string `json:"format"`
	// Blob is the signature.
	Blob []byte `json:"blob"`
}

// MarshalJSON writes a nil blob as "".
func (a SignAnswer) MarshalJSON() ([]byte, error) {
	type plain SignAnswer
	p := plain(a)
	p.Blob = orEmpty(p.Blob)
	return json.Marshal(p)
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (a *SignAnswer) UnmarshalJSON(data []byte) error {
	var v SignAnswer
	err := decodeObject(data, map[string]field{
		"format": text(&v.Format),
		"blob":   binary(&v.Blob),
	})
	if err != nil {
		return err
	}
	if len(v.Format) > MaxName || len(v.Blob) > MaxKey {
		return errTooLong
	}
	*a = v
	return nil
}

// GrantRequest asks for SSH grants: nodkey ssh-grant (DESIGN.md section
// 13).
type GrantRequest struct {
	// Key is the name of a [key.*] section.
	Key string `json:"key"`
	// User is the remote user name.
	User string `json:"user"`
	// Hosts are names in the broker's known_hosts: at most MaxGrantHosts.
	Hosts []string `json:"hosts"`
	// Seconds is how long the grants should last (--for). The broker uses
	// whole minutes, rounded down: at least one, and at most the key's
	// window.
	Seconds int64 `json:"seconds"`
	// Reason is the reason from --reason, or "". It is claimed.
	Reason string `json:"reason"`
}

// Check checks the caps of the request.
func (r *GrantRequest) Check() error {
	if len(r.Hosts) > MaxGrantHosts {
		return errTooMany
	}
	if len(r.Key) > MaxName || len(r.User) > MaxName {
		return errTooLong
	}
	for _, h := range r.Hosts {
		if len(h) > MaxName {
			return errTooLong
		}
	}
	return nil
}

// MarshalJSON writes a nil list as [].
func (r GrantRequest) MarshalJSON() ([]byte, error) {
	type plain GrantRequest
	p := plain(r)
	p.Hosts = orEmpty(p.Hosts)
	return json.Marshal(p)
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (r *GrantRequest) UnmarshalJSON(data []byte) error {
	var v GrantRequest
	err := decodeObject(data, map[string]field{
		"key":     text(&v.Key),
		"user":    text(&v.User),
		"hosts":   textList(&v.Hosts, MaxGrantHosts),
		"seconds": integer(&v.Seconds),
		"reason":  text(&v.Reason),
	})
	if err != nil {
		return err
	}
	if err := v.Check(); err != nil {
		return err
	}
	*r = v
	return nil
}

// GrantAnswer says that the grants were made.
type GrantAnswer struct {
	// Minutes is how long the grants last, from the time of the request.
	Minutes int `json:"minutes"`
}

// UnmarshalJSON decodes strictly.
func (a *GrantAnswer) UnmarshalJSON(data []byte) error {
	var v GrantAnswer
	if err := decodeObject(data, map[string]field{"minutes": integer(&v.Minutes)}); err != nil {
		return err
	}
	*a = v
	return nil
}

// PreapproveRequest asks for a scheduled grant: nodkey preapprove
// (DESIGN.md section 8). It names secrets, or a key with a remote user and
// hosts, as nodkey ssh-grant does.
type PreapproveRequest struct {
	// Secrets are secret names: at most MaxSecrets. Empty for a key.
	Secrets []string `json:"secrets"`
	// Key is the name of a [key.*] section. Empty for secrets.
	Key string `json:"key"`
	// User is the remote user name, for a key.
	User string `json:"user"`
	// Hosts are names in the broker's known_hosts, for a key: at most
	// MaxGrantHosts.
	Hosts []string `json:"hosts"`
	// From and Until are the first moment and the end of the grant, as
	// the person typed them (ParseTime). The broker reads them.
	From  string `json:"from"`
	Until string `json:"until"`
	// Uses is how many uses the grant has. With Windows, it is the uses
	// in each window.
	Uses int64 `json:"uses"`
	// Reason is the reason from --reason, or "". It is claimed.
	Reason string `json:"reason"`
	// Windows makes the request one for a standing grant (DESIGN.md
	// section 8): 1 to MaxWindows windows. Nil for a scheduled grant; then
	// MarshalJSON does not write the field.
	Windows []Window `json:"windows"`
}

// Check checks the caps of the request.
func (r *PreapproveRequest) Check() error {
	if len(r.Secrets) > MaxSecrets || len(r.Hosts) > MaxGrantHosts || len(r.Windows) > MaxWindows {
		return errTooMany
	}
	for i := range r.Windows {
		if err := r.Windows[i].Check(); err != nil {
			return err
		}
	}
	if len(r.Key) > MaxName || len(r.User) > MaxName || len(r.From) > MaxTime || len(r.Until) > MaxTime {
		return errTooLong
	}
	for _, s := range append(append([]string(nil), r.Secrets...), r.Hosts...) {
		if len(s) > MaxName {
			return errTooLong
		}
	}
	return nil
}

// MarshalJSON writes a nil list as [], and no field "windows" for nil
// windows.
func (r PreapproveRequest) MarshalJSON() ([]byte, error) {
	type plain PreapproveRequest
	p := plain(r)
	p.Secrets, p.Hosts = orEmpty(p.Secrets), orEmpty(p.Hosts)
	if r.Windows == nil {
		// The shallower field wins over the one in plain.
		return json.Marshal(struct {
			plain
			Windows *struct{} `json:"windows,omitempty"`
		}{plain: p})
	}
	return json.Marshal(p)
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (r *PreapproveRequest) UnmarshalJSON(data []byte) error {
	var v PreapproveRequest
	err := decodeObjectOptional(data, map[string]field{
		"secrets": textList(&v.Secrets, MaxSecrets),
		"key":     text(&v.Key),
		"user":    text(&v.User),
		"hosts":   textList(&v.Hosts, MaxGrantHosts),
		"from":    text(&v.From),
		"until":   text(&v.Until),
		"uses":    integer(&v.Uses),
		"reason":  text(&v.Reason),
		"windows": list(&v.Windows, MaxWindows, object[Window]()),
	}, map[string]bool{"windows": true})
	if err != nil {
		return err
	}
	if v.Windows != nil && len(v.Windows) == 0 {
		return errType // an empty list of windows is not a request
	}
	if err := v.Check(); err != nil {
		return err
	}
	*r = v
	return nil
}

// PreapproveAnswer says that the scheduled grant was approved.
type PreapproveAnswer struct {
	// ID is the grant ID: 22 characters of base64url. A cancel names it.
	ID string `json:"id"`
	// From and Until are the span of the grant in RFC 3339 form, in the
	// broker's local time.
	From  string `json:"from"`
	Until string `json:"until"`
	// GrantToken is the token of a standing grant, in the answer to
	// a request with windows, and only there. It is a secret: never print
	// or log it. The client checks it with grantkey.Parse.
	GrantToken string `json:"grant_token"`
}

// String returns the answer without the token.
func (a PreapproveAnswer) String() string {
	t := "no token"
	if a.GrantToken != "" {
		t = "token hidden"
	}
	return "PreapproveAnswer{" + a.ID + ", " + a.From + ", " + a.Until + ", " + t + "}"
}

// GoString returns the same text as String.
func (a PreapproveAnswer) GoString() string { return a.String() }

// Format prints the same text as String for every verb.
func (a PreapproveAnswer) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// LogValue returns a text without the token, so slog never logs it.
func (a PreapproveAnswer) LogValue() slog.Value { return slog.StringValue(a.String()) }

// MarshalJSON writes no field "grant_token" when there is no token.
func (a PreapproveAnswer) MarshalJSON() ([]byte, error) {
	type plain PreapproveAnswer
	if a.GrantToken == "" {
		return json.Marshal(struct {
			plain
			GrantToken *struct{} `json:"grant_token,omitempty"`
		}{plain: plain(a)})
	}
	return json.Marshal(plain(a))
}

// MaxGrantToken is the most bytes of GrantToken that the client reads.
// A token is shorter (grantkey.Length).
const MaxGrantToken = 128

// UnmarshalJSON decodes strictly. grant_token may be missing.
func (a *PreapproveAnswer) UnmarshalJSON(data []byte) error {
	var v PreapproveAnswer
	err := decodeObjectOptional(data, map[string]field{
		"id": text(&v.ID), "from": text(&v.From), "until": text(&v.Until), "grant_token": text(&v.GrantToken),
	}, map[string]bool{"grant_token": true})
	if err != nil {
		return err
	}
	if len(v.ID) > MaxName || len(v.From) > MaxTime || len(v.Until) > MaxTime || len(v.GrantToken) > MaxGrantToken {
		return errTooLong
	}
	*a = v
	return nil
}

// PreapproveCancelRequest cancels a scheduled grant that the same client
// has. The broker answers the same for an ID that it does not know and for
// the ID of another client.
type PreapproveCancelRequest struct {
	ID string `json:"id"`
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (r *PreapproveCancelRequest) UnmarshalJSON(data []byte) error {
	var v PreapproveCancelRequest
	if err := decodeObject(data, map[string]field{"id": text(&v.ID)}); err != nil {
		return err
	}
	if len(v.ID) > MaxName {
		return errTooLong
	}
	*r = v
	return nil
}

// PreapproveCancelAnswer says that the grant was cancelled. ID is the ID
// of the request.
type PreapproveCancelAnswer struct {
	ID string `json:"id"`
}

// UnmarshalJSON decodes strictly.
func (a *PreapproveCancelAnswer) UnmarshalJSON(data []byte) error {
	var v PreapproveCancelAnswer
	if err := decodeObject(data, map[string]field{"id": text(&v.ID)}); err != nil {
		return err
	}
	if len(v.ID) > MaxName {
		return errTooLong
	}
	*a = v
	return nil
}

// ErrorAnswer is the body of every answer that is not 200: the status
// text, such as {"error":"Forbidden"}, and nothing else.
type ErrorAnswer struct {
	Error string `json:"error"`
}

// UnmarshalJSON decodes strictly.
func (a *ErrorAnswer) UnmarshalJSON(data []byte) error {
	var v ErrorAnswer
	if err := decodeObject(data, map[string]field{"error": text(&v.Error)}); err != nil {
		return err
	}
	if len(v.Error) > MaxName {
		return errTooLong
	}
	*a = v
	return nil
}

// The kinds of a Window.
const (
	WindowDaily  = "daily"
	WindowWeekly = "weekly"
)

// Weekdays are the day names of a weekly Window, in the order of the week.
var Weekdays = [7]string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

// Window is one daily or weekly window of a standing grant, in the local
// time of the broker. It does not pass midnight: From is before To.
type Window struct {
	// Kind is WindowDaily or WindowWeekly.
	Kind string `json:"kind"`
	// Days are the day names of a weekly window (Weekdays), 1 to 7, each
	// once. Empty for a daily window.
	Days []string `json:"days"`
	// From and To are "HH:MM", 24 hours. To is after From.
	From string `json:"from"`
	To   string `json:"to"`
}

// Check checks the caps and the form of the window.
func (w *Window) Check() error {
	if len(w.Days) > len(Weekdays) {
		return errTooMany
	}
	if len(w.Kind) > MaxName || len(w.From) > MaxTime || len(w.To) > MaxTime {
		return errTooLong
	}
	switch w.Kind {
	case WindowDaily:
		if len(w.Days) != 0 {
			return errBadWindow
		}
	case WindowWeekly:
		if len(w.Days) == 0 {
			return errBadWindow
		}
		seen := make(map[string]bool, len(w.Days))
		for _, d := range w.Days {
			if !slices.Contains(Weekdays[:], d) || seen[d] {
				return errBadWindow
			}
			seen[d] = true
		}
	default:
		return errBadWindow
	}
	from, ok1 := ParseClock(w.From)
	to, ok2 := ParseClock(w.To)
	if !ok1 || !ok2 || from >= to {
		return errBadWindow
	}
	return nil
}

// ParseClock reads "HH:MM" (two digits each, 00:00 to 23:59) and returns
// the minutes since midnight.
func ParseClock(s string) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	for _, i := range []int{0, 1, 3, 4} {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	h, m := int(s[0]-'0')*10+int(s[1]-'0'), int(s[3]-'0')*10+int(s[4]-'0')
	if h > 23 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

// MarshalJSON writes nil days as [].
func (w Window) MarshalJSON() ([]byte, error) {
	type plain Window
	p := plain(w)
	p.Days = orEmpty(p.Days)
	return json.Marshal(p)
}

// UnmarshalJSON decodes strictly, and checks the caps and the form.
func (w *Window) UnmarshalJSON(data []byte) error {
	var v Window
	err := decodeObject(data, map[string]field{
		"kind": text(&v.Kind),
		"days": textList(&v.Days, len(Weekdays)),
		"from": text(&v.From),
		"to":   text(&v.To),
	})
	if err != nil {
		return err
	}
	if err := v.Check(); err != nil {
		return err
	}
	*w = v
	return nil
}
