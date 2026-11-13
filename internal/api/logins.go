package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// The paths of website logins (DESIGN.md section 21). Each takes POST only.
const (
	// PathLoginList lists the logins that match a page (ListLoginsRequest,
	// ListLoginsAnswer). There is no tap. nodkey asks it for the browser
	// plugin of #104.
	PathLoginList = "/v1/logins/list"
	// PathLogin asks for the username and the password of one login
	// (LoginRequest, LoginAnswer). It needs a tap, a grant or a
	// pre-approval.
	PathLogin = "/v1/logins/login"
	// PathLoginTOTP asks for the current TOTP code of a login
	// (TOTPRequest, TOTPAnswer).
	PathLoginTOTP = "/v1/logins/totp"
)

// Caps of the website login requests and answers.
const (
	// MaxURL is the most bytes of a page URL (loginmatch.MaxURL).
	MaxURL = 2048
	// MaxLoginText is the most bytes of an item name or a user name in an
	// answer (the limit of the bw store).
	MaxLoginText = 1024
	// MaxLoginEntries is the most items of a ListLoginsAnswer (the limit
	// of the bw store).
	MaxLoginEntries = 500
	// MaxItemID is the most bytes of an item ID.
	MaxItemID = 36
	// MaxTOTPCode is the most bytes of a TOTP code.
	MaxTOTPCode = 8
)

// ListLoginsRequest asks which logins match a page.
type ListLoginsRequest struct {
	// URL is the page URL. It is claimed (THREAT-MODEL.md T43).
	URL string `json:"url"`
}

// Check checks the caps of the request.
func (r *ListLoginsRequest) Check() error {
	if len(r.URL) > MaxURL {
		return errTooLong
	}
	return nil
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (r *ListLoginsRequest) UnmarshalJSON(data []byte) error {
	var v ListLoginsRequest
	if err := decodeObject(data, map[string]field{"url": text(&v.URL)}); err != nil {
		return err
	}
	if err := v.Check(); err != nil {
		return err
	}
	*r = v
	return nil
}

// LoginEntry is one login in a ListLoginsAnswer. It holds no password and
// no TOTP seed.
type LoginEntry struct {
	// Logins is the name of the [logins.*] section.
	Logins string `json:"logins"`
	// ID is the item ID.
	ID string `json:"id"`
	// Name and Username are from the vault.
	Name     string `json:"name"`
	Username string `json:"username"`
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (e *LoginEntry) UnmarshalJSON(data []byte) error {
	var v LoginEntry
	err := decodeObject(data, map[string]field{
		"logins": text(&v.Logins), "id": text(&v.ID), "name": text(&v.Name), "username": text(&v.Username),
	})
	if err != nil {
		return err
	}
	if len(v.Logins) > MaxName || len(v.ID) > MaxItemID || len(v.Name) > MaxLoginText || len(v.Username) > MaxLoginText {
		return errTooLong
	}
	*e = v
	return nil
}

// ListLoginsAnswer lists the logins that match the page.
type ListLoginsAnswer struct {
	Logins []LoginEntry `json:"logins"`
}

// MarshalJSON writes a nil list as [].
func (a ListLoginsAnswer) MarshalJSON() ([]byte, error) {
	type plain ListLoginsAnswer
	p := plain{Logins: orEmpty(a.Logins)}
	if len(p.Logins) > MaxLoginEntries {
		return nil, errTooMany
	}
	return json.Marshal(p)
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (a *ListLoginsAnswer) UnmarshalJSON(data []byte) error {
	var v ListLoginsAnswer
	if err := decodeObject(data, map[string]field{
		"logins": list(&v.Logins, MaxLoginEntries, object[LoginEntry]()),
	}); err != nil {
		return err
	}
	*a = v
	return nil
}

// LoginRequest asks for one login.
type LoginRequest struct {
	// URL is the page URL. It is claimed.
	URL string `json:"url"`
	// Item is an item ID from the list.
	Item string `json:"item"`
}

// Check checks the caps of the request.
func (r *LoginRequest) Check() error {
	if len(r.URL) > MaxURL || len(r.Item) > MaxItemID {
		return errTooLong
	}
	return nil
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (r *LoginRequest) UnmarshalJSON(data []byte) error {
	var v LoginRequest
	if err := decodeObject(data, map[string]field{"url": text(&v.URL), "item": text(&v.Item)}); err != nil {
		return err
	}
	if err := v.Check(); err != nil {
		return err
	}
	*r = v
	return nil
}

// TOTPRequest asks for the current TOTP code of a login.
type TOTPRequest struct {
	URL  string `json:"url"`
	Item string `json:"item"`
}

// Check checks the caps of the request.
func (r *TOTPRequest) Check() error { return (&LoginRequest{URL: r.URL, Item: r.Item}).Check() }

// UnmarshalJSON decodes strictly, and checks the caps.
func (r *TOTPRequest) UnmarshalJSON(data []byte) error {
	var v LoginRequest
	if err := v.UnmarshalJSON(data); err != nil {
		return err
	}
	*r = TOTPRequest(v)
	return nil
}

// LoginAnswer holds the username and the password of a login. The broker
// writes it with Encode, not with encoding/json, as for SecretsAnswer. The
// password is a secret: fmt and slog never show it.
type LoginAnswer struct {
	Username string `json:"username"`
	Password []byte `json:"password"`
}

// Check checks the caps of the answer.
func (a *LoginAnswer) Check() error {
	if len(a.Username) > MaxLoginText || len(a.Password) > MaxValue {
		return errTooLong
	}
	return nil
}

// Encode writes the answer as JSON into a new buffer of exactly its size.
// The buffer holds the password in base64: the caller must clear it once
// the answer is written.
func (a *LoginAnswer) Encode() ([]byte, error) {
	if err := a.Check(); err != nil {
		return nil, err
	}
	user, err := json.Marshal(a.Username)
	if err != nil {
		return nil, err
	}
	const (
		head = `{"username":`
		mid  = `,"password":"`
		tail = `"}`
	)
	n := len(head) + len(user) + len(mid) + base64.StdEncoding.EncodedLen(len(a.Password)) + len(tail)
	// The exact size, so that append never moves the bytes and leaves a
	// copy behind.
	b := make([]byte, 0, n)
	b = append(b, head...)
	b = append(b, user...)
	b = append(b, mid...)
	b = base64.StdEncoding.AppendEncode(b, a.Password)
	return append(b, tail...), nil
}

// UnmarshalJSON decodes strictly, and checks the caps.
func (a *LoginAnswer) UnmarshalJSON(data []byte) error {
	var v LoginAnswer
	err := decodeObject(data, map[string]field{"username": text(&v.Username), "password": binary(&v.Password)})
	if err != nil {
		clear(v.Password)
		return err
	}
	if err := v.Check(); err != nil {
		clear(v.Password)
		return err
	}
	*a = v
	return nil
}

// Clear overwrites the password with zeros, as best effort.
func (a *LoginAnswer) Clear() { clear(a.Password) }

// String returns a text without the password.
func (a LoginAnswer) String() string { return "api.LoginAnswer{password hidden}" }

// GoString returns a text without the password.
func (a LoginAnswer) GoString() string { return a.String() }

// Format writes a text without the password, for every verb.
func (a LoginAnswer) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// LogValue returns a text without the password, so slog never logs it.
func (a LoginAnswer) LogValue() slog.Value { return slog.StringValue(a.String()) }

// MarshalJSON refuses: the password must not go through encoding/json,
// which leaves a copy in a buffer that nobody clears. Use Encode.
func (a LoginAnswer) MarshalJSON() ([]byte, error) {
	return nil, errors.New("api: a LoginAnswer is written with Encode, not with encoding/json")
}

// TOTPAnswer holds one TOTP code. A code is good for a short time only,
// and fmt and slog do not show it.
type TOTPAnswer struct {
	Code string `json:"code"`
}

// UnmarshalJSON decodes strictly, and checks that the code is 6 to
// MaxTOTPCode digits.
func (a *TOTPAnswer) UnmarshalJSON(data []byte) error {
	var v TOTPAnswer
	if err := decodeObject(data, map[string]field{"code": text(&v.Code)}); err != nil {
		return err
	}
	if len(v.Code) < 6 || len(v.Code) > MaxTOTPCode {
		return errTooLong
	}
	for _, c := range []byte(v.Code) {
		if c < '0' || c > '9' {
			return errType
		}
	}
	*a = v
	return nil
}

// String returns a text without the code.
func (a TOTPAnswer) String() string { return "api.TOTPAnswer{code hidden}" }

// GoString returns a text without the code.
func (a TOTPAnswer) GoString() string { return a.String() }

// Format writes a text without the code, for every verb.
func (a TOTPAnswer) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, a.String()) }

// LogValue returns a text without the code, so slog never logs it.
func (a TOTPAnswer) LogValue() slog.Value { return slog.StringValue(a.String()) }
