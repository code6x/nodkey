package client

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/code6x/nodkey/internal/api"
)

// The requests for website logins (DESIGN.md section 21), for the browser
// plugin of #104. They never print anything: the caller gets the answer
// and decides what to do with it. A LoginAnswer holds a password; the
// caller must call its Clear as soon as it has used it.

// errLoginRequest is the error for a request that is over a cap of the
// broker.
var errLoginRequest = errors.New("the request is over a cap of the broker: the page URL is at most 2048 bytes and the item ID a UUID")

// ListLogins asks the broker for the logins that match the page pageURL.
// There is no tap. The answer holds the item IDs, names and user names,
// never a password.
func ListLogins(ctx context.Context, b *Broker, pageURL string) (*api.ListLoginsAnswer, error) {
	req := api.ListLoginsRequest{URL: pageURL}
	if req.Check() != nil {
		return nil, errLoginRequest
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errLoginRequest
	}
	return Post[api.ListLoginsAnswer](ctx, b, api.PathLoginList, body, nil)
}

// Login asks the broker for the username and the password of the item at
// the page pageURL. It waits for the person's tap, as nodkey run does;
// onCode, if not nil, gets the short code when the request starts to wait.
// The caller must Clear the answer.
func Login(ctx context.Context, b *Broker, pageURL, item string, onCode func(code string)) (*api.LoginAnswer, error) {
	req := api.LoginRequest{URL: pageURL, Item: item}
	if req.Check() != nil {
		return nil, errLoginRequest
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errLoginRequest
	}
	return Post[api.LoginAnswer](ctx, b, api.PathLogin, body, onCode)
}

// LoginTOTP asks the broker for the current TOTP code of the item at the
// page pageURL. The broker allows it after an approved login (DESIGN.md
// section 21.3).
func LoginTOTP(ctx context.Context, b *Broker, pageURL, item string) (*api.TOTPAnswer, error) {
	req := api.TOTPRequest{URL: pageURL, Item: item}
	if req.Check() != nil {
		return nil, errLoginRequest
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errLoginRequest
	}
	return Post[api.TOTPAnswer](ctx, b, api.PathLoginTOTP, body, nil)
}
