package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/code6x/nodkey/internal/loginmatch"
)

// nodkey agent-browser-plugin: the credential plugin of agent-browser
// (DESIGN.md section 21.10, issue #104). agent-browser runs it once for
// each request: it writes one JSON request to its stdin, and reads one
// JSON answer from its stdout. The protocol is agent-browser.plugin.v1, as
// agent-browser PluginVersion speaks it; the test with recorded requests is
// abplugin_test.go.

// PluginProtocol is the protocol of agent-browser's plugins.
const PluginProtocol = "agent-browser.plugin.v1"

// PluginVersion is the version of agent-browser whose requests the tests
// recorded (docs/agent-browser.md).
const PluginVersion = "0.38.1"

const (
	// maxPluginRequest is the most bytes of a request on stdin.
	maxPluginRequest = 64 << 10
	// PluginResolveTime is how long credential.resolve waits for the
	// broker. agent-browser stops the plugin after 15 seconds; the answer
	// must come before that.
	PluginResolveTime = 12 * time.Second
	// PluginCommandTime is how long nodkey.list and nodkey.totp wait for
	// the broker. agent-browser stops "plugin run" after 60 seconds.
	PluginCommandTime = 50 * time.Second
)

// The request types and the capabilities of the plugin.
const (
	pluginManifest = "plugin.manifest"
	pluginResolve  = "credential.resolve"
	pluginList     = "nodkey.list"
	pluginTOTP     = "nodkey.totp"
	capCredential  = "credential.read" //nolint:gosec // G101: a capability name of agent-browser, not a credential.
	capCommand     = "command.run"
)

const pluginUsage = `Usage: nodkey agent-browser-plugin

The credential plugin of agent-browser (` + PluginVersion + `). agent-browser runs
it: it reads one request on stdin and writes one answer on stdout. Do not
run it by hand. Set it up in ~/.agent-browser/config.json:

  {"plugins": [{"name": "nodkey", "command": "/usr/local/bin/nodkey",
                "args": ["agent-browser-plugin"],
                "capabilities": ["credential.read", "command.run"]}]}

Give the full path of nodkey. agent-browser does not split "command" at
spaces: the subcommand goes in "args".

First let the person approve the login on the phone, then log in at once:

  nodkey preapprove --login ITEM --url https://example.com/sign-in
  agent-browser auth login example --credential-provider nodkey \
    --item ITEM --url https://example.com/sign-in

Requests:
  credential.resolve  the username and the password of the item --item, for
                      the page --url. It never asks for a tap: run
                      nodkey preapprove --login first.
  nodkey.list         agent-browser plugin run nodkey nodkey.list
                      --payload '{"url":"https://example.com/"}'
                      the logins for the page: item IDs, names, usernames
  nodkey.totp         agent-browser plugin run nodkey nodkey.totp
                      --payload '{"itemRef":"ITEM","url":"https://example.com/"}'
                      the current TOTP code, once, after the login

Guide: docs/agent-browser.md.
`

// pluginRunner holds the parts of the plugin that the tests replace.
type pluginRunner struct {
	load       func(path string) (*Broker, error)
	configPath func() (string, error)
	version    string
}

// AgentBrowserPlugin runs nodkey agent-browser-plugin, and returns the
// exit code.
func AgentBrowserPlugin(args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	r := pluginRunner{load: Load, configPath: ConfigPath, version: version}
	return r.run(context.Background(), args, stdin, stdout, stderr)
}

// pluginError is a refusal of the plugin: its text goes into the answer
// and to stderr. code says what kind of refusal it is (exitUsage,
// exitDenied, exitUnavailable); the process still exits with 0. The text
// is a fixed text, or an error of this package (such as the path of the
// client config or the broker's address). It never holds a value, the
// item reference or the page.
type pluginError struct {
	code int
	text string
}

func (r pluginRunner) run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && isHelp(args[0]) {
		_, _ = io.WriteString(stderr, pluginUsage)
		return exitOK
	}
	if len(args) > 0 {
		return UsageError(stderr, "agent-browser-plugin", "it takes no arguments: agent-browser runs it, with the request on stdin")
	}
	answer, perr := r.serve(ctx, stdin, stderr)
	if perr != nil {
		// The exit code is 0 when the answer is written: agent-browser
		// drops the answer of a plugin that exits with another code, and
		// the agent would not see why.
		_, _ = fmt.Fprintf(stderr, "nodkey agent-browser-plugin: %s\n", oneLine(perr.text))
		if !writePluginError(stdout, perr.text) {
			return exitUnavailable
		}
		return exitOK
	}
	defer clear(answer)
	if _, err := stdout.Write(answer); err != nil {
		return fail(stderr, exitUnavailable, "cannot write the answer to agent-browser")
	}
	return exitOK
}

// pluginRequest is the envelope of a request. Other fields are ignored.
type pluginRequest struct {
	Protocol   string          `json:"protocol"`
	Type       string          `json:"type"`
	Capability string          `json:"capability"`
	Request    json.RawMessage `json:"request"`
}

// loginRef is the request of credential.resolve and nodkey.totp. A field
// that is missing or null stays nil.
type loginRef struct {
	ItemRef *string `json:"itemRef"`
	URL     *string `json:"url"`
}

// serve reads the request and returns the answer.
func (r pluginRunner) serve(ctx context.Context, stdin io.Reader, stderr io.Writer) ([]byte, *pluginError) {
	data, err := io.ReadAll(io.LimitReader(stdin, maxPluginRequest+1))
	if err != nil {
		return nil, &pluginError{exitUsage, "cannot read the request from stdin"}
	}
	if len(data) > maxPluginRequest {
		return nil, &pluginError{exitUsage, fmt.Sprintf("the request is longer than %d bytes", maxPluginRequest)}
	}
	var req pluginRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, &pluginError{exitUsage, "the request is not a JSON object of " + PluginProtocol}
	}
	if req.Protocol != PluginProtocol {
		return nil, &pluginError{exitUsage, "the request is not of the protocol " + PluginProtocol +
			"; use agent-browser " + PluginVersion + ", the version that nodkey is tested with (docs/agent-browser.md)"}
	}
	var want string
	switch req.Type {
	case pluginManifest:
		return manifestAnswer(), nil
	case pluginResolve:
		want = capCredential
	case pluginList, pluginTOTP:
		want = capCommand
	default:
		return nil, &pluginError{exitUsage, "unknown request type: nodkey answers " + pluginResolve + ", " +
			pluginList + " and " + pluginTOTP}
	}
	if req.Capability != want {
		return nil, &pluginError{exitUsage, "a " + req.Type + " request must have the capability " + want}
	}
	if len(req.Request) == 0 || req.Request[0] != '{' {
		return nil, &pluginError{exitUsage, "the request has no \"request\" object"}
	}
	switch req.Type {
	case pluginResolve:
		return r.resolve(ctx, req.Request, stderr)
	case pluginList:
		return r.list(ctx, req.Request, stderr)
	default:
		return r.totp(ctx, req.Request, stderr)
	}
}

// checkRef checks the item and the page of credential.resolve and
// nodkey.totp.
func checkRef(raw json.RawMessage) (item, page string, perr *pluginError) {
	var ref loginRef
	if err := json.Unmarshal(raw, &ref); err != nil {
		return "", "", &pluginError{exitUsage, "the request has no valid itemRef and url"}
	}
	if ref.ItemRef == nil || !itemIDPattern.MatchString(*ref.ItemRef) {
		return "", "", &pluginError{exitUsage, "the item is not an item ID: give --item with the UUID that " +
			"\"agent-browser plugin run nodkey nodkey.list\" lists for the page"}
	}
	if ref.URL == nil || *ref.URL == "" {
		return "", "", &pluginError{exitUsage, "the request has no page URL: give agent-browser --url with the https page of the login"}
	}
	p, err := checkPage(*ref.URL)
	if err != nil {
		return "", "", err
	}
	return *ref.ItemRef, p, nil
}

// checkPage checks a page URL as the broker does, for a clear error
// before the request. It returns the page as the broker reads it (with no
// fragment): the plugin sends that to the broker, and gives it back to
// agent-browser, so both see the same page.
func checkPage(page string) (string, *pluginError) {
	p, err := loginmatch.ParsePage(page)
	if err != nil {
		return "", &pluginError{exitUsage, "the page URL: " + err.Error()}
	}
	return p.URL(), nil
}

// broker loads the client config.
func (r pluginRunner) broker(stderr io.Writer) (*Broker, *pluginError) {
	path, err := r.configPath()
	if err != nil {
		return nil, &pluginError{exitUnavailable, err.Error()}
	}
	b, err := r.load(path)
	if err != nil {
		return nil, &pluginError{exitUnavailable, err.Error()}
	}
	b.warnVersions(r.version, func(text string) { warnLine(stderr, text) })
	return b, nil
}

// requestError turns the error of a request into a refusal.
func requestError(err error, what string) *pluginError {
	var e *Error
	switch {
	case errors.As(err, &e) && e.NeedsTap():
		return &pluginError{exitDenied, what + ": it needs a tap first: run \"nodkey preapprove --login ITEM --url URL\", " +
			"wait for the tap, then run agent-browser auth login within 60 seconds"}
	case errors.As(err, &e) && e.Denied():
		return &pluginError{exitDenied, what + ": " + e.Error()}
	case errors.Is(err, context.DeadlineExceeded):
		return &pluginError{exitUnavailable, what + ": no answer from the broker in time"}
	}
	return &pluginError{exitUnavailable, what + ": " + err.Error()}
}

func (r pluginRunner) resolve(ctx context.Context, raw json.RawMessage, stderr io.Writer) ([]byte, *pluginError) {
	item, page, perr := checkRef(raw)
	if perr != nil {
		return nil, perr
	}
	b, perr := r.broker(stderr)
	if perr != nil {
		return nil, perr
	}
	ctx, cancel := context.WithTimeout(ctx, PluginResolveTime)
	defer cancel()
	ans, err := LoginNoTap(ctx, b, page, item)
	if err != nil {
		return nil, requestError(err, "login")
	}
	defer ans.Clear()
	out, err := credentialAnswer(ans.Username, ans.Password, page)
	if err != nil {
		return nil, &pluginError{exitUnavailable, err.Error()}
	}
	return out, nil
}

func (r pluginRunner) list(ctx context.Context, raw json.RawMessage, stderr io.Writer) ([]byte, *pluginError) {
	var req struct {
		URL *string `json:"url"`
	}
	if err := json.Unmarshal(raw, &req); err != nil || req.URL == nil || *req.URL == "" {
		return nil, &pluginError{exitUsage, "give the page in the payload: {\"url\":\"https://example.com/\"}"}
	}
	page, perr := checkPage(*req.URL)
	if perr != nil {
		return nil, perr
	}
	b, perr := r.broker(stderr)
	if perr != nil {
		return nil, perr
	}
	ctx, cancel := context.WithTimeout(ctx, PluginCommandTime)
	defer cancel()
	ans, err := ListLogins(ctx, b, page)
	if err != nil {
		return nil, requestError(err, "list")
	}
	type entry struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
	}
	data := struct {
		Logins []entry `json:"logins"`
	}{Logins: []entry{}}
	for _, l := range ans.Logins {
		data.Logins = append(data.Logins, entry{ID: l.ID, Name: l.Name, Username: l.Username})
	}
	return dataAnswer(data)
}

func (r pluginRunner) totp(ctx context.Context, raw json.RawMessage, stderr io.Writer) ([]byte, *pluginError) {
	item, page, perr := checkRef(raw)
	if perr != nil {
		return nil, perr
	}
	b, perr := r.broker(stderr)
	if perr != nil {
		return nil, perr
	}
	ctx, cancel := context.WithTimeout(ctx, PluginCommandTime)
	defer cancel()
	ans, err := LoginTOTP(ctx, b, page, item)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.Status == http.StatusForbidden {
			return nil, &pluginError{exitDenied, "totp: denied: there was no login through nodkey for this item " +
				"and page in the last 2 minutes, the code of that login was already given, or this machine or " +
				"page may not use the item; log in again with agent-browser auth login, then ask for the code"}
		}
		return nil, requestError(err, "totp")
	}
	return dataAnswer(struct {
		Code string `json:"code"`
	}{Code: ans.Code})
}

// manifestAnswer is the answer to plugin.manifest.
func manifestAnswer() []byte {
	return []byte(`{"protocol":"` + PluginProtocol + `","success":true,"manifest":{"name":"nodkey",` +
		`"capabilities":["` + capCredential + `","` + capCommand + `"]}}` + "\n")
}

// dataAnswer is the answer of a plugin run command.
func dataAnswer(data any) ([]byte, *pluginError) {
	d, err := json.Marshal(data)
	if err != nil {
		return nil, &pluginError{exitUnavailable, "cannot write the answer"}
	}
	out := []byte(`{"protocol":"` + PluginProtocol + `","success":true,"data":`)
	out = append(out, d...)
	return append(out, "}\n"...), nil
}

// writePluginError writes the answer of a refusal, and reports whether
// it could. text is a fixed text.
func writePluginError(w io.Writer, text string) bool {
	t, _ := json.Marshal("nodkey: " + oneLine(text))
	_, err := fmt.Fprintf(w, `{"protocol":"%s","success":false,"error":%s}`+"\n", PluginProtocol, t)
	return err == nil
}

// errPasswordText refuses a password that is not UTF-8 text: a JSON
// string cannot hold it as it is.
var errPasswordText = errors.New("the password of the item is not UTF-8 text, so agent-browser cannot fill it; change it in Bitwarden")

// credentialAnswer writes the answer of credential.resolve into one
// buffer of exactly its size, so that no copy of the password is left
// behind by a growing buffer. The caller must clear it.
func credentialAnswer(username string, password []byte, page string) ([]byte, error) {
	if !utf8.Valid(password) {
		return nil, errPasswordText
	}
	user, err := json.Marshal(username)
	if err != nil {
		return nil, err
	}
	u, err := json.Marshal(page)
	if err != nil {
		return nil, err
	}
	head := `{"protocol":"` + PluginProtocol + `","success":true,"credential":{"username":`
	const mid, mid2, tail = `,"password":"`, `","url":`, "}}\n"
	n := len(head) + len(user) + len(mid) + jsonEscapedLen(password) + len(mid2) + len(u) + len(tail)
	b := make([]byte, 0, n)
	b = append(b, head...)
	b = append(b, user...)
	b = append(b, mid...)
	b = appendJSONEscaped(b, password)
	b = append(b, mid2...)
	b = append(b, u...)
	b = append(b, tail...)
	if len(b) != n {
		clear(b)
		return nil, errors.New("cannot write the answer")
	}
	return b, nil
}

// jsonEscapedLen is the length of s escaped for a JSON string.
func jsonEscapedLen(s []byte) int {
	n := 0
	for _, c := range s {
		switch {
		case c == '"' || c == '\\':
			n += 2
		case c < 0x20:
			n += 6
		default:
			n++
		}
	}
	return n
}

// appendJSONEscaped appends s, which is valid UTF-8, escaped for a JSON
// string, with no quotes. dst must have room: it never grows.
func appendJSONEscaped(dst, s []byte) []byte {
	const hex = "0123456789abcdef"
	for _, c := range s {
		switch {
		case c == '"' || c == '\\':
			dst = append(dst, '\\', c)
		case c < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		default:
			dst = append(dst, c)
		}
	}
	return dst
}
