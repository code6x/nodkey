package store

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-resty/resty/v2"
	infauth "github.com/infisical/go-sdk/packages/api/auth"
	infsecrets "github.com/infisical/go-sdk/packages/api/secrets"
	inferrors "github.com/infisical/go-sdk/packages/errors"

	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/version"
)

// The errors of an infisical store. As every store error, they are fixed
// texts: the SDK's error text and the server's error text are never shown,
// because they may repeat a request (THREAT-MODEL.md T19).
var (
	ErrInfFailed   = errors.New("the Infisical server refused the request, or could not be reached")
	ErrInfLogin    = errors.New("the Infisical server refused the login of the machine identity")
	ErrInfDenied   = errors.New("the Infisical server refused the access token, or the machine identity may not read the secret")
	ErrInfNotFound = errors.New("the Infisical server has no such secret in this project, environment and path")
	ErrInfTooLarge = errors.New("the answer of the Infisical server is larger than 1 MiB")
	// ErrInfReference is a value that refers to another secret (${...}).
	// nodkey asks Infisical not to expand references, and hands out no
	// such value: the tap must show every secret that goes out.
	ErrInfReference = errors.New("the value refers to another secret (${...}); nodkey hands out no such value")
	// ErrInfRateLimited is Infisical's rate limit. errors.Is matches it
	// with ErrRateLimited too, so the broker sends its alert.
	ErrInfRateLimited error = rateLimitError{"the rate limit of Infisical is reached; the machine identity must wait"}
)

// rateLimitError is the rate limit of one kind of store.
type rateLimitError struct{ text string }

func (e rateLimitError) Error() string { return e.text }

// Is matches ErrRateLimited.
func (e rateLimitError) Is(target error) bool { return target == ErrRateLimited }

const (
	// infParallel is the most calls to Infisical at the same time, for one
	// infisical store.
	infParallel = 4
	// maxInfAnswer is the largest answer of Infisical, in bytes, after
	// gzip: 1 MiB, as the output of a store program.
	maxInfAnswer = maxStdout
	// maxInfToken is the longest access token that the store keeps. A
	// token is a JWT of about 1 KiB.
	maxInfToken = 16 << 10
	// infTokenMargin is how long before its end an access token is
	// dropped and the store logs in again, so that a token never ends on
	// the way to Infisical.
	infTokenMargin = 10 * time.Second
	// infSecretType is the type of the secrets that the store reads: a
	// machine identity has no personal secrets.
	infSecretType = "shared"
)

// errInfUnauthorized is a 401 of Infisical: the access token ended, or
// was revoked. It never leaves the store: Fetch logs in again once.
var errInfUnauthorized = errors.New("the access token was refused")

// infStore gets values from Infisical with a machine identity and
// Universal Auth, in the broker's process. It has no program.
//
// It uses the request and answer code of the Infisical Go SDK
// (packages/api/auth and packages/api/secrets), but not the SDK's
// client: that client starts a goroutine that renews the token, reads
// the client ID and secret from the environment when they are empty, logs
// to stderr, and builds its own HTTP client, with no limit on the size of
// an answer and no context. The store gives the SDK's calls its own
// resty client instead (newClient): no retries, no redirects, no log, no
// cache, the context of the request, and a cap on the size of an answer.
type infStore struct {
	name      string
	api       string // the server's API, such as https://app.infisical.com/api
	clientID  string
	timeout   time.Duration
	transport http.RoundTripper
	now       func() time.Time
	slots     chan struct{} // the places for calls of this store
	logins    chan struct{} // one login at a time

	mu       sync.Mutex
	secret   Value     // the client secret
	token    Value     // the access token; empty when the store has none
	tokenEnd time.Time // when the store drops token; zero for no known end
	tokenGen uint64    // counts the logins, so a refused token is dropped only once
	closed   bool
}

// infRef is one secret in Infisical.
type infRef struct {
	project, environment, path, name string
}

// InfisicalRef returns the id that Fetch of an infisical store takes for
// the secret: "PROJECT/ENVIRONMENT/NAME/PATH", where PATH has no "/" at
// the start ("" for the folder "/"). No part but PATH can hold a "/".
func InfisicalRef(project, environment, path, name string) string {
	return project + "/" + environment + "/" + name + "/" + strings.TrimPrefix(path, "/")
}

// parseInfRef reads an id of InfisicalRef and checks each part, as the
// config does.
func parseInfRef(id string) (infRef, bool) {
	project, rest, ok1 := strings.Cut(id, "/")
	environment, rest, ok2 := strings.Cut(rest, "/")
	name, path, ok3 := strings.Cut(rest, "/")
	r := infRef{project: project, environment: environment, path: "/" + path, name: name}
	ok := ok1 && ok2 && ok3 && config.ValidInfisicalProject(r.project) &&
		config.ValidInfisicalEnvironment(r.environment) && config.ValidInfisicalPath(r.path) &&
		config.ValidInfisicalName(r.name)
	return r, ok
}

// newInfisical reads the client secret file of an infisical store and
// returns the store.
func newInfisical(cfg config.Store, d deps) (*infStore, error) {
	server, ok := config.InfisicalServer(cfg.Server)
	if !ok || server != cfg.Server {
		return nil, fmt.Errorf("store %q: server: is not an https URL without a user, query or fragment", cfg.Name)
	}
	if !isUUID(cfg.ClientID) {
		return nil, fmt.Errorf("store %q: client_id: is not a UUID", cfg.Name)
	}
	if !cleanAbs(cfg.ClientSecretFile) {
		return nil, fmt.Errorf("store %q: client_secret_file: %s", cfg.Name, cleanAbsRule)
	}
	data, err := d.readPrivateFile(cfg.ClientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("store %q: client_secret_file: %w", cfg.Name, err) // the error names the path, never the content
	}
	defer clear(data)
	secret, ok := parseKey(data, maxTokenLen)
	if !ok {
		return nil, fmt.Errorf("store %q: client_secret_file %s: it holds no client secret, or a character that "+
			"a client secret never has (the content is not shown here)", cfg.Name, cfg.ClientSecretFile)
	}
	tr := d.infTransport
	if tr == nil {
		tr = newInfTransport()
	}
	now := d.now
	if now == nil {
		now = time.Now
	}
	return &infStore{
		name: cfg.Name, api: server + "/api", clientID: cfg.ClientID, timeout: d.timeout, transport: tr, now: now,
		slots: make(chan struct{}, infParallel), logins: make(chan struct{}, 1), secret: secret,
	}, nil
}

// newInfTransport returns the HTTP transport to Infisical: TLS 1.2 or
// newer, the proxy of the environment, and a limit for each step of a
// connection.
func newInfTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           4,
	}
}

// infCall is the state of one call to Infisical.
type infCall struct {
	ctx      context.Context
	base     http.RoundTripper
	tooLarge atomic.Bool
}

// RoundTrip sends req with the context of the call, and caps the answer.
// The SDK's calls take no context; this one stops them when the call ends.
func (c *infCall) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := c.base.RoundTrip(req.WithContext(c.ctx))
	if err != nil {
		return nil, err
	}
	if res.ContentLength > maxInfAnswer {
		_ = res.Body.Close()
		c.tooLarge.Store(true)
		return nil, ErrInfTooLarge
	}
	res.Body = &capBody{rc: res.Body, left: maxInfAnswer, call: c}
	return res, nil
}

// capBody fails a read past its limit.
type capBody struct {
	rc   io.ReadCloser
	left int64
	call *infCall
}

func (b *capBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.rc.Read(p)
	if int64(n) > b.left {
		clear(p[:n])
		b.left = -1
		b.call.tooLarge.Store(true)
		return 0, ErrInfTooLarge
	}
	b.left -= int64(n)
	return n, err
}

func (b *capBody) Close() error { return b.rc.Close() }

// noLog is the logger of the resty client: it drops every line, which can
// hold a URL or an error of the server.
type noLog struct{}

func (noLog) Errorf(string, ...any) {}
func (noLog) Warnf(string, ...any)  {}
func (noLog) Debugf(string, ...any) {}

// newClient returns the resty client of one call: through c, with no
// retries, no redirects, no cookies and no log.
func (s *infStore) newClient(c *infCall) *resty.Client {
	hc := &http.Client{
		Transport: c,
		// A redirect is the answer: no other server gets the client secret
		// or the access token.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       s.timeout,
	}
	return resty.NewWithClient(hc).
		SetBaseURL(s.api).
		SetLogger(noLog{}).
		SetRetryCount(0).
		SetHeader("User-Agent", "nodkey/"+version.Running)
}

// Start logs in to Infisical. If it fails, Fetch tries again.
func (s *infStore) Start(ctx context.Context) error {
	const step = "infisical login"
	_, err := callWithin(ctx, s.slots, s.timeout, func(ctx context.Context) (Value, error) {
		_, _, _, err := s.tokenFor(ctx)
		return Value{}, err
	})
	if err != nil {
		return stepError(s.name, step, err)
	}
	return nil
}

// Fetch gets one secret: id is from InfisicalRef. It reads the secret
// with the access token, and logs in first when the store has no token or
// the token's time is up. When Infisical refuses a token that was not
// just got (a 401: it ended or was revoked), Fetch logs in again once and
// reads once more; a second refusal denies.
func (s *infStore) Fetch(ctx context.Context, id string) (Value, error) {
	const step = "infisical secret get"
	ref, ok := parseInfRef(id)
	if !ok {
		return Value{}, stepError(s.name, step, ErrBadID)
	}
	v, err := callWithin(ctx, s.slots, s.timeout, func(ctx context.Context) (Value, error) {
		token, gen, fresh, err := s.tokenFor(ctx)
		if err != nil {
			return Value{}, err
		}
		v, err := s.read(ctx, token, ref)
		if !errors.Is(err, errInfUnauthorized) || fresh {
			return v, err
		}
		s.dropToken(gen)
		token, _, _, err = s.tokenFor(ctx)
		if err != nil {
			return Value{}, err
		}
		return s.read(ctx, token, ref)
	})
	if errors.Is(err, errInfUnauthorized) {
		err = ErrInfDenied
	}
	if err != nil {
		return Value{}, stepError(s.name, step, err)
	}
	return v, nil
}

// tokenFor returns the access token and the number of its login, and
// logs in first when the store has none, or its time is up. fresh
// reports whether this call logged in. One login runs at a time.
func (s *infStore) tokenFor(ctx context.Context) (token string, gen uint64, fresh bool, err error) {
	if token, gen, ok, err := s.current(); ok || err != nil {
		return token, gen, false, err
	}
	if err := acquire(ctx, s.logins); err != nil {
		return "", 0, false, err
	}
	defer func() { <-s.logins }()
	// Another call may have logged in while this one waited.
	if token, gen, ok, err := s.current(); ok || err != nil {
		return token, gen, false, err
	}
	token, gen, err = s.login(ctx)
	return token, gen, err == nil, err
}

// current returns the access token when the store has one whose time is
// not up. err is ErrClosed after Close.
func (s *infStore) current() (string, uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", 0, false, ErrClosed
	}
	if s.token.Bytes() == nil || (!s.tokenEnd.IsZero() && !s.now().Before(s.tokenEnd)) {
		return "", 0, false, nil
	}
	return string(s.token.Bytes()), s.tokenGen, true, nil
}

// dropToken drops the access token of login gen, which Infisical refused.
// A newer token, of another call's login, is kept.
func (s *infStore) dropToken(gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenGen == gen {
		s.token.Clear()
		s.token = Value{}
	}
}

// login logs in with Universal Auth, and keeps the access token in
// memory only. It does not hold s.mu while it waits for Infisical, so
// Close never waits for it.
func (s *infStore) login(ctx context.Context) (string, uint64, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return "", 0, ErrClosed
	}
	secret := string(s.secret.Bytes())
	s.mu.Unlock()
	call := &infCall{ctx: ctx, base: s.transport}
	got := s.now()
	res, err := infauth.CallUniversalAuthLogin(s.newClient(call), infauth.UniversalAuthLoginRequest{
		ClientID: s.clientID, ClientSecret: secret,
	})
	if err != nil {
		if e := infError(call, err); errors.Is(e, ErrInfRateLimited) || errors.Is(e, ErrInfTooLarge) {
			return "", 0, e
		}
		return "", 0, ErrInfLogin
	}
	token, ok := parseKey([]byte(res.AccessToken), maxInfToken)
	expiresIn := res.ExpiresIn
	res = infauth.MachineIdentityAuthLoginResponse{} // Go cannot clear a string
	if !ok {
		return "", 0, ErrInfLogin
	}
	var end time.Time
	if expiresIn > 0 {
		ttl := time.Duration(min(expiresIn, int64(365*24*3600))) * time.Second
		end = got.Add(ttl - min(infTokenMargin, ttl/10))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		token.Clear()
		return "", 0, ErrClosed
	}
	s.token.Clear()
	s.token, s.tokenEnd = token, end
	s.tokenGen++
	return string(token.Bytes()), s.tokenGen, nil
}

// read reads one secret with token, and checks the answer.
func (s *infStore) read(ctx context.Context, token string, ref infRef) (Value, error) {
	call := &infCall{ctx: ctx, base: s.transport}
	c := s.newClient(call).SetAuthScheme("Bearer").SetAuthToken(token)
	res, err := infsecrets.CallRetrieveSecretV3(nil, c, infsecrets.RetrieveSecretV3RawRequest{
		SecretKey:   ref.name,
		ProjectID:   ref.project,
		Environment: ref.environment,
		SecretPath:  ref.path,
		Type:        infSecretType,
		// No imports and no expanded references: the value is the asked
		// secret's own.
		IncludeImports:         false,
		ExpandSecretReferences: false,
	})
	if err != nil {
		return Value{}, infError(call, err)
	}
	sec := &res.Secret
	if sec.SecretKey != ref.name ||
		(sec.Environment != "" && sec.Environment != ref.environment) ||
		(sec.Workspace != "" && !strings.EqualFold(sec.Workspace, ref.project)) ||
		(sec.SecretPath != "" && sec.SecretPath != ref.path) ||
		(sec.Type != "" && sec.Type != infSecretType) {
		return Value{}, errOtherItem
	}
	if strings.Contains(sec.SecretValue, "${") {
		return Value{}, ErrInfReference
	}
	return keepValue([]byte(sec.SecretValue), nil)
}

// infError turns an error of the SDK into a fixed error. The SDK's text,
// which holds the server's text, is dropped.
func infError(call *infCall, err error) error {
	if call.tooLarge.Load() {
		return ErrInfTooLarge
	}
	if e, ok := errors.AsType[*inferrors.APIError](err); ok {
		switch e.StatusCode {
		case http.StatusTooManyRequests:
			return ErrInfRateLimited
		case http.StatusUnauthorized:
			return errInfUnauthorized
		case http.StatusForbidden:
			return ErrInfDenied
		case http.StatusNotFound:
			return ErrInfNotFound
		}
	}
	return ErrInfFailed
}

// Close clears the client secret and the access token.
func (s *infStore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secret.Clear()
	s.token.Clear()
	s.token = Value{}
	s.closed = true
}

// String names the store, without its secrets.
func (s *infStore) String() string { return fmt.Sprintf("infisical store %q", s.name) }

// GoString names the store, without its secrets.
func (s *infStore) GoString() string { return s.String() }

// Format writes String for every verb.
func (s *infStore) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
