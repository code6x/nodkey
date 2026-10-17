// Package release finds the newest release of nodkey on GitHub (DESIGN.md
// section 15). nodkey version uses it on a terminal, and the broker uses it
// 10 minutes after its start, and then once a day, to send a notice when a
// newer release is out (check.go).
//
// The lookup asks GitHub's API, without a login, for the newest release,
// and reads only its tag, and whether it is a draft or a prerelease. It
// takes only a tag "vX.Y.Z" with numbers that version.ParseRelease
// accepts. Nothing else from the answer is ever shown or logged: the link
// to the release page is made from the version (PageURL). An error has a
// fixed text, with at most the HTTP status.
package release

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/code6x/nodkey/internal/version"
)

const (
	// defaultBaseURL is the address of GitHub's API. Only tests change it.
	defaultBaseURL = "https://api.github.com"
	// latestPath is the newest release of nodkey that is not a draft or a
	// prerelease.
	latestPath = "/repos/code6x/nodkey/releases/latest"
	// pageURL is the start of the address of the page of a release. The
	// tag follows it.
	pageURL = "https://github.com/code6x/nodkey/releases/tag/v"
	// apiVersion is the version of GitHub's API that the lookup asks for.
	apiVersion = "2022-11-28"
)

const (
	// maxAnswer is the largest answer that the lookup reads. GitHub's
	// answer is a few KiB, with the release notes.
	maxAnswer = 1 << 20
	// maxTag is the longest tag of a release: "v" and three numbers of at
	// most 6 digits (version.ParseRelease). A longer tag is refused before
	// it is parsed: a tag of 1 MiB of dots would cost about 16 MiB there.
	maxTag = len("v999999.999999.999999")
	// callTimeout bounds one lookup, with its connection and its answer.
	callTimeout = 30 * time.Second
	// stepTimeout bounds each step of a connection: the TCP connection,
	// the TLS handshake, and the wait for the headers of the answer.
	stepTimeout = 10 * time.Second
)

// ErrRateLimit is the error of a lookup that GitHub refused with 403 or
// 429. Without a login, GitHub allows only a few calls an hour from one
// address. Try again later.
var ErrRateLimit = errors.New("GitHub limits the calls from this address for now")

// Client asks GitHub for the newest release of nodkey. Make it with New.
type Client struct {
	// http and base are fields only so that a test can use a fake GitHub
	// server. Neither the config nor the environment changes them.
	http      *http.Client
	base      string
	userAgent string
	timeout   time.Duration // the whole lookup
}

// New returns a Client for this nodkey, whose version is own. It sends
// own in its User-Agent, as GitHub asks every client to: so GitHub learns
// the version of nodkey (THREAT-MODEL.md T34).
func New(own version.Release) *Client {
	return &Client{http: newHTTPClient(), base: defaultBaseURL, userAgent: "nodkey/" + own.String(), timeout: callTimeout}
}

// newHTTPClient returns the HTTP client of the lookup.
//
//   - It uses the proxy from the environment, as the Telegram code does:
//     HTTPS_PROXY or https_proxy, except for the hosts in NO_PROXY or
//     no_proxy.
//   - TLS 1.2 or newer, with the system's CA certificates.
//   - It speaks only HTTP/1.1, as the Telegram code does.
//   - It follows no redirect: Latest takes a redirect as an error.
//   - Each step of a connection has a time limit; Latest bounds the whole
//     lookup.
//   - It keeps no connection open after a lookup. The broker asks only
//     once a day.
func newHTTPClient() *http.Client {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	dialer := &net.Dialer{Timeout: stepTimeout}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			DialContext:            dialer.DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    stepTimeout,
			ResponseHeaderTimeout:  stepTimeout,
			MaxResponseHeaderBytes: 64 << 10,
			DisableKeepAlives:      true,
			Protocols:              protocols,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// PageURL returns the address of the page of the release r, with its
// release notes. It is made from the version, never taken from an answer
// of GitHub.
func PageURL(r version.Release) string { return pageURL + r.String() }

// Latest asks GitHub for the newest release of nodkey, and returns its
// version. It fails on any answer but 200 with a release that is not a
// draft, not a prerelease, and has the tag "vX.Y.Z". 403 and 429 give
// ErrRateLimit. The error text is fixed, with at most the HTTP status: it
// never holds text or a header of the answer, or Go's error text, which
// can name the proxy. So the error may go to a terminal or the journal as
// it is. When it returns, no dial of it goes on.
func (c *Client) Latest(ctx context.Context) (version.Release, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	// Go's HTTP client goes on with a dial after its request ended, such as
	// when the broker stops during a lookup: it would still connect through
	// the proxy, and make a TLS handshake with GitHub. CloseIdleConnections
	// ends such a dial too.
	defer c.http.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+latestPath, nil)
	if err != nil {
		return version.Release{}, errors.New("cannot make the request to GitHub")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return version.Release{}, errors.New("cannot reach GitHub: " + netReason(err))
	}
	defer func() { _ = resp.Body.Close() }() // a close error adds nothing
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusTooManyRequests:
		return version.Release{}, fmt.Errorf("%w (HTTP %d); try again later", ErrRateLimit, resp.StatusCode)
	default:
		// Also a redirect, which the client does not follow.
		return version.Release{}, fmt.Errorf("GitHub answered with HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return version.Release{}, errors.New("cannot read the answer of GitHub: " + netReason(err))
	}
	if len(data) > maxAnswer {
		return version.Release{}, errors.New("the answer of GitHub is too large")
	}
	return parseLatest(data)
}

// errNotValid is the error for an answer that does not have the form of a
// release.
var errNotValid = errors.New("the answer of GitHub is not a valid release")

// parseLatest reads the answer of GitHub: a JSON object with tag_name,
// draft and prerelease. Other keys do not matter. A key counts only when
// it is written exactly so: Go's JSON decoder would also take TAG_NAME
// for a struct field tag_name.
func parseLatest(data []byte) (version.Release, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return version.Release{}, errNotValid
	}
	var tag *string
	var draft, prerelease *bool
	for key, dst := range map[string]any{"tag_name": &tag, "draft": &draft, "prerelease": &prerelease} {
		raw, ok := fields[key]
		// A JSON null leaves the pointer nil.
		if !ok || json.Unmarshal(raw, dst) != nil {
			return version.Release{}, errNotValid
		}
	}
	switch {
	case tag == nil || draft == nil || prerelease == nil:
		return version.Release{}, errNotValid
	case *draft:
		return version.Release{}, errors.New("the newest release on GitHub is a draft")
	case *prerelease:
		return version.Release{}, errors.New("the newest release on GitHub is a prerelease")
	}
	errTag := errors.New("the tag of the newest release on GitHub is not vX.Y.Z")
	if len(*tag) > maxTag {
		return version.Release{}, errTag
	}
	rest, ok := strings.CutPrefix(*tag, "v")
	r, isRelease := version.ParseRelease(rest)
	if !ok || !isRelease {
		return version.Release{}, errTag
	}
	return r, nil
}

// netReason returns a fixed reason for an error of http.Client.Do or of
// reading the answer. It looks only at the types in err, never at its
// text: the text can hold the address of the proxy, or the text of the
// status line that the proxy sent.
func netReason(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var netErr net.Error
	var opErr *net.OpError
	switch {
	case errors.Is(err, context.Canceled):
		return "the lookup was cancelled"
	case errors.As(err, &dnsErr):
		return "cannot find the address of the server"
	case errors.As(err, &certErr):
		return "the TLS certificate of the server is not valid"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "the lookup timed out"
	case errors.As(err, &opErr) && opErr.Op == "proxyconnect":
		return "cannot connect to the proxy"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "cannot connect to the server"
	}
	return "the connection failed"
}
