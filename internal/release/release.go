// Package release finds the newest release of nodkey on GitHub, and the
// security releases (DESIGN.md section 15). nodkey version uses it on a
// terminal, and the broker uses it 10 minutes after its start, and then
// once a day, to send a notice when a newer release is out (check.go).
//
// The lookup asks GitHub's API, without a login, for the list of the last
// 20 releases, in one call. Of each release it reads its tag, whether it
// is a draft or a prerelease, and its notes. It takes only a tag "vX.Y.Z"
// with numbers that version.ParseRelease accepts. It reads the notes only
// to find the line "### Security", which marks a security release, and
// the IDs of advisories in the strict GHSA form under that line. Nothing
// else from the answer is ever shown or logged: only release versions and
// such IDs come out, and the link to the release page is made from the
// version (PageURL). An error has a fixed text, with at most the HTTP
// status.
package release

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/code6x/nodkey/internal/version"
)

const (
	// defaultBaseURL is the address of GitHub's API. Only tests change it.
	defaultBaseURL = "https://api.github.com"
	// listPath is the list of the last releases of nodkey, newest first,
	// with drafts and prereleases. GitHub sends at most maxList of them.
	listPath = "/repos/code6x/nodkey/releases?per_page=20"
	// pageURL is the start of the address of the page of a release. The
	// tag follows it.
	pageURL = "https://github.com/code6x/nodkey/releases/tag/v"
	// apiVersion is the version of GitHub's API that the lookup asks for.
	apiVersion = "2022-11-28"
)

const (
	// maxAnswer is the largest answer that the lookup reads. GitHub's
	// answer is some tens of KiB: 20 releases, with their notes.
	maxAnswer = 1 << 20
	// maxList is the most releases that the list may have: the per_page
	// of listPath.
	maxList = 20
	// maxBody is the part of the notes of a release that the lookup reads
	// for the mark of a security release. The search is cheap only on a
	// small part, and the Security section comes first in the notes, so a
	// mark after 64 KiB does not count.
	maxBody = 64 << 10
	// maxIDs is the most advisory IDs that the lookup keeps of a release,
	// and that SecurityNewer returns.
	maxIDs = 3
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

// Info is what the lookup found.
type Info struct {
	// Newest is the highest release in the list.
	Newest version.Release
	// Security holds the security releases in the list, sorted by
	// version, oldest first, each version once.
	Security []Security
}

// Security is a security release: its notes have the line "### Security".
type Security struct {
	Version version.Release
	// IDs holds at most 3 advisory IDs in the strict GHSA form, such as
	// GHSA-xxxx-xxxx-xxxx, from the Security section. It may be empty.
	IDs []string
}

// SecurityNewer returns the security releases that are newer than own,
// oldest first, so that a security release that was skipped is not lost.
// ids holds at most 3 advisory IDs of them, each once, taken from the
// newest release first.
func (i Info) SecurityNewer(own version.Release) (versions []version.Release, ids []string) {
	for _, s := range i.Security {
		if s.Version.Compare(own) > 0 {
			versions = append(versions, s.Version)
		}
	}
	for k := len(i.Security) - 1; k >= 0; k-- {
		if i.Security[k].Version.Compare(own) <= 0 {
			continue
		}
		ids = addIDs(ids, i.Security[k].IDs)
	}
	return versions, ids
}

// addIDs adds the IDs of from to ids that ids does not hold yet, until
// ids holds maxIDs.
func addIDs(ids, from []string) []string {
	for _, id := range from {
		if len(ids) < maxIDs && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids
}

// Client asks GitHub for the releases of nodkey. Make it with New.
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
//   - It follows no redirect: Lookup takes a redirect as an error.
//   - Each step of a connection has a time limit; Lookup bounds the whole
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

// Lookup asks GitHub for the list of the last 20 releases of nodkey, and
// returns the newest release and the security releases in it. Drafts,
// prereleases and releases without a tag "vX.Y.Z" do not count. It fails
// on any answer but 200 with a list in the expected form that has a
// release that counts. 403 and 429 give ErrRateLimit. The error text is fixed, with at most the HTTP status: it
// never holds text or a header of the answer, or Go's error text, which
// can name the proxy. So the error may go to a terminal or the journal as
// it is. When it returns, no dial of it goes on.
func (c *Client) Lookup(ctx context.Context) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	// Go's HTTP client goes on with a dial after its request ended, such as
	// when the broker stops during a lookup: it would still connect through
	// the proxy, and make a TLS handshake with GitHub. CloseIdleConnections
	// ends such a dial too.
	defer c.http.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+listPath, nil)
	if err != nil {
		return Info{}, errors.New("cannot make the request to GitHub")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return Info{}, errors.New("cannot reach GitHub: " + netReason(err))
	}
	defer func() { _ = resp.Body.Close() }() // a close error adds nothing
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden, http.StatusTooManyRequests:
		return Info{}, fmt.Errorf("%w (HTTP %d); try again later", ErrRateLimit, resp.StatusCode)
	default:
		// Also a redirect, which the client does not follow.
		return Info{}, fmt.Errorf("GitHub answered with HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return Info{}, errors.New("cannot read the answer of GitHub: " + netReason(err))
	}
	if len(data) > maxAnswer {
		return Info{}, errors.New("the answer of GitHub is too large")
	}
	return parseList(data)
}

// errNotValid is the error for an answer that does not have the form of a
// list of releases.
var errNotValid = errors.New("the answer of GitHub is not a valid release")

// parseList reads the answer of GitHub: a JSON list of at most maxList
// objects, each with tag_name, draft, prerelease and body. Other keys do
// not matter. A key counts only when it is written exactly so: Go's JSON
// decoder would also take TAG_NAME for a struct field tag_name. A key of
// a wrong type makes the whole answer not valid. The list is read one
// release at a time, so a long list costs no more than its first
// releases.
func parseList(data []byte) (Info, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return Info{}, errNotValid
	}
	var info Info
	found := false
	for n := 0; dec.More(); n++ {
		if n == maxList {
			return Info{}, errNotValid
		}
		var fields map[string]json.RawMessage
		if err := dec.Decode(&fields); err != nil || fields == nil {
			return Info{}, errNotValid
		}
		r, ok, body, err := parseRelease(fields)
		if err != nil {
			return Info{}, err
		}
		if !ok {
			continue
		}
		if !found || r.Compare(info.Newest) > 0 {
			info.Newest = r
		}
		found = true
		if marked, ids := securityMark(body); marked {
			info.Security = addSecurity(info.Security, r, ids)
		}
	}
	// The end of the list, and nothing after it.
	if tok, err := dec.Token(); err != nil || tok != json.Delim(']') {
		return Info{}, errNotValid
	}
	if _, err := dec.Token(); err != io.EOF {
		return Info{}, errNotValid
	}
	if !found {
		return Info{}, errors.New("GitHub lists no release of nodkey")
	}
	slices.SortFunc(info.Security, func(a, b Security) int { return a.Version.Compare(b.Version) })
	return info, nil
}

// parseRelease reads one release of the list. ok is false for a draft, a
// prerelease, and a tag that is not "vX.Y.Z": such a release does not
// count. body is the notes, "" when they are null or missing.
func parseRelease(fields map[string]json.RawMessage) (r version.Release, ok bool, body string, err error) {
	var tag, notes *string
	var draft, prerelease *bool
	for key, dst := range map[string]any{"tag_name": &tag, "draft": &draft, "prerelease": &prerelease} {
		raw, ok := fields[key]
		// A JSON null leaves the pointer nil.
		if !ok || json.Unmarshal(raw, dst) != nil {
			return version.Release{}, false, "", errNotValid
		}
	}
	if raw, ok := fields["body"]; ok && json.Unmarshal(raw, &notes) != nil {
		return version.Release{}, false, "", errNotValid
	}
	if tag == nil || draft == nil || prerelease == nil {
		return version.Release{}, false, "", errNotValid
	}
	if notes != nil {
		body = *notes
	}
	if *draft || *prerelease || len(*tag) > maxTag {
		return version.Release{}, false, "", nil
	}
	rest, hasV := strings.CutPrefix(*tag, "v")
	r, isRelease := version.ParseRelease(rest)
	if !hasV || !isRelease {
		return version.Release{}, false, "", nil
	}
	return r, true, body, nil
}

// addSecurity adds the security release r with ids to list. When list
// has r already, it adds only the IDs that are new.
func addSecurity(list []Security, r version.Release, ids []string) []Security {
	for k := range list {
		if list[k].Version == r {
			list[k].IDs = addIDs(list[k].IDs, ids)
			return list
		}
	}
	return append(list, Security{Version: r, IDs: ids})
}

// securityMark reports whether the first maxBody bytes of the notes body
// have the line "### Security", after trailing spaces and "\r" are
// removed. ids holds at most maxIDs advisory IDs in the strict GHSA form
// from the lines after it, up to the next line that starts with "#".
func securityMark(body string) (marked bool, ids []string) {
	if len(body) > maxBody {
		body = body[:maxBody]
	}
	for line := range strings.Lines(body) {
		line = strings.TrimRight(strings.TrimSuffix(line, "\n"), " \r")
		switch {
		case !marked:
			marked = line == "### Security"
		case strings.HasPrefix(line, "#"):
			return marked, ids
		default:
			ids = findIDs(ids, line)
		}
	}
	return marked, ids
}

// ghsaChars are the characters of the three parts of a GHSA ID.
const ghsaChars = "23456789cfghjmpqrvwx"

// ghsaLen is the length of a GHSA ID.
const ghsaLen = len("GHSA-xxxx-xxxx-xxxx")

// findIDs adds to ids the GHSA IDs in line that ids does not hold yet,
// until ids holds maxIDs. An ID counts only as a word of its own: a
// letter, a digit, "-" or "_" right before or after it makes it part of a
// longer word.
func findIDs(ids []string, line string) []string {
	for i := 0; len(ids) < maxIDs; {
		j := strings.Index(line[i:], "GHSA-")
		if j < 0 {
			break
		}
		start, end := i+j, i+j+ghsaLen
		i = start + 1
		if end > len(line) || !isGHSA(line[start:end]) {
			continue
		}
		before, _ := utf8.DecodeLastRuneInString(line[:start])
		after, _ := utf8.DecodeRuneInString(line[end:])
		if (start > 0 && isWordRune(before)) || (end < len(line) && isWordRune(after)) {
			continue
		}
		// A copy, so that the ID does not keep the whole answer in memory.
		ids = addIDs(ids, []string{strings.Clone(line[start:end])})
	}
	return ids
}

// isGHSA reports whether id has the strict form of a GHSA ID:
// "GHSA-xxxx-xxxx-xxxx", where each x is one of ghsaChars.
func isGHSA(id string) bool {
	if len(id) != ghsaLen || !strings.HasPrefix(id, "GHSA-") {
		return false
	}
	for k := len("GHSA-"); k < len(id); k++ {
		switch {
		case k == 9 || k == 14:
			if id[k] != '-' {
				return false
			}
		case strings.IndexByte(ghsaChars, id[k]) < 0:
			return false
		}
	}
	return true
}

// isWordRune reports whether r continues a word around a GHSA ID.
func isWordRune(r rune) bool {
	return r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
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
