// Package loginmatch decides if a page URL that a client sends matches a
// URI of a Bitwarden login item (DESIGN.md section 21).
//
// It follows the match type of each URI, as Bitwarden does: base domain
// (also when the URI has no match type), host, starts with, and exact. A
// regular expression and "never" do not match. Equivalent domains of
// Bitwarden are not used. The page URL must be https.
//
// "Starts with" and "exact" are stricter than in Bitwarden: the URI must
// be https and have the same host and port as the page.
//
// The page URL is claimed by the client: the broker cannot check that the
// browser is on that page (THREAT-MODEL.md T43).
package loginmatch

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// MaxURL is the longest page URL that a client may send.
const MaxURL = 2048

// Type is the match type of a URI, as the bw CLI writes it in
// login.uris[].match.
type Type int

// The match types of Bitwarden.
const (
	Domain     Type = 0
	Host       Type = 1
	StartsWith Type = 2
	Exact      Type = 3
	Regex      Type = 4
	Never      Type = 5
)

// The errors of ParsePage. They never hold the URL: it is text the client chose.
var (
	ErrPageURL  = errors.New("the page URL is not a valid absolute URL; give the full URL of the login page, for example https://example.com/sign-in")
	ErrHTTPS    = errors.New("the page URL is not https; nodkey hands out logins only for https pages (DESIGN.md section 21)")
	ErrHost     = errors.New("the page URL has no valid host name; give the host as plain ASCII (punycode for other letters), with no user name, password or trailing dot")
	ErrTooLong  = errors.New("the page URL is longer than 2048 bytes; give the URL of the login page only")
	ErrNoSuffix = errors.New("the host of the page URL is a public suffix; give the URL of the site itself")
)

// Page is a page URL that a client sent, after its checks.
type Page struct {
	full   string // the URL with no fragment
	origin string // https://host[:port]
	host   string // lower case, no port
	port   string // "" for 443
	base   string // the base domain of host
}

// Origin returns "https://host" or "https://host:port".
func (p Page) Origin() string { return p.origin }

// URL returns the page URL with no fragment.
func (p Page) URL() string { return p.full }

// ParsePage checks a page URL that a client sent.
func ParsePage(s string) (Page, error) {
	if len(s) > MaxURL {
		return Page{}, ErrTooLong
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return Page{}, ErrPageURL
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.Scheme == "" {
		return Page{}, ErrPageURL
	}
	if u.Scheme != "https" {
		return Page{}, ErrHTTPS
	}
	if u.User != nil {
		return Page{}, ErrHost
	}
	host, port, ok := hostPort(u)
	if !ok {
		return Page{}, ErrHost
	}
	if port == "443" {
		port = ""
	}
	base, ok := baseDomain(host)
	if !ok {
		return Page{}, ErrNoSuffix
	}
	u.Fragment, u.RawFragment = "", ""
	u.Host = host
	if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	}
	origin := "https://" + u.Host
	return Page{full: u.String(), origin: origin, host: host, port: port, base: base}, nil
}

// hostPort returns the lower case host and the port of u. It refuses an
// empty host, a trailing dot, a host that is not plain ASCII letters,
// digits, dots and dashes (or an IP address), and a bad port.
func hostPort(u *url.URL) (string, string, bool) {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return "", "", false
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", "", false
		}
	}
	if host == "" || len(host) > 253 {
		return "", "", false
	}
	if ip := net.ParseIP(host); ip != nil {
		if strings.Contains(host, "%") {
			return "", "", false
		}
		return ip.String(), port, true
	}
	if strings.HasSuffix(host, ".") || strings.HasPrefix(host, ".") || strings.Contains(host, "..") {
		return "", "", false
	}
	labels := strings.Split(host, ".")
	// A last label of digits, or of 0x and hex digits, is an IPv4 address
	// for a browser (https://192.0.2.01/, https://3221225985/), but not
	// for net.ParseIP. Refuse it: the origin would not be where the
	// browser connects.
	if last := labels[len(labels)-1]; strings.HasPrefix(last, "0x") || strings.Trim(last, "0123456789") == "" {
		return "", "", false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", "", false
			}
		}
	}
	return host, port, true
}

// baseDomain returns the registrable domain of host: the public suffix and
// one label more. An IP address and a name with no dot are their own base
// domain. A host that is itself a public suffix has none.
func baseDomain(host string) (string, bool) {
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return host, true
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil || d == "" {
		return "", false
	}
	return d, true
}

// Match reports if the page matches one URI of an item. uri is
// login.uris[].uri and match is login.uris[].match (nil when Bitwarden
// has none: then the base domain is used).
func Match(p Page, uri string, match *int) bool {
	if p.origin == "" || uri == "" || len(uri) > MaxURL {
		return false
	}
	t := Domain
	if match != nil {
		t = Type(*match)
	}
	switch t {
	case Domain, Host:
		host, port, ok := itemHost(uri)
		if !ok {
			return false
		}
		if t == Host {
			return host == p.host && port == p.port
		}
		base, ok := baseDomain(host)
		return ok && base == p.base
	case StartsWith, Exact:
		// Stricter than Bitwarden: the URI must be https, with the same
		// host and port as the page, so that "https://example.com" does
		// not match "https://example.com.example.net/" (T43).
		if !strings.HasPrefix(strings.ToLower(uri), "https://") {
			return false
		}
		host, port, ok := itemHost(uri)
		if !ok || host != p.host || port != p.port {
			return false
		}
		if t == Exact {
			return p.full == uri
		}
		return strings.HasPrefix(p.full, uri)
	default:
		// Regex, Never and any unknown type do not match.
		return false
	}
}

// itemHost reads the host and port of a URI of an item. A URI with no
// scheme is read as http://, as Bitwarden does. Only http and https URIs
// have a host here; androidapp:// and others do not match a page.
func itemHost(uri string) (string, string, bool) {
	s := strings.TrimSpace(uri)
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" {
		return "", "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", "", false
	}
	host, port, ok := hostPort(u)
	if !ok {
		return "", "", false
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	return host, port, true
}
