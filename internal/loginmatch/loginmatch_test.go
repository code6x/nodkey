package loginmatch

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func ip(n int) *int { return &n }

func mustPage(t *testing.T, s string) Page {
	t.Helper()
	p, err := ParsePage(s)
	if err != nil {
		t.Fatalf("ParsePage(%q): %v", s, err)
	}
	return p
}

func TestParsePage(t *testing.T) {
	cases := []struct{ in, origin, full string }{
		{"https://example.com/login", "https://example.com", "https://example.com/login"},
		{"https://Example.COM:443/a?b=c#frag", "https://example.com", "https://example.com/a?b=c"},
		{"https://shop.example.co.uk:8443/", "https://shop.example.co.uk:8443", "https://shop.example.co.uk:8443/"},
		{"https://192.0.2.10/", "https://192.0.2.10", "https://192.0.2.10/"},
		{"https://[2001:db8::1]:8443/x", "https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443/x"},
		{"https://xn--bcher-kva.example/", "https://xn--bcher-kva.example", "https://xn--bcher-kva.example/"},
	}
	for _, c := range cases {
		p := mustPage(t, c.in)
		if p.Origin() != c.origin || p.URL() != c.full {
			t.Errorf("%s: got %s %s", c.in, p.Origin(), p.URL())
		}
	}
}

func TestParsePageRefused(t *testing.T) {
	cases := []struct {
		in   string
		want error
	}{
		{"http://example.com/", ErrHTTPS},
		{"HTTP://example.com/", ErrHTTPS},
		{"ftp://example.com/", ErrHTTPS},
		{"javascript:alert(1)", ErrPageURL},
		{"example.com/login", ErrPageURL},
		{"/login", ErrPageURL},
		{"", ErrPageURL},
		{"https://example.com/a b", ErrPageURL},
		{"https://bücher.example/", ErrPageURL},
		{"https://example.com/\x00", ErrPageURL},
		{"https://alice:pw@example.com/", ErrHost},
		{"https://example.com./", ErrHost},
		{"https://.example.com/", ErrHost},
		{"https:///path", ErrHost},
		{"https://exa_mple.com/", ErrHost},
		{"https://-example.com/", ErrHost},
		{"https://example.com:0/", ErrHost},
		{"https://example.com:65536/", ErrHost},
		{"https://example.com:/", ErrHost},
		{"https://example.com:0443/", ErrHost},
		{"https://co.uk/", ErrNoSuffix},
		{"https://192.0.2.01/", ErrHost},
		{"https://0300.0.2.1/", ErrHost},
		{"https://3221225985/", ErrHost},
		{"https://example.0x1f/", ErrHost},
		{"https://github.io/", ErrNoSuffix},
		{"https://example.com/" + strings.Repeat("a", MaxURL), ErrTooLong},
	}
	for _, c := range cases {
		_, err := ParsePage(c.in)
		if !errors.Is(err, c.want) {
			t.Errorf("ParsePage(%.40q): got %v, want %v", c.in, err, c.want)
		}
		if err != nil && c.in != "" && strings.Contains(err.Error(), c.in) {
			t.Errorf("error holds the URL: %v", err)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		page, uri string
		match     *int
		want      bool
	}{
		// Base domain, also with no match type.
		{"https://login.example.com/", "https://example.com", nil, true},
		{"https://example.com/", "https://www.example.com/x", nil, true},
		{"https://example.com/", "example.com", nil, true},
		{"https://example.com:8443/", "https://example.com", ip(0), true},
		{"https://example.org/", "https://example.com", nil, false},
		{"https://example.com.evil.example/", "https://example.com", nil, false},
		{"https://a.example.co.uk/", "https://b.example.co.uk", nil, true},
		{"https://example.co.uk/", "https://other.co.uk", nil, false},
		{"https://alice.github.io/", "https://bob.github.io", nil, false},
		{"https://192.0.2.10/", "https://192.0.2.10:8443/", nil, true},
		{"https://192.0.2.10/", "https://198.51.100.10/", nil, false},
		{"https://192.0.2.10/", "https://10.0.2.10/", nil, false},
		{"https://example.com/", "androidapp://com.example", nil, false},
		{"https://example.com/", "", nil, false},
		{"https://example.com/", "https://co.uk", nil, false},
		// Host: host and port.
		{"https://example.com/", "https://example.com/login", ip(1), true},
		{"https://example.com/", "example.com", ip(1), true},
		{"https://login.example.com/", "https://example.com", ip(1), false},
		{"https://example.com:8443/", "https://example.com", ip(1), false},
		{"https://example.com:8443/", "https://example.com:8443", ip(1), true},
		// Starts with and exact.
		{"https://example.com/login?x=1", "https://example.com/login", ip(2), true},
		{"https://example.com/logout", "https://example.com/login", ip(2), false},
		{"https://example.com.evil.example/", "https://example.com", ip(2), false},
		{"https://example.com:8443/", "https://example.com", ip(2), false},
		{"https://example.com/", "http://example.com/", ip(2), false},
		{"https://example.com/", "example.com/", ip(2), false},
		{"https://example.com/", "HTTPS://example.com/", ip(2), false},
		{"https://example.com/x", "https://example.com", ip(2), true},
		{"https://example.com:8443/x", "https://example.com:8443/", ip(2), true},
		{"https://example.com/", "http://example.com/", ip(3), false},
		{"https://example.com/login", "https://example.com/login", ip(3), true},
		{"https://example.com/login?x=1", "https://example.com/login", ip(3), false},
		{"https://example.com/login#a", "https://example.com/login", ip(3), true},
		// Regex, never and unknown types never match.
		{"https://example.com/", ".*", ip(4), false},
		{"https://example.com/", "https://example.com", ip(4), false},
		{"https://example.com/", "https://example.com", ip(5), false},
		{"https://example.com/", "https://example.com", ip(6), false},
		{"https://example.com/", "https://example.com", ip(-1), false},
	}
	for _, c := range cases {
		p := mustPage(t, c.page)
		if got := Match(p, c.uri, c.match); got != c.want {
			m := "nil"
			if c.match != nil {
				m = strconv.Itoa(*c.match)
			}
			t.Errorf("Match(%s, %s, %s) = %v, want %v", c.page, c.uri, m, got, c.want)
		}
	}
}

func TestZeroPageMatchesNothing(t *testing.T) {
	if Match(Page{}, "https://example.com", nil) {
		t.Fatal("zero page matched")
	}
}

func FuzzParsePage(f *testing.F) {
	f.Add("https://example.com/login", "example.com")
	f.Fuzz(func(t *testing.T, page, uri string) {
		p, err := ParsePage(page)
		if err != nil {
			return
		}
		if !strings.HasPrefix(p.Origin(), "https://") || !strings.HasPrefix(p.URL(), p.Origin()) {
			t.Fatalf("bad page %q -> %q %q", page, p.Origin(), p.URL())
		}
		for m := -1; m < 7; m++ {
			_ = Match(p, uri, &m)
		}
		_ = Match(p, uri, nil)
	})
}
