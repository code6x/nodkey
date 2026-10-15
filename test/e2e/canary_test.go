//go:build e2e

package e2e

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The canary search of DESIGN.md section 17. The first canary is the
// value of the secret in the store: nodkey must never show it, log it or
// send it anywhere but into the environment of the command of nodkey run.
// The second canary is a word in the command line of a parent process of
// ssh: nodkey ssh-agent sends it to the broker as claimed text, and the
// broker masks it before it shows or logs it (DESIGN.md section 7).

// canaryForm is one form of a canary, as the search looks for it.
type canaryForm struct {
	name  string
	value string
}

// formsOf returns the forms of value to look for: as it is, in lower and
// upper case, in hex, and in base64 and base64url. A base64 text holds a
// value in one of 3 ways, by its offset modulo 3 in the bytes that were
// encoded, so there are 3 forms of each: the characters that depend only on
// the value (base64Core). Each name starts with label.
func formsOf(label, value string) []canaryForm {
	h := hex.EncodeToString([]byte(value))
	forms := []canaryForm{
		{label + " as it is", value},
		{label + " in lower case", strings.ToLower(value)},
		{label + " in upper case", strings.ToUpper(value)},
		{label + " in hex", h},
		{label + " in upper-case hex", strings.ToUpper(h)},
	}
	for shift := range 3 {
		forms = append(forms,
			canaryForm{fmt.Sprintf("%s in base64 at offset %d", label, shift), base64Core(base64.RawStdEncoding, value, shift)},
			canaryForm{fmt.Sprintf("%s in base64url at offset %d", label, shift), base64Core(base64.RawURLEncoding, value, shift)})
	}
	return forms
}

// canary1Prefix starts the first canary; the rest of it is random.
const canary1Prefix = "e2e-canary-"

// windowLen is the length of the parts of the first canary that the
// search looks for, so that it finds a value that was cut, too.
const windowLen = 12

// secretForms returns the forms of the first canary to look for (formsOf):
// the whole value, and each part of windowLen characters of its random
// part.
func secretForms(canary string) []canaryForm {
	forms := formsOf("the first canary", canary)
	random := strings.TrimPrefix(canary, canary1Prefix)
	for i := 0; i+windowLen <= len(random); i++ {
		forms = append(forms, formsOf(fmt.Sprintf("a part of the first canary (at %d)", i), random[i:i+windowLen])...)
	}
	return forms
}

// base64Core returns the characters of the base64 of value after shift
// other bytes that depend only on value. Every base64 text that encodes
// value at an offset of shift modulo 3 holds them, whatever comes before
// and after the value.
func base64Core(enc *base64.Encoding, value string, shift int) string {
	s := enc.EncodeToString(append(make([]byte, shift), value...))
	// Character i holds bits 6i to 6i+5; the value has bits 8*shift to
	// 8*(shift+len(value))-1.
	start := (8*shift + 5) / 6
	end := 8 * (shift + len(value)) / 6
	return s[start:end]
}

// found returns the names of the forms that text holds.
func found(text string, forms []canaryForm) []string {
	var names []string
	for _, f := range forms {
		if strings.Contains(text, f.value) {
			names = append(names, f.name)
		}
	}
	return names
}

// TestCanaryForms: the search finds the first canary in each form that it
// looks for, also inside other data, whatever its offset in a base64
// text, and also when only a part of it is there. So a search that finds
// nothing has looked.
func TestCanaryForms(t *testing.T) {
	value := newCanary1(t)
	forms := secretForms(value)
	random := strings.TrimPrefix(value, canary1Prefix)
	for _, part := range []string{value, random[:windowLen], random[len(random)-windowLen-1:], random[3 : 3+windowLen+2]} {
		for _, before := range []string{"", "a", "ab", "abc"} {
			for _, after := range []string{"", "z", "yz"} {
				data := []byte(before + part + after)
				h := hex.EncodeToString(data)
				for name, text := range map[string]string{
					"plain":         string(data),
					"lower case":    strings.ToLower(string(data)),
					"upper case":    strings.ToUpper(string(data)),
					"hex":           h,
					"upper hex":     strings.ToUpper(h),
					"base64":        base64.StdEncoding.EncodeToString(data),
					"raw base64":    base64.RawStdEncoding.EncodeToString(data),
					"base64url":     base64.URLEncoding.EncodeToString(data),
					"raw base64url": base64.RawURLEncoding.EncodeToString(data),
				} {
					if len(found("{"+text+"}", forms)) == 0 {
						t.Errorf("the search does not find %d characters of the canary %s after %q and before %q",
							len(part), name, before, after)
					}
				}
			}
		}
	}
	if got := found(strings.Repeat(canary1Prefix, 10)+random[:windowLen-1], forms); len(got) != 0 {
		t.Errorf("the search finds %q in a text without the canary", got)
	}
}

// hidden holds the canaries while the test runs, so that a failure
// message never shows them (redact).
var hidden struct {
	mu     sync.Mutex
	values []string
}

// hide makes redact replace each of values.
func hide(values ...string) {
	hidden.mu.Lock()
	defer hidden.mu.Unlock()
	hidden.values = append(hidden.values, values...)
}

// redact returns s with each canary replaced by "[canary]", in any case.
// The test prints text only through it, so that a test failure never
// prints a value (AGENTS.md).
func redact(s string) string {
	hidden.mu.Lock()
	defer hidden.mu.Unlock()
	for _, v := range hidden.values {
		for {
			i := strings.Index(asciiLower(s), asciiLower(v))
			if i < 0 {
				break
			}
			s = s[:i] + "[canary]" + s[i+len(v):]
		}
	}
	return s
}

// asciiLower returns s with the ASCII letters A to Z in lower case. It
// keeps the length of s, unlike strings.ToLower.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
