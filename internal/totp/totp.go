// Package totp makes TOTP codes (RFC 6238) on the broker, from the
// login.totp field of a Bitwarden item (DESIGN.md section 21).
//
// The seed never leaves the broker: Key hides it in every format, and
// only Code reads it. Two forms are accepted: a plain base32 secret, and
// an otpauth://totp URI with SHA1, SHA256 or SHA512, 6 to 8 digits and
// any period from 1 to 3600 seconds. Every other form (steam://,
// otpauth://hotp, an unknown algorithm) is refused.
//
// No error of this package holds the seed or the field it came from.
package totp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 uses HMAC-SHA1 by default; HMAC-SHA1 is not broken.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Limits of the accepted forms.
const (
	MinDigits  = 6
	MaxDigits  = 8
	MaxPeriod  = 3600
	maxSeedLen = 1024 // bytes of the decoded seed
	maxField   = 4096 // bytes of the login.totp field
)

const hidden = "[totp seed hidden]"

// Algorithm is the HMAC hash of a key.
type Algorithm string

// The accepted algorithms.
const (
	SHA1   Algorithm = "SHA1"
	SHA256 Algorithm = "SHA256"
	SHA512 Algorithm = "SHA512"
)

// The errors of Parse. They never hold the field.
var (
	ErrEmpty     = errors.New("the item has no TOTP seed; add one in the item's \"Authenticator key\" field in Bitwarden")
	ErrForm      = errors.New("the TOTP field is not a base32 secret or an otpauth://totp URI; nodkey makes no codes for steam:// or other forms (DESIGN.md section 21); put a base32 secret or an otpauth://totp URI in the item's \"Authenticator key\" field")
	ErrBase32    = errors.New("the TOTP secret is not valid base32; copy the secret again from the site into the item's \"Authenticator key\" field")
	ErrAlgorithm = errors.New("the otpauth URI names an algorithm other than SHA1, SHA256 or SHA512; nodkey does not make codes for it (DESIGN.md section 21)")
	ErrDigits    = errors.New("the otpauth URI asks for fewer than 6 or more than 8 digits; nodkey does not make codes for it (DESIGN.md section 21)")
	ErrPeriod    = errors.New("the otpauth URI has a period that is not a whole number of seconds from 1 to 3600; fix the period in the item's \"Authenticator key\" field")
)

// Key is a parsed TOTP key. It hides the seed in every format.
type Key struct {
	seed   []byte
	alg    Algorithm
	digits int
	period time.Duration
}

// String returns a redacted form.
func (Key) String() string { return hidden }

// GoString returns a redacted form.
func (Key) GoString() string { return "totp.Key{" + hidden + "}" }

// Format prints a redacted form for every verb.
func (Key) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, hidden) }

// LogValue returns a redacted form.
func (Key) LogValue() slog.Value { return slog.StringValue(hidden) }

// MarshalJSON refuses to encode the key.
func (Key) MarshalJSON() ([]byte, error) { return nil, errors.New("totp: a key is never encoded") }

// MarshalText refuses to encode the key.
func (Key) MarshalText() ([]byte, error) { return nil, errors.New("totp: a key is never encoded") }

// Digits returns the number of digits of a code.
func (k Key) Digits() int { return k.digits }

// Period returns the time step.
func (k Key) Period() time.Duration { return k.period }

// Algorithm returns the HMAC hash.
func (k Key) Algorithm() Algorithm { return k.alg }

// Clear overwrites the seed. The key makes no codes after it.
func (k *Key) Clear() {
	for i := range k.seed {
		k.seed[i] = 0
	}
	k.seed = nil
}

// Parse reads the login.totp field of an item. It does not change or
// keep field: the caller clears it. Every copy of the seed that Parse
// makes is cleared, except the one in the Key, which Clear clears.
func Parse(field []byte) (Key, error) {
	s := bytes.TrimSpace(field)
	if len(s) == 0 {
		return Key{}, ErrEmpty
	}
	if len(s) > maxField {
		return Key{}, ErrForm
	}
	if i := bytes.IndexByte(s, ':'); i >= 0 {
		if !bytes.EqualFold(s[:i], []byte("otpauth")) {
			return Key{}, ErrForm
		}
		return parseURI(s)
	}
	seed, err := decodeBase32(s)
	if err != nil {
		return Key{}, err
	}
	return Key{seed: seed, alg: SHA1, digits: 6, period: 30 * time.Second}, nil
}

// parseURI reads otpauth://totp/LABEL?PARAMS. It reads the parameters on
// the bytes of s, with no copy of the secret. A secret with a percent
// escape is refused: a base32 secret needs none.
func parseURI(s []byte) (Key, error) {
	const prefix = "otpauth://totp/"
	if len(s) < len(prefix) || !bytes.EqualFold(s[:len(prefix)], []byte(prefix)) {
		return Key{}, ErrForm
	}
	q := bytes.IndexByte(s, '?')
	if q < 0 {
		return Key{}, ErrEmpty
	}
	rest := s[q+1:]
	if i := bytes.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	k := Key{alg: SHA1, digits: 6, period: 30 * time.Second}
	var secret []byte
	seen := map[string]bool{}
	for _, part := range bytes.Split(rest, []byte("&")) {
		if len(part) == 0 {
			continue
		}
		name, val, ok := bytes.Cut(part, []byte("="))
		if !ok {
			return Key{}, ErrForm
		}
		// Make a string only of a known name: an unknown name could be
		// a pasted seed, and a string cannot be cleared.
		key := ""
		for _, known := range []string{"secret", "algorithm", "digits", "period"} {
			if bytes.EqualFold(name, []byte(known)) {
				key = known
			}
		}
		if key == "" {
			continue
		}
		if seen[key] {
			return Key{}, ErrForm
		}
		seen[key] = true
		switch key {
		case "secret":
			if bytes.IndexByte(val, '%') >= 0 || bytes.IndexByte(val, '+') >= 0 {
				return Key{}, ErrBase32
			}
			secret = val
		case "algorithm":
			switch Algorithm(strings.ToUpper(string(val))) {
			case SHA1:
				k.alg = SHA1
			case SHA256:
				k.alg = SHA256
			case SHA512:
				k.alg = SHA512
			default:
				return Key{}, ErrAlgorithm
			}
		case "digits":
			n, err := strconv.Atoi(string(val))
			if err != nil || n < MinDigits || n > MaxDigits {
				return Key{}, ErrDigits
			}
			k.digits = n
		case "period":
			n, err := strconv.Atoi(string(val))
			if err != nil || n < 1 || n > MaxPeriod {
				return Key{}, ErrPeriod
			}
			k.period = time.Duration(n) * time.Second
		}
	}
	if len(secret) == 0 {
		return Key{}, ErrEmpty
	}
	seed, err := decodeBase32(secret)
	if err != nil {
		return Key{}, err
	}
	k.seed = seed
	return k, nil
}

// decodeBase32 reads a base32 secret. Spaces and dashes are dropped,
// case does not matter, and padding is optional. It works in buffers of
// a fixed size, and clears the cleaned copy, and the seed on an error.
func decodeBase32(s []byte) ([]byte, error) {
	clean := make([]byte, 0, len(s))
	defer func() { clear(clean[:cap(clean)]) }()
	for _, c := range s {
		switch {
		case c == ' ' || c == '-' || c == '\t' || c == '=':
		case c >= 'a' && c <= 'z':
			clean = append(clean, c-'a'+'A')
		case (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'):
			clean = append(clean, c)
		default:
			return nil, ErrBase32
		}
	}
	if len(clean) == 0 {
		return nil, ErrEmpty
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	seed := make([]byte, enc.DecodedLen(len(clean)))
	n, err := enc.Decode(seed, clean)
	if err != nil || n == 0 || n > maxSeedLen {
		clear(seed)
		return nil, ErrBase32
	}
	if n < len(seed) {
		clear(seed[n:])
	}
	return seed[:n], nil
}

// ErrCleared is returned by Code for a key that was cleared or never parsed.
var ErrCleared = errors.New("totp: the key has no seed")

// Code returns the code for the time t.
func (k Key) Code(t time.Time) (string, error) {
	if len(k.seed) == 0 || k.period <= 0 || k.digits < MinDigits || k.digits > MaxDigits {
		return "", ErrCleared
	}
	unix := t.Unix()
	if unix < 0 {
		return "", errors.New("totp: the time is before 1970; check the broker's clock")
	}
	step := uint64(unix) / uint64(k.period/time.Second)
	return hotp(k.seed, k.alg, k.digits, step), nil
}

// Step returns the number of the time step that holds t. Two codes of
// one key with the same step are the same code.
func (k Key) Step(t time.Time) int64 {
	if k.period <= 0 || t.Unix() < 0 {
		return -1
	}
	return t.Unix() / int64(k.period/time.Second)
}

func hotp(seed []byte, alg Algorithm, digits int, counter uint64) string {
	var h func() hash.Hash
	switch alg {
	case SHA256:
		h = sha256.New
	case SHA512:
		h = sha512.New
	default:
		h = sha1.New
	}
	mac := hmac.New(h, seed)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}
