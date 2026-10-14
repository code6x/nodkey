package approval

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// idSize is the size of a request ID in bytes (DESIGN.md section 7).
const idSize = 16

// codeAlphabet holds the characters of a short code: lower case letters
// and digits, without 0, 1, i, l and o, which people mix up.
const codeAlphabet = "23456789abcdefghjkmnpqrstuvwxyz"

// codeSize is the length of a short code, such as "k3f9".
const codeSize = 4

// Tries before register gives up. With crypto/rand, the first try works.
const (
	idTries   = 4
	codeTries = 32
)

// newID returns a new request ID: idSize random bytes in base64url
// without padding.
func newID(random io.Reader) (string, error) {
	var b [idSize]byte
	if _, err := io.ReadFull(random, b[:]); err != nil {
		return "", fmt.Errorf("approval: cannot read random bytes for a request ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// newCode returns a random short code. Each character is uniform over
// codeAlphabet: bytes that would make some characters more likely are
// skipped.
func newCode(random io.Reader) (string, error) {
	const limit = 256 - 256%len(codeAlphabet)
	var code [codeSize]byte
	var buf [16]byte
	n := 0
	for range 8 {
		if _, err := io.ReadFull(random, buf[:]); err != nil {
			return "", fmt.Errorf("approval: cannot read random bytes for a short code: %w", err)
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			code[n] = codeAlphabet[int(b)%len(codeAlphabet)]
			if n++; n == codeSize {
				return string(code[:]), nil
			}
		}
	}
	return "", errors.New("approval: the random bytes for a short code are not random")
}

// register gives p a request ID and a short code that no other request in
// Decide has. The short code is only for people, but two requests with one
// code at the same time would confuse them.
func (c *Core) register(p *pending) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for range idTries {
		id, err := newID(c.random)
		if err != nil {
			return err
		}
		if c.ids[id] != nil {
			continue
		}
		for range codeTries {
			code, err := newCode(c.random)
			if err != nil {
				return err
			}
			if c.codes[code] {
				continue
			}
			p.id, p.code = id, code
			c.ids[id] = p
			c.codes[code] = true
			return nil
		}
		return errors.New("approval: cannot make a short code that no other request has")
	}
	return errors.New("approval: cannot make a request ID that no other request has")
}
