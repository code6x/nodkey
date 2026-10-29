// Package grantkey is the token of a standing grant (DESIGN.md section 8).
//
// A token is "nkg_", 43 base62 characters (32 random bytes) and 6 base62
// characters of the CRC32 (IEEE) of the part before. All tokens have the
// same length. The broker keeps only the SHA-256 hash of a token.
package grantkey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
)

const (
	prefix    = "nkg_"
	alphabet  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	randBytes = 32
	randChars = 43 // 62^43 > 2^256
	sumChars  = 6  // 62^6 > 2^32

	// Length is the length of every token.
	Length = len(prefix) + randChars + sumChars
)

var (
	// ErrFormat is returned by Parse for anything that is not a token.
	// It never holds the input.
	ErrFormat = errors.New("grantkey: not a grant token")
	bigBase   = big.NewInt(62)
)

// Token is a grant token. It hides its value in every format.
type Token struct {
	v string
}

// String returns a redacted form.
func (Token) String() string { return "nkg_…" }

// GoString returns a redacted form.
func (Token) GoString() string { return "grantkey.Token{nkg_…}" }

// Format prints a redacted form for every verb.
func (Token) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("nkg_…")) }

// Reveal returns the secret value. Use it only to write the token to its
// file or to a header.
func (t Token) Reveal() string { return t.v }

// New makes a new random token.
func New() (Token, error) {
	b := make([]byte, randBytes)
	if _, err := rand.Read(b); err != nil {
		return Token{}, errors.New("grantkey: no random bytes")
	}
	body := prefix + encode(new(big.Int).SetBytes(b), randChars)
	return Token{v: body + checksum(body)}, nil
}

// Parse checks the prefix, the length, the alphabet and the checksum.
// Its errors never hold the input.
func Parse(s string) (Token, error) {
	if len(s) != Length || s[:len(prefix)] != prefix {
		return Token{}, ErrFormat
	}
	for i := len(prefix); i < len(s); i++ {
		if indexOf(s[i]) < 0 {
			return Token{}, ErrFormat
		}
	}
	body := s[:len(prefix)+randChars]
	if subtle.ConstantTimeCompare([]byte(s[len(body):]), []byte(checksum(body))) != 1 {
		return Token{}, ErrFormat
	}
	// The random part must fit in 32 bytes.
	n := new(big.Int)
	for i := len(prefix); i < len(body); i++ {
		n.Mul(n, bigBase)
		n.Add(n, big.NewInt(int64(indexOf(body[i]))))
	}
	if n.BitLen() > randBytes*8 {
		return Token{}, ErrFormat
	}
	return Token{v: s}, nil
}

// Hash returns the SHA-256 hash of the full token string.
func Hash(t Token) [32]byte { return sha256.Sum256([]byte(t.v)) }

// Equal compares two hashes in constant time.
func Equal(a, b [32]byte) bool { return subtle.ConstantTimeCompare(a[:], b[:]) == 1 }

func checksum(body string) string {
	return encode(new(big.Int).SetUint64(uint64(crc32.ChecksumIEEE([]byte(body)))), sumChars)
}

func indexOf(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'Z':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 36
	}
	return -1
}

// encode writes n in base62, padded with '0' to width characters.
func encode(n *big.Int, width int) string {
	out := make([]byte, width)
	for i := width - 1; i >= 0; i-- {
		var m big.Int
		n.DivMod(n, bigBase, &m)
		out[i] = alphabet[m.Int64()]
	}
	return string(out)
}
