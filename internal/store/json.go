package store

import (
	"bytes"
	"unicode/utf8"
)

// The answers of bws and bw are JSON. nodkey reads them with its own small
// reader, not with encoding/json, for three reasons:
//
//   - It is strict. The answer must be one JSON object and nothing more,
//     in valid UTF-8 (RFC 8259). A key may appear only once in an object,
//     and keys match only exactly. encoding/json takes the last of two
//     equal keys, matches keys without regard to case, and puts U+FFFD in
//     place of invalid UTF-8 or a lone surrogate (an escape from D800 to
//     DFFF without its pair); that would hand out a changed value.
//   - It decodes a secret into one buffer of the exact size, which the
//     caller can clear. encoding/json makes Go strings, which cannot be
//     cleared, and keeps copies in its own buffers.
//   - It reads only the fields that nodkey needs, and skips the others
//     without keeping them.

// maxDepth is the deepest nesting of objects and arrays in an answer. The
// answers of bws and bw nest at most 4 levels deep.
const maxDepth = 32

// jsonReader reads one JSON text from data.
type jsonReader struct {
	data  []byte
	pos   int
	depth int // the objects and arrays around pos
}

// readAnswer reads data as one JSON object, with only whitespace around
// it. It calls member for each key of the object, with the reader at the
// key's value: member must read the value, for example with skip.
func readAnswer(data []byte, member func(r *jsonReader, key string) error) error {
	r := &jsonReader{data: data}
	r.space()
	if err := r.object(member); err != nil {
		return err
	}
	r.space()
	if r.pos != len(r.data) {
		return ErrBadAnswer
	}
	return nil
}

// space skips whitespace.
func (r *jsonReader) space() {
	for r.pos < len(r.data) {
		switch r.data[r.pos] {
		case ' ', '\t', '\n', '\r':
			r.pos++
		default:
			return
		}
	}
}

// peek returns the next byte, or 0 at the end.
func (r *jsonReader) peek() byte {
	if r.pos < len(r.data) {
		return r.data[r.pos]
	}
	return 0
}

// enter counts one more level of nesting, and refuses too many.
func (r *jsonReader) enter() error {
	if r.depth++; r.depth > maxDepth {
		return ErrBadAnswer
	}
	r.pos++ // the "{" or "["
	r.space()
	return nil
}

// object reads an object, and calls member for each key, as readAnswer
// does. A key that appears twice is an error.
func (r *jsonReader) object(member func(r *jsonReader, key string) error) error {
	if r.peek() != '{' {
		return ErrBadAnswer
	}
	if err := r.enter(); err != nil {
		return err
	}
	if r.peek() == '}' {
		r.pos++
		r.depth--
		return nil
	}
	seen := make(map[string]bool)
	var kb []byte
	for {
		kb = kb[:0]
		if _, err := r.str(&kb); err != nil {
			return err
		}
		key := string(kb)
		if seen[key] {
			return ErrBadAnswer
		}
		seen[key] = true
		r.space()
		if r.peek() != ':' {
			return ErrBadAnswer
		}
		r.pos++
		r.space()
		if err := member(r, key); err != nil {
			return err
		}
		r.space()
		switch r.peek() {
		case ',':
			r.pos++
			r.space()
		case '}':
			r.pos++
			r.depth--
			return nil
		default:
			return ErrBadAnswer
		}
	}
}

// array reads an array and skips its values.
func (r *jsonReader) array() error {
	if r.peek() != '[' {
		return ErrBadAnswer
	}
	if err := r.enter(); err != nil {
		return err
	}
	if r.peek() == ']' {
		r.pos++
		r.depth--
		return nil
	}
	for {
		if err := r.skip(); err != nil {
			return err
		}
		r.space()
		switch r.peek() {
		case ',':
			r.pos++
			r.space()
		case ']':
			r.pos++
			r.depth--
			return nil
		default:
			return ErrBadAnswer
		}
	}
}

// skip reads one value and drops it. It checks the value as strictly as
// the values that nodkey keeps.
func (r *jsonReader) skip() error {
	switch c := r.peek(); {
	case c == '{':
		return r.object(func(r *jsonReader, _ string) error { return r.skip() })
	case c == '[':
		return r.array()
	case c == '"':
		_, err := r.str(nil)
		return err
	case c == 't':
		return r.literal("true")
	case c == 'f':
		return r.literal("false")
	case c == 'n':
		return r.literal("null")
	case c == '-' || '0' <= c && c <= '9':
		return r.number()
	}
	return ErrBadAnswer
}

// literal reads the word lit: true, false or null.
func (r *jsonReader) literal(lit string) error {
	if !bytes.HasPrefix(r.data[r.pos:], []byte(lit)) {
		return ErrBadAnswer
	}
	r.pos += len(lit)
	return nil
}

// null reads null.
func (r *jsonReader) null() error {
	return r.literal("null")
}

// number reads a number: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
func (r *jsonReader) number() error {
	if r.peek() == '-' {
		r.pos++
	}
	switch c := r.peek(); {
	case c == '0':
		r.pos++
	case '1' <= c && c <= '9':
		r.digits()
	default:
		return ErrBadAnswer
	}
	if r.peek() == '.' {
		r.pos++
		if r.digits() == 0 {
			return ErrBadAnswer
		}
	}
	if c := r.peek(); c == 'e' || c == 'E' {
		r.pos++
		if c := r.peek(); c == '+' || c == '-' {
			r.pos++
		}
		if r.digits() == 0 {
			return ErrBadAnswer
		}
	}
	return nil
}

// digits reads digits, and returns how many.
func (r *jsonReader) digits() int {
	start := r.pos
	for r.pos < len(r.data) && '0' <= r.data[r.pos] && r.data[r.pos] <= '9' {
		r.pos++
	}
	return r.pos - start
}

// text reads a string that is not secret, such as a key or a status, of
// at most limit bytes after decoding.
func (r *jsonReader) text(limit int) (string, error) {
	var b []byte
	n, err := r.str(&b)
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", ErrBadAnswer
	}
	return string(b), nil
}

// secret reads a string that holds a secret. It decodes it into a new
// buffer of the exact size, so the buffer never grows and leaves a copy
// behind. The caller must clear the result.
func (r *jsonReader) secret() ([]byte, error) {
	start := r.pos
	n, err := r.str(nil) // check it and measure it
	if err != nil {
		return nil, err
	}
	r.pos = start
	b := make([]byte, 0, n)
	if _, err := r.str(&b); err != nil {
		clear(b[:cap(b)])
		return nil, err
	}
	return b, nil
}

// str reads a string. When out is not nil, it appends the decoded bytes
// to *out. It returns the number of decoded bytes. Control characters, a
// bad escape, invalid UTF-8 and a lone surrogate are errors.
func (r *jsonReader) str(out *[]byte) (int, error) {
	if r.peek() != '"' {
		return 0, ErrBadAnswer
	}
	r.pos++
	n := 0
	put := func(b ...byte) {
		n += len(b)
		if out != nil {
			*out = append(*out, b...)
		}
	}
	var enc [utf8.UTFMax]byte // an escaped character, encoded
	defer clear(enc[:])
	for r.pos < len(r.data) {
		c := r.data[r.pos]
		switch {
		case c == '"':
			r.pos++
			return n, nil
		case c == '\\':
			rn, err := r.escape()
			if err != nil {
				return 0, err
			}
			put(enc[:utf8.EncodeRune(enc[:], rn)]...)
		case c < 0x20:
			return 0, ErrBadAnswer
		case c < utf8.RuneSelf:
			put(c)
			r.pos++
		default:
			rn, size := utf8.DecodeRune(r.data[r.pos:])
			if rn == utf8.RuneError && size == 1 {
				return 0, ErrBadAnswer // invalid UTF-8, also an encoded surrogate
			}
			put(r.data[r.pos : r.pos+size]...)
			r.pos += size
		}
	}
	return 0, ErrBadAnswer // no closing quote
}

// escape reads one escape after a backslash, and returns its character.
// A surrogate pair, a high surrogate (D800 to DBFF) and then a low one
// (DC00 to DFFF), gives one character. A lone surrogate is an error.
func (r *jsonReader) escape() (rune, error) {
	r.pos++ // the backslash
	if r.pos >= len(r.data) {
		return 0, ErrBadAnswer
	}
	c := r.data[r.pos]
	r.pos++
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
	default:
		return 0, ErrBadAnswer
	}
	r1, ok := r.hex4()
	switch {
	case !ok:
		return 0, ErrBadAnswer
	case 0xDC00 <= r1 && r1 < 0xE000: // a low surrogate first
		return 0, ErrBadAnswer
	case r1 < 0xD800 || r1 >= 0xE000:
		return r1, nil
	}
	// A high surrogate: a low one must follow.
	if !bytes.HasPrefix(r.data[r.pos:], []byte(`\u`)) {
		return 0, ErrBadAnswer
	}
	r.pos += 2
	r2, ok := r.hex4()
	if !ok || r2 < 0xDC00 || r2 >= 0xE000 {
		return 0, ErrBadAnswer
	}
	return 0x10000 + (r1-0xD800)<<10 + (r2 - 0xDC00), nil
}

// hex4 reads 4 hex digits.
func (r *jsonReader) hex4() (rune, bool) {
	if len(r.data)-r.pos < 4 {
		return 0, false
	}
	var v rune
	for _, c := range r.data[r.pos : r.pos+4] {
		var d byte
		switch {
		case '0' <= c && c <= '9':
			d = c - '0'
		case 'a' <= c && c <= 'f':
			d = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		v = v<<4 | rune(d)
	}
	r.pos += 4
	return v, true
}
