// Package config loads the broker and client config files and checks them
// (DESIGN.md section 14).
//
// Loading is strict. An unknown key, a missing key or a value out of range
// is an error, so a typo cannot turn a rule off. An error names the section
// and the key, or the line. It may show a file path, or a section name or
// key name that looks normal. It never shows a value from a file, or a name
// that does not look normal, because a mistake can put a token there.
package config

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// namePattern is the form of every name a person chooses: clients, stores,
// secrets, keys and known hosts. These names appear in the verified part
// of approval messages (DESIGN.md section 7).
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// nameRule says what namePattern allows, for error messages.
const nameRule = `must be 1 to 64 letters, digits, ".", "_" or "-", starting with a letter or digit`

// keyPattern is the form of the keys that nodkey defines, such as tls_key.
var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// shownKeyPattern is the form of each part of a key name that an error may
// show, such as "telegram" and "user_id" in telegram.user_id: at most 16
// characters. The longest key that nodkey defines, notice_chat_id, has 14.
// Other text may have been pasted by mistake, such as a token.
var shownKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)

// bareKeyPattern is the form of a TOML key that needs no quotes.
var bareKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// sectionName returns how a named section is written in a file, such as
// [secret.github-token]. A name that is not a bare TOML key is quoted.
func sectionName(kind, name string) string {
	if !bareKeyPattern.MatchString(name) {
		name = strconv.Quote(name)
	}
	return "[" + kind + "." + name + "]"
}

// place names a key for an error message: "[telegram] user_id", or only
// the key for one at the top of the file.
func place(section, key string) string {
	if section == "" {
		return key
	}
	return section + " " + key
}

// keyText returns the key k, quoted, for an error message, such as
// "secret.github-token.windw". ok is false when k may hold pasted text:
// when a part does not match shownKeyPattern, or when a section name
// breaks the name rule (namePattern). A section name is the part after one
// of nameSections, such as github-token in secret.github-token; it may
// hold "-", and approval messages show it anyway. An error must not show a
// key for which ok is false.
func keyText(k toml.Key, nameSections []string) (string, bool) {
	if len(k) == 0 {
		return "", false
	}
	for i, part := range k {
		pattern := shownKeyPattern
		if i == 1 && slices.Contains(nameSections, k[0]) {
			pattern = namePattern
		}
		if !pattern.MatchString(part) {
			return "", false
		}
	}
	return strconv.Quote(k.String()), true
}

// unknownKeysError returns the error for the unknown keys, sorted. It
// lists the names that keyText shows, and only counts the others.
func unknownKeysError(keys []toml.Key, nameSections []string) error {
	var shown []string
	hidden := 0
	for _, k := range keys {
		if s, ok := keyText(k, nameSections); ok {
			shown = append(shown, s)
		} else {
			hidden++
		}
	}
	var msg string
	switch len(shown) {
	case 0:
	case 1:
		msg = "unknown key " + shown[0]
	default:
		msg = "unknown keys " + strings.Join(shown, ", ")
	}
	if hidden == 0 {
		return errors.New(msg)
	}
	more := ""
	if msg != "" {
		more = "more "
	}
	count := fmt.Sprintf("%d %sunknown key", hidden, more)
	if hidden > 1 {
		count += "s"
	}
	if msg != "" {
		count = msg + ", and " + count
	}
	return errors.New(count + "; an error shows a key name only if it looks like a config key, such as tls_key")
}

// errNotConfig is the error for a file that cannot be read as a config
// file, when nothing more can be said without repeating text from it.
var errNotConfig = errors.New("not a valid config file")

// decode parses TOML data into v. On top of the TOML library, it refuses
// unknown keys, keys that match ours only when case is ignored, and a
// value that is not a table where named sections are expected.
// nameSections are the sections whose subtables carry a name the person
// chose, such as "secret" in [secret.github-token]. A panic while decoding
// becomes an error (see decodeWith); on any error, v must not be used.
func decode(data []byte, v any, nameSections ...string) error {
	return decodeWith(toml.Decode, data, v, nameSections...)
}

// tomlDecoder is the form of toml.Decode.
type tomlDecoder = func(data string, v any) (toml.MetaData, error)

// decodeWith is decode with the TOML library's Decode function as a
// parameter, so that a test can pass one that panics.
//
// It recovers from a panic and returns errNotConfig. A panic in the TOML
// library is a bug there, and its message can repeat text from the file,
// such as a token pasted by mistake. So the error says only that the file
// is not valid, and the panic value is dropped.
func decodeWith(tomlDecode tomlDecoder, data []byte, v any, nameSections ...string) (err error) {
	// finished is set only when decodeStrict returns. So a panic always
	// gives an error, even one whose value recover returns as nil
	// (panic(nil) with GODEBUG=panicnil=1).
	finished := false
	defer func() {
		if !finished {
			_ = recover()
			err = errNotConfig
		}
	}()
	err = decodeStrict(tomlDecode, data, v, nameSections)
	finished = true
	return err
}

// decodeStrict is the work of decode, for decodeWith.
func decodeStrict(tomlDecode tomlDecoder, data []byte, v any, nameSections []string) error {
	md, err := tomlDecode(string(data), v)
	if err != nil {
		return tomlError(err)
	}
	// BurntSushi/toml v1.6.0 silently drops a value that is not a table
	// when it decodes into a Go map (secret = "x").
	for _, s := range nameSections {
		if t := md.Type(s); t != "" && t != "Hash" {
			return fmt.Errorf("%s: must be a table, such as [%s.NAME]", s, s)
		}
	}
	unknown := make(map[string]toml.Key)
	for _, k := range md.Undecoded() {
		unknown[k.String()] = k
	}
	// The library matches keys to fields without regard to case. So
	// "ASK" would set ask, and with both in one table the result would
	// depend on map order. Only our exact keys are allowed.
	for _, k := range md.Keys() {
		for i, part := range k {
			if i == 1 && slices.Contains(nameSections, k[0]) {
				continue
			}
			if !keyPattern.MatchString(part) {
				unknown[k.String()] = k
				break
			}
		}
	}
	if len(unknown) > 0 {
		var keys []toml.Key
		for _, s := range slices.Sorted(maps.Keys(unknown)) {
			keys = append(keys, unknown[s])
		}
		return unknownKeysError(keys, nameSections)
	}
	if line := inlineTableLine(string(data)); line > 0 {
		return fmt.Errorf("line %d: inline tables ({ ... }) are not allowed; write each section below its own [header]", line)
	}
	return checkHeaders(md, nameSections)
}

// checkHeaders checks that every key is written below the header of its
// own section, such as ask below [secret.github-token]. The TOML library
// also takes a dotted key (secret.github-token.ask = ...) at the top of the
// file, or below [secret], and merges it into the section. Then a reader
// of the section would not see that key. Inline tables must already be
// refused: the library lists them like headers. The key names here are
// known keys, but a section name may be pasted text, so the error shows a
// key only when keyText does.
func checkHeaders(md toml.MetaData, nameSections []string) error {
	var section toml.Key // the section of the last header; empty at the top
	for _, k := range md.Keys() {
		switch md.Type(k...) {
		case "Hash", "ArrayHash":
			section = k
			continue
		}
		if parent := k[:len(k)-1]; !slices.Equal(parent, section) {
			key, ok := keyText(k, nameSections)
			if !ok {
				return errors.New("a key is not below the header of its own section; write each key " +
					"below its own [header], not as a dotted key (the key is not shown here)")
			}
			return fmt.Errorf("key %s: write it as %s = ... below its own [%s] header, not as a dotted key",
				key, toml.Key{k[len(k)-1]}, parent)
		}
	}
	return nil
}

// inlineTableLine returns the line of the first inline table ({ ... }) in
// TOML data, or 0 if there is none. Outside strings and comments, "{"
// starts an inline table and nothing else. The data must already be valid
// TOML.
func inlineTableLine(data string) int {
	line := 1
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\n':
			line++
		case '#':
			for i+1 < len(data) && data[i+1] != '\n' {
				i++
			}
		case '"', '\'':
			i, line = skipString(data, i, line)
		case '{':
			return line
		}
	}
	return 0
}

// skipString skips the TOML string that starts at data[i]. It returns the
// index of the string's last byte and the line number there.
func skipString(data string, i, line int) (int, int) {
	quote := data[i]
	delim := data[i : i+1]
	if strings.HasPrefix(data[i:], strings.Repeat(delim, 3)) {
		delim = strings.Repeat(delim, 3)
	}
	for j := i + len(delim); j < len(data); j++ {
		switch {
		case data[j] == '\\' && quote == '"':
			// An escape: skip the next byte. In a multi-line string it
			// can be a newline.
			if j+1 < len(data) && data[j+1] == '\n' {
				line++
			}
			j++
		case data[j] == '\n':
			line++
		case strings.HasPrefix(data[j:], delim):
			end := j + len(delim)
			// A multi-line string may end with one or two quotes of its
			// own before the closing three.
			for k := 0; len(delim) == 3 && k < 2 && end < len(data) && data[end] == quote; k++ {
				end++
			}
			return end - 1, line
		}
	}
	return len(data) - 1, line // not closed; the TOML parser refuses that
}

// typeError is the form of the TOML library's other errors, such as
// `toml: line 9 (last key "telegram.user_id"): incompatible types: ...`.
// The text after the key names two types, never a value.
var typeError = regexp.MustCompile(`^toml: (?:line ([0-9]+) )?\(last key "(?:[^"\\]|\\.)*"\): (.+)$`)

// tomlError keeps only the position of a TOML syntax error. The library's
// message, and even the key it names, can repeat text pasted into the
// file. Its other errors (typeError) name the last key and two types. The
// key can hold a section name that is pasted text, so only the line and
// the types are kept. An error of any other form is not shown.
func tomlError(err error) error {
	var pe toml.ParseError
	var ppe *toml.ParseError
	switch {
	case errors.As(err, &pe):
	case errors.As(err, &ppe):
		// The library returns a ParseError, not a pointer. Take a pointer
		// too, so that a change in the library cannot let the text through.
		if ppe == nil {
			return errors.New("not valid TOML")
		}
		pe = *ppe
	default:
		m := typeError.FindStringSubmatch(err.Error())
		switch {
		case m == nil:
			return errNotConfig
		case m[1] == "":
			return errors.New(m[2])
		default:
			return fmt.Errorf("line %s: %s", m[1], m[2])
		}
	}
	return fmt.Errorf("line %d, column %d: not valid TOML, or a number out of range",
		pe.Position.Line, pe.Position.Col)
}

// parsePath expands a path from a config file and checks that it is set
// and absolute. A relative path would depend on the working directory.
func parsePath(section, key, p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%s: is missing", place(section, key))
	}
	x, err := ExpandPath(p)
	if err != nil {
		return "", fmt.Errorf("%s: %w", place(section, key), err)
	}
	if !filepath.IsAbs(x) {
		return "", fmt.Errorf("%s: must be an absolute path, or start with ${CREDENTIALS_DIRECTORY}/ or ~/",
			place(section, key))
	}
	return x, nil
}

// parseDuration parses a duration such as "90s" or "15m". The error does
// not repeat the text.
func parseDuration(section, key, s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf(`%s: must be a duration such as "90s" or "15m"`, place(section, key))
	}
	return d, nil
}

// formatDuration writes d for a person: "10m", not "10m0s".
func formatDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// Pin is the SHA-256 hash of a TLS public key, taken over its DER
// SubjectPublicKeyInfo. Each side of a connection pins the other side's key
// with it (DESIGN.md section 10).
type Pin [sha256.Size]byte

const pinPrefix = "sha256:"

var errBadPin = errors.New(`must be "sha256:" and 43 base64 characters, as printed by nodkey keygen`)

// ParsePin parses a pin in the form that String returns: "sha256:" and
// the hash in standard base64 without padding. Only that exact form is
// accepted, so two different texts never give the same pin.
func ParsePin(s string) (Pin, error) {
	var p Pin
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(s, pinPrefix))
	if err != nil || len(b) != len(p) {
		return Pin{}, errBadPin
	}
	copy(p[:], b)
	// The decoder skips newlines and ignores unused bits, so compare the
	// text with the one exact form.
	if p.String() != s {
		return Pin{}, errBadPin
	}
	return p, nil
}

// String returns the pin as "sha256:" and the hash in standard base64
// without padding.
func (p Pin) String() string {
	return pinPrefix + base64.RawStdEncoding.EncodeToString(p[:])
}
