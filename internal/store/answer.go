package store

import (
	"bytes"
	"fmt"
)

// The answers that nodkey reads from bws and bw. DESIGN.md section 16
// lists the fields.

// Limits of the keys that a store keeps in memory.
const (
	// maxTokenLen is the longest bws access token. A token has about 100
	// characters.
	maxTokenLen = 4096
	// maxSessionLen is the longest bw session key. A session key is 64
	// random bytes in base64: 88 characters.
	maxSessionLen = 1024
	// maxStatusLen is the longest status in the answer of bw status.
	maxStatusLen = 64
	// maxIDLen is the longest "id" in an answer that nodkey compares with
	// the asked ID. A UUID has 36 characters.
	maxIDLen = 64
)

// The states of bw that bw status reports.
const (
	bwUnauthenticated = "unauthenticated" // logged out
	bwLocked          = "locked"          // logged in, but the session key does not work
	bwUnlocked        = "unlocked"        // logged in, and the session key works
)

// errOtherItem is the error of an answer without an "id", or with the ID
// of another item than the one asked for.
var errOtherItem = fmt.Errorf("%w: it has no id, or the id of another item", ErrBadAnswer)

// parseBWSSecret reads the answer of "bws secret get ID --output json":
// one JSON object. It reads only the fields "id" and "value". "id" must be
// the asked ID id, in upper or lower case. A value that is missing, null or
// empty is ErrNoValue, and one with a NUL byte is ErrBadValue (see
// keepValue). The other fields, such as "key" and "note", are skipped;
// "note" can hold secrets too.
func parseBWSSecret(data []byte, id string) (Value, error) {
	var value []byte
	sameID := false
	err := readAnswer(data, func(r *jsonReader, key string) error {
		switch key {
		case "id":
			return readID(r, id, &sameID)
		case "value":
			switch r.peek() {
			case 'n':
				return r.null()
			case '"':
				b, err := r.secret()
				value = b
				return err
			}
			return ErrBadAnswer
		}
		return r.skip()
	})
	if err == nil && !sameID {
		err = errOtherItem
	}
	return keepValue(value, err)
}

// parseBWItem reads the answer of "bw get item ID": one JSON object. It
// reads only the fields "id", "deletedDate", "archivedDate" and
// "login.password". "id" must be the asked ID id, in upper or lower case.
// An item in the trash (a deletedDate that is not null) is ErrTrashed, and
// an archived item (an archivedDate that is not null) is ErrArchived: bw
// still returns such items by their ID, but its own search skips them. A
// normal item has these two fields as null, or not at all. A password
// with a NUL byte is ErrBadValue (see keepValue). A password that is
// missing, null or empty is ErrNoValue; so is an item that is not
// a login, which has no login field. The other fields are skipped;
// "notes", "fields", "passwordHistory" and "login.totp" can hold secrets
// too.
func parseBWItem(data []byte, id string) (Value, error) {
	var password []byte
	sameID, trashed, archived := false, false, false
	err := readAnswer(data, func(r *jsonReader, key string) error {
		switch key {
		case "id":
			return readID(r, id, &sameID)
		case "deletedDate":
			return readDate(r, &trashed)
		case "archivedDate":
			return readDate(r, &archived)
		case "login":
			if r.peek() == 'n' {
				return r.null()
			}
			return r.object(func(r *jsonReader, key string) error {
				if key != "password" {
					return r.skip()
				}
				switch r.peek() {
				case 'n':
					return r.null()
				case '"':
					b, err := r.secret()
					password = b
					return err
				}
				return ErrBadAnswer
			})
		}
		return r.skip()
	})
	switch {
	case err != nil:
	case !sameID:
		err = errOtherItem
	case trashed:
		err = ErrTrashed
	case archived:
		err = ErrArchived
	}
	return keepValue(password, err)
}

// readID reads the field "id" of an answer. It sets *same when the ID is
// want, in upper or lower case.
func readID(r *jsonReader, want string, same *bool) error {
	got, err := r.text(maxIDLen)
	if err != nil {
		return err
	}
	*same = sameUUID(got, want)
	return nil
}

// sameUUID reports whether a and b are the same text, where only the
// ASCII letters may differ in case. strings.EqualFold also takes other
// letters, such as the Kelvin sign for "k".
func sameUUID(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lower(a[i]) != lower(b[i]) {
			return false
		}
	}
	return true
}

// lower returns c in lower case, if it is an ASCII letter.
func lower(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// readDate reads a date of a bw item, such as "deletedDate": null, or a
// string, which sets *set.
func readDate(r *jsonReader, set *bool) error {
	switch r.peek() {
	case 'n':
		return r.null()
	case '"':
		*set = true
		return r.skip()
	}
	return ErrBadAnswer
}

// keepValue returns b as a Value when err is nil and b is a value that
// nodkey can hand out, and clears b otherwise. An empty value is
// ErrNoValue. A value with a NUL byte is ErrBadValue: a command's
// environment cannot hold it, because execve ends each variable at a NUL.
func keepValue(b []byte, err error) (Value, error) {
	switch {
	case err != nil:
	case len(b) == 0:
		err = ErrNoValue
	case bytes.IndexByte(b, 0) >= 0:
		err = ErrBadValue
	}
	if err != nil {
		clear(b)
		return Value{}, err
	}
	return newValue(b), nil
}

// parseBWStatus reads the answer of "bw status": one JSON object. It
// reads only the field "status": unauthenticated, locked or unlocked. The
// other fields, such as "userEmail", are skipped.
func parseBWStatus(data []byte) (string, error) {
	status := ""
	err := readAnswer(data, func(r *jsonReader, key string) error {
		if key != "status" {
			return r.skip()
		}
		s, err := r.text(maxStatusLen)
		status = s
		return err
	})
	if err != nil {
		return "", err
	}
	switch status {
	case bwUnauthenticated, bwLocked, bwUnlocked:
		return status, nil
	}
	return "", ErrBadAnswer
}

// parseKey reads a bws access token from its file, or a bw session key
// from the answer of "bw unlock --raw". Whitespace at the start and the
// end is dropped, such as the newline at the end of a file. What is left
// must be 1 to limit printable ASCII characters without spaces; a token
// and a session key have no others. It returns a new Value; the caller
// clears data. An error never shows the key.
func parseKey(data []byte, limit int) (Value, bool) {
	start, end := 0, len(data)
	for start < end && isSpace(data[start]) {
		start++
	}
	for end > start && isSpace(data[end-1]) {
		end--
	}
	if end == start || end-start > limit {
		return Value{}, false
	}
	for _, c := range data[start:end] {
		if c <= ' ' || c > '~' {
			return Value{}, false
		}
	}
	return newValue(append([]byte(nil), data[start:end]...)), true
}

// isSpace reports whether c is ASCII whitespace.
func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}
