package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"testing"
	"unicode/utf8"
)

// This file has a second, slow implementation of checkJSONShape, made from
// json.Decoder.Token. Its rules are written another way, so FuzzJSONShape
// can compare the two.

// referenceKeyPattern is the form of a key, as a regular expression.
var referenceKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// referenceLevel is an open object or array in referenceShape.
type referenceLevel struct {
	keys    map[string]struct{} // the keys so far; nil in an array
	wantKey bool                // in an object: the next token is a key or "}"
}

// referenceShape is checkJSONShape, made from json.Decoder.Token. It
// reports only whether the body passes, not why.
func referenceShape(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []referenceLevel
	done := false // the outer object is complete
	values := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return done
		}
		if err != nil || done {
			return false
		}
		if n := len(stack); n > 0 && stack[n-1].wantKey {
			if tok == json.Delim('}') {
				stack = stack[:n-1]
				done = referenceEnd(stack)
				continue
			}
			key, ok := tok.(string)
			if !ok || !referenceKeyPattern.MatchString(key) {
				return false
			}
			if _, dup := stack[n-1].keys[key]; dup || len(stack[n-1].keys) == maxJSONKeys {
				return false
			}
			stack[n-1].keys[key] = struct{}{}
			stack[n-1].wantKey = false
			continue
		}
		if len(stack) == 0 && tok != json.Delim('{') {
			return false
		}
		if tok != json.Delim(']') {
			if values++; values > maxJSONValues {
				return false
			}
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			if len(stack) == maxJSONDepth {
				return false
			}
			level := referenceLevel{}
			if tok == json.Delim('{') {
				level = referenceLevel{keys: make(map[string]struct{}), wantKey: true}
			}
			stack = append(stack, level)
		case json.Delim(']'):
			stack = stack[:len(stack)-1]
			done = referenceEnd(stack)
		default: // a string, a number, true, false or null
			done = referenceEnd(stack)
		}
	}
}

// referenceEnd is called after a value ended in referenceShape. It reports
// whether the outer object is complete.
func referenceEnd(stack []referenceLevel) bool {
	if len(stack) == 0 {
		return true
	}
	if top := &stack[len(stack)-1]; top.keys != nil {
		top.wantKey = true
	}
	return false
}

// FuzzJSONShape compares checkJSONShape with referenceShape, and with
// json.Valid: both must pass and refuse the same bodies, and a body that
// passes must be valid JSON.
func FuzzJSONShape(f *testing.F) {
	for _, s := range []string{
		`{}`, ` {"reason":"x"} `, `{"command":["a","b"],"count":-1.5e+3,"flag":true,"opt":null}`,
		`{"secrets":[{"var":"A","name":"b"},{}]}`, `{"reason":"x","reason":"y"}`, `{"Reason":"x"}`,
		`{"reason":"x"}{}`, `{"a":01}`, `{"a":1.}`, `{"a":-}`, `{"a":tru}`, `[]`, `null`, `{"a":"\x"}`,
		`{"command":[[[[]]]]}`, "{\"reason\":\"\x01\"}", `{"a":[1,]}`, `{,}`, `{"a" 1}`, `{"a":1 "b":2}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if !utf8.Valid(data) {
			return // decodeJSON refuses it before checkJSONShape
		}
		err := checkJSONShape(data)
		if err != nil {
			var re *requestError
			if !errors.As(err, &re) {
				t.Fatalf("checkJSONShape(%q) = %v, not a requestError", data, err)
			}
		}
		if want := referenceShape(data); (err == nil) != want {
			t.Fatalf("checkJSONShape(%q) = %v, but the reference says %v", data, err, want)
		}
		if err == nil && !json.Valid(data) {
			t.Fatalf("checkJSONShape(%q) passed, but it is not valid JSON", data)
		}
	})
}
