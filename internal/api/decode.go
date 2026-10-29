package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Errors of the strict decoding and of the caps. They never hold text from
// the data, so they are safe to log.
var (
	errNotObject = errors.New("api: the value is not a JSON object")
	errSyntax    = errors.New("api: the data is not valid JSON")
	errUnknown   = errors.New("api: an object has an unknown field")
	errDuplicate = errors.New("api: a field appears twice in one object")
	errMissing   = errors.New("api: an object misses a field")
	errNull      = errors.New("api: a field or a list item is null")
	errType      = errors.New("api: a value has the wrong type")
	errTrailing  = errors.New("api: more data after the JSON value")
	errTooMany   = errors.New("api: a list has more items than its cap")
	errTooLong   = errors.New("api: a value is longer than its cap")
	errBadWindow = errors.New("api: a window is not valid")
	errBadVar    = errors.New("api: a variable name is not valid")
	errRead      = errors.New("api: the answer could not be read")
	errTooLarge  = errors.New("api: the answer is larger than api.MaxAnswer")
)

// field decodes the value of one field of an object. The value is not
// null.
type field func(raw json.RawMessage) error

// decodeObject decodes the JSON object data. fields has a decoder for each
// field: each one must be in data exactly once, with a value that is not
// null, and data must have no other field. Names must match exactly; Go's
// usual decoding would also take a name in another case.
func decodeObject(data []byte, fields map[string]field) error {
	return decodeObjectOptional(data, fields, nil)
}

// decodeObjectOptional is decodeObject, but the fields named in optional
// may be missing. When present, they are checked as the others are.
func decodeObjectOptional(data []byte, fields map[string]field, optional map[string]bool) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errNotObject
	}
	seen := make(map[string]bool, len(fields))
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return errSyntax
		}
		name, ok := t.(string)
		if !ok {
			return errSyntax
		}
		decode, known := fields[name]
		switch {
		case !known:
			return errUnknown
		case seen[name]:
			return errDuplicate
		}
		seen[name] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return errSyntax
		}
		if isNull(raw) {
			return errNull
		}
		if err := decode(raw); err != nil {
			return err
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return errSyntax
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errTrailing
	}
	for name := range fields {
		if !seen[name] && !optional[name] {
			return errMissing
		}
	}
	return nil
}

// isNull reports whether raw is the JSON value null.
func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// text decodes a JSON string into p.
func text(p *string) field {
	return func(raw json.RawMessage) error { return decodeText(raw, p) }
}

// decodeText decodes the JSON string raw into p.
func decodeText(raw json.RawMessage, p *string) error {
	if !isString(raw) {
		return errType
	}
	if err := json.Unmarshal(raw, p); err != nil {
		return errType
	}
	return nil
}

// binary decodes a JSON string in base64 into p. Go's decoder would also
// take a list of numbers; this one does not.
func binary(p *[]byte) field {
	return func(raw json.RawMessage) error { return decodeBinary(raw, p) }
}

// decodeBinary decodes the JSON string raw, in base64, into p.
func decodeBinary(raw json.RawMessage, p *[]byte) error {
	if !isString(raw) {
		return errType
	}
	var b []byte
	if err := json.Unmarshal(raw, &b); err != nil {
		return errType
	}
	if b == nil {
		b = []byte{}
	}
	*p = b
	return nil
}

// isString reports whether raw starts as a JSON string.
func isString(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 0 && raw[0] == '"'
}

// integer decodes a JSON number without a fraction or an exponent into p.
func integer[T int64 | int | uint32](p *T) field {
	return func(raw json.RawMessage) error {
		if err := json.Unmarshal(raw, p); err != nil {
			return errType
		}
		return nil
	}
}

// textList decodes a JSON list of strings into p: at most most items,
// none of them null.
func textList(p *[]string, most int) field {
	return func(raw json.RawMessage) error { return decodeTextList(raw, p, most) }
}

// decodeTextList decodes the JSON list of strings raw into p.
func decodeTextList(raw json.RawMessage, p *[]string, most int) error {
	var items []*string
	if err := json.Unmarshal(raw, &items); err != nil || items == nil {
		return errType
	}
	if len(items) > most {
		return errTooMany
	}
	out := make([]string, len(items))
	for i, s := range items {
		if s == nil {
			return errNull
		}
		out[i] = *s
	}
	*p = out
	return nil
}

// list decodes a JSON list into p, with decode for each item: at most
// most items, none of them null.
func list[T any](p *[]T, most int, decode func(json.RawMessage, *T) error) field {
	return func(raw json.RawMessage) error {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil || items == nil {
			return errType
		}
		if len(items) > most {
			return errTooMany
		}
		out := make([]T, len(items))
		for i, item := range items {
			err := errNull
			if !isNull(item) {
				err = decode(item, &out[i])
			}
			if err != nil {
				wipeAll(out[:i])
				return err
			}
		}
		*p = out
		return nil
	}
}

// wiper is an item that holds a secret, such as a SecretValue.
type wiper interface{ wipe() }

// wipeAll overwrites the secrets of the items that list decoded before an
// item failed, as best effort.
func wipeAll[T any](items []T) {
	for i := range items {
		if w, ok := any(&items[i]).(wiper); ok {
			w.wipe()
		}
	}
}

// object returns a decoder of list items that are objects of type T, for
// list.
func object[T any, P interface {
	*T
	json.Unmarshaler
}]() func(json.RawMessage, *T) error {
	return func(raw json.RawMessage, p *T) error { return P(p).UnmarshalJSON(raw) }
}

// orEmpty returns s, or an empty slice for nil: JSON writes a nil slice as
// null, which the other side refuses.
func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ReadAnswer reads an answer body of at most MaxAnswer bytes and decodes
// it strictly into a new T, such as SecretsAnswer. The client calls it for
// an answer with status 200. The bytes it read are cleared, as best
// effort: an answer may hold secret values. Errors never hold text from
// the answer.
func ReadAnswer[T any, P interface {
	*T
	json.Unmarshaler
}](body io.Reader) (*T, error) {
	data, err := io.ReadAll(io.LimitReader(body, MaxAnswer+1))
	defer clear(data)
	if err != nil {
		return nil, errRead
	}
	if len(data) > MaxAnswer {
		return nil, errTooLarge
	}
	v := new(T)
	if err := P(v).UnmarshalJSON(bytes.TrimSpace(data)); err != nil {
		return nil, err
	}
	return v, nil
}
