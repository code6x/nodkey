package store

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
)

// hidden is what fmt, slog and String show in place of a secret.
const hidden = "[hidden]"

// errNotEncoded is the error of MarshalJSON and MarshalText.
var errNotEncoded = errors.New("store: a secret value is never encoded as JSON or text; read it with Bytes")

// Value is a secret: a value from a store, or the bws token or the bw
// session key that a store keeps. fmt, slog, encoding/json and
// encoding/xml never show it: String, GoString, Format and LogValue give
// "[hidden]", and MarshalJSON and MarshalText fail. Read it only with
// Bytes, and Clear it when it is no longer needed.
//
// A Value points to its bytes, and copies of a Value share them: Clear on
// one copy clears them for all. fmt prints an unexported struct field
// without calling its methods; for a Value it then shows only a pointer,
// never the bytes.
type Value struct {
	p *valueBytes
}

// valueBytes holds the bytes of a Value. It hides them from fmt too.
type valueBytes struct {
	b []byte
}

// newValue returns a Value that owns b.
func newValue(b []byte) Value {
	return Value{p: &valueBytes{b: b}}
}

// Bytes returns the value. It is the Value's own memory, not a copy: do
// not change it, and do not keep it after Clear. Never log or print it.
// The zero Value and a cleared Value give nil.
func (v Value) Bytes() []byte {
	if v.p == nil {
		return nil
	}
	return v.p.b
}

// Clear overwrites the value with zeros and forgets it. Clearing is best
// effort: a copy that a caller made, a Go string, or a buffer of the
// operating system is not cleared. Clear must not run at the same time as
// another method of the same Value.
func (v Value) Clear() {
	if v.p == nil {
		return
	}
	clear(v.p.b)
	v.p.b = nil
}

// String returns "[hidden]".
func (Value) String() string { return hidden }

// GoString returns a text without the value, for %#v.
func (Value) GoString() string { return "store.Value{" + hidden + "}" }

// Format writes "[hidden]" for every verb, such as %v, %s, %q and %x.
func (Value) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, hidden) }

// LogValue returns "[hidden]", so slog never logs the value.
func (Value) LogValue() slog.Value { return slog.StringValue(hidden) }

// MarshalJSON fails, so a value cannot be sent or logged as JSON by
// mistake. Code that sends a value must read it with Bytes.
func (Value) MarshalJSON() ([]byte, error) { return nil, errNotEncoded }

// MarshalText fails, as MarshalJSON does.
func (Value) MarshalText() ([]byte, error) { return nil, errNotEncoded }

// String returns "[hidden]".
func (valueBytes) String() string { return hidden }

// GoString returns a text without the value.
func (valueBytes) GoString() string { return "store.valueBytes{" + hidden + "}" }

// Format writes "[hidden]" for every verb.
func (valueBytes) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, hidden) }
