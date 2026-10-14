package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// refDepth returns the nesting depth of a JSON text as encoding/json's
// streaming decoder sees it, and false if it is not one valid JSON value.
func refDepth(line []byte) (int, bool) {
	dec := json.NewDecoder(bytes.NewReader(line))
	depth, maxd := 0, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return maxd, depth == 0 && json.Valid(line)
		}
		if err != nil {
			return 0, false
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			depth++
			maxd = max(maxd, depth)
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
	}
}

func FuzzTooDeepMatchesDecoder(f *testing.F) {
	for _, s := range []string{
		`{"a":"\\","b":[[["x"]]]}`, `{"a":"\"[[[[","b":1}`, `{"[[[[[":{"]]]]":[]}}`,
		"{\"a\":\"\xff[\xc0\"}", `{"a":""[[["}`, strings.Repeat("[", 17) + strings.Repeat("]", 17),
		strings.Repeat(`{"a":`, 16) + "1" + strings.Repeat("}", 16), `"\\\\\"[[["`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		d, ok := refDepth(line)
		if !ok {
			return // not valid JSON: parseEntry refuses it either way
		}
		if got, want := tooDeep(line), d > maxDepth; got != want {
			t.Fatalf("tooDeep = %v, but the decoder sees depth %d", got, d)
		}
	})
}

// TestEveryEventFitsTheDepthLimit: the deepest entry the broker writes, and Open
// on a log of every event, pass the depth check.
func TestEveryEventFitsTheDepthLimit(t *testing.T) {
	c := newChain(t).addAll()
	for i, line := range c.lines {
		if d, ok := refDepth(line); !ok || d > 2 || tooDeep(line) {
			t.Errorf("line %d: depth %d, valid %v, tooDeep %v", i+1, d, ok, tooDeep(line))
		}
	}
}
