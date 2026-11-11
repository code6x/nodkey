package client

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// maskAll writes the chunks to a new maskWriter for values, closes it, and
// returns what it wrote.
func maskAll(t *testing.T, values []string, chunks ...[]byte) string {
	t.Helper()
	var out bytes.Buffer
	vs := make([][]byte, len(values))
	for i, v := range values {
		vs[i] = []byte(v)
	}
	m := newMaskWriter(&out, vs)
	for _, c := range chunks {
		n, err := m.Write(c)
		if err != nil || n != len(c) {
			t.Fatalf("Write = %d, %v; want %d, nil", n, err, len(c))
		}
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out.String()
}

func TestMaskWriter(t *testing.T) {
	const canary = "CANARY-7f3a9c"
	tests := []struct {
		name   string
		values []string
		chunks []string
		want   string
	}{
		{"one value", []string{canary}, []string{"token=" + canary + "\n"}, "token=***\n"},
		{"every time", []string{canary}, []string{canary + canary + " " + canary}, "****** ***"},
		{"no value", []string{canary}, []string{"plain text\n"}, "plain text\n"},
		{"two values", []string{"alpha", "beta"}, []string{"alpha beta gamma"}, "*** *** gamma"},
		{"longest wins", []string{"abc", "abcdef"}, []string{"xabcdefx abcx"}, "x***x ***x"},
		{"split in two", []string{canary}, []string{"a CAN", "ARY-7f3a9c b"}, "a *** b"},
		{"split byte by byte", []string{canary}, split("<" + canary + ">"), "<***>"},
		{"a start that is not a value", []string{canary}, []string{"CANARY-7", "x CANARY"}, "CANARY-7x CANARY"},
		{"a start at the end", []string{canary}, []string{"end CANARY-7f3a9"}, "end CANARY-7f3a9"},
		{"a value inside a false start", []string{"aab"}, []string{"a", "a", "aab"}, "aa***"},
		{"overlap", []string{"aba"}, []string{"ababa"}, "***ba"},
		{"a longer value split, a shorter one whole", []string{"ab", "abcd"}, []string{"ab", "cd ab", "c"}, "*** ***c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks := make([][]byte, len(tt.chunks))
			for i, c := range tt.chunks {
				chunks[i] = []byte(c)
			}
			if got := maskAll(t, tt.values, chunks...); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func split(s string) []string {
	out := make([]string, len(s))
	for i := range s {
		out[i] = s[i : i+1]
	}
	return out
}

// TestMaskWriterBinary checks binary output with a binary value, split at
// every place: the value never comes out, and every other byte does.
func TestMaskWriterBinary(t *testing.T) {
	value := make([]byte, 40)
	_, _ = rand.Read(value)
	value[0] = 0xff // also a byte that is not valid UTF-8
	noise := make([]byte, 300)
	_, _ = rand.Read(noise)
	noise = bytes.ReplaceAll(noise, value[:1], []byte{0}) // no false start
	var in []byte
	in = append(in, noise[:100]...)
	in = append(in, value...)
	in = append(in, noise[100:200]...)
	in = append(in, value...)
	in = append(in, noise[200:]...)
	want := string(noise[:100]) + maskText + string(noise[100:200]) + maskText + string(noise[200:])
	for cut := 0; cut <= len(in); cut++ {
		got := maskAll(t, []string{string(value)}, in[:cut], in[cut:])
		if got != want {
			t.Fatalf("cut at %d: the output is not the input with the value masked", cut)
		}
		if bytes.Contains([]byte(got), value) {
			t.Fatalf("cut at %d: the value is in the output", cut)
		}
	}
}

// TestMaskWriterHoldsBack checks that a start of a value is not written
// before it is known not to be the value.
func TestMaskWriterHoldsBack(t *testing.T) {
	var out bytes.Buffer
	m := newMaskWriter(&out, [][]byte{[]byte("secret"), nil})
	_, _ = m.Write([]byte("a secr"))
	if got := out.String(); got != "a " {
		t.Fatalf("after a start of the value, the output is %q, want %q", got, "a ")
	}
	_, _ = m.Write([]byte("et b"))
	if got := out.String(); got != "a *** b" {
		t.Fatalf("got %q, want %q", got, "a *** b")
	}
	m.clear()
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestMaskWriterError(t *testing.T) {
	m := newMaskWriter(failWriter{}, [][]byte{[]byte("secret")})
	if _, err := m.Write([]byte("x")); err == nil {
		t.Fatal("Write to a broken writer: no error")
	}
}
