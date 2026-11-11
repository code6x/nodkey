package client

import (
	"bytes"
	"io"
	"sort"
)

// maskText replaces each fetched value in the output of the command
// (nodkey run --mask, DESIGN.md section 5).
const maskText = "***"

// maskWriter writes to w what is written to it, with each value replaced
// by maskText. A value may be split across writes: maskWriter holds back
// the end of the data while it may still be the start of a value, and
// writes it with the next write, or with Close. At one place, the longest
// value that matches wins. maskWriter never writes a part of a value.
// It is not safe for use by more than one goroutine.
type maskWriter struct {
	w      io.Writer
	values [][]byte // longest first; none is empty
	first  [256]bool
	buf    []byte // data that may still be the start of a value
}

// newMaskWriter returns a maskWriter for the values. Empty values are
// left out. It keeps its own copy of the values; clear wipes it.
func newMaskWriter(w io.Writer, values [][]byte) *maskWriter {
	m := &maskWriter{w: w}
	for _, v := range values {
		if len(v) == 0 {
			continue
		}
		c := bytes.Clone(v)
		m.values = append(m.values, c)
		m.first[c[0]] = true
	}
	sort.SliceStable(m.values, func(i, j int) bool { return len(m.values[i]) > len(m.values[j]) })
	return m
}

// Write masks p and writes all of it that cannot be the start of a value.
// It reports len(p) when the writes to w succeed.
func (m *maskWriter) Write(p []byte) (int, error) {
	m.buf = append(m.buf, p...)
	if err := m.flush(false); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close writes the data that is held back, masked. It does not close w.
func (m *maskWriter) Close() error {
	return m.flush(true)
}

// flush writes m.buf to w, masked. Unless final, it keeps the end of
// m.buf that is the start of a longer value.
func (m *maskWriter) flush(final bool) error {
	var out []byte
	b := m.buf
	i := 0
	for i < len(b) {
		// Copy the bytes that cannot start a value as they are.
		j := i
		for j < len(b) && !m.first[b[j]] {
			j++
		}
		out = append(out, b[i:j]...)
		if i = j; i == len(b) {
			break
		}
		rest := b[i:]
		if !final && m.mayGrow(rest) {
			break
		}
		if n := m.match(rest); n > 0 {
			out = append(out, maskText...)
			i += n
			continue
		}
		out = append(out, b[i])
		i++
	}
	// Keep the held bytes at the start of buf; wipe the rest of it.
	held := copy(m.buf, b[i:])
	clear(m.buf[held:])
	m.buf = m.buf[:held]
	if len(out) == 0 {
		return nil
	}
	_, err := m.w.Write(out)
	clear(out)
	return err
}

// mayGrow reports whether rest is a start of a value longer than rest,
// so that more data may make it a value.
func (m *maskWriter) mayGrow(rest []byte) bool {
	for _, v := range m.values {
		if len(v) <= len(rest) {
			return false // the rest are shorter still
		}
		if bytes.HasPrefix(v, rest) {
			return true
		}
	}
	return false
}

// match returns the length of the longest value at the start of rest, or 0.
func (m *maskWriter) match(rest []byte) int {
	for _, v := range m.values {
		if bytes.HasPrefix(rest, v) {
			return len(v)
		}
	}
	return 0
}

// clear wipes the copies of the values and the held data.
func (m *maskWriter) clear() {
	for _, v := range m.values {
		clear(v)
	}
	clear(m.buf)
	m.buf = m.buf[:0]
}
