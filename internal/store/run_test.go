package store

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestOutputKeepsUpToTheCap(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, firstBufferSize - 1, firstBufferSize, firstBufferSize + 1, 3 * firstBufferSize, 10000} {
		data := bytes.Repeat([]byte("x"), n)
		for name, rd := range map[string]io.Reader{
			"one read":     bytes.NewReader(data),
			"byte by byte": iotest.OneByteReader(bytes.NewReader(data)),
			"data and EOF": iotest.DataErrReader(bytes.NewReader(data)),
		} {
			full := 0
			o := &output{keep: true, max: 20000, full: func() { full++ }}
			got, err := o.ReadFrom(rd)
			if err != nil || got != int64(n) || !bytes.Equal(o.buf, data) || o.over || full != 0 {
				t.Errorf("%d bytes, %s: ReadFrom = %d, %v; kept %d bytes; over %v; full called %d times",
					n, name, got, err, len(o.buf), o.over, full)
			}
			if cap(o.buf) > o.max+1 {
				t.Errorf("%d bytes, %s: the buffer grew to %d", n, name, cap(o.buf))
			}
		}
	}
}

func TestOutputStopsAtTheCap(t *testing.T) {
	t.Parallel()
	for _, keep := range []bool{true, false} {
		full := 0
		o := &output{keep: keep, max: 100, full: func() { full++ }}
		_, err := o.ReadFrom(strings.NewReader(strings.Repeat("x", 101)))
		if !errors.Is(err, errOverflow) || !o.over || full != 1 {
			t.Errorf("keep %v: ReadFrom over the cap = %v; over %v; full called %d times", keep, err, o.over, full)
		}
		if keep && len(o.buf) > o.max+1 {
			t.Errorf("kept %d bytes", len(o.buf))
		}
		// Later writes fail too, and full is not called again.
		if _, err := o.Write([]byte("x")); !errors.Is(err, errOverflow) || full != 1 {
			t.Errorf("keep %v: Write after the cap = %v; full called %d times", keep, err, full)
		}
		if _, err := o.ReadFrom(strings.NewReader("x")); !errors.Is(err, errOverflow) {
			t.Errorf("keep %v: ReadFrom after the cap = %v", keep, err)
		}
	}
	// Write stops at the cap too, and counts what it took.
	o := &output{keep: true, max: 10}
	if n, err := o.Write([]byte("0123456789")); n != 10 || err != nil {
		t.Errorf("Write up to the cap = %d, %v", n, err)
	}
	if _, err := o.Write([]byte("x")); !errors.Is(err, errOverflow) || !o.over {
		t.Errorf("Write over the cap = %v", err)
	}
}

func TestOutputClearsItsMemory(t *testing.T) {
	t.Parallel()
	secret := madeUp("value")
	o := &output{keep: true, max: 1 << 20}
	if _, err := o.ReadFrom(iotest.HalfReader(strings.NewReader(strings.Repeat(secret, 1000)))); err != nil {
		t.Fatal(err)
	}
	// Each bigger buffer clears the one before it. Keep the last one to
	// look at it after clear.
	last := o.buf[:cap(o.buf)]
	o.clear()
	if !bytes.Equal(last, make([]byte, len(last))) {
		t.Error("clear left bytes in the buffer")
	}
	// stderr: the bytes are only counted, in a buffer that is cleared.
	e := &output{max: 1 << 20}
	if _, err := e.ReadFrom(strings.NewReader(strings.Repeat(secret, 10))); err != nil {
		t.Fatal(err)
	}
	if e.buf != nil || e.n != 10*len(secret) {
		t.Errorf("stderr kept %d bytes, counted %d", len(e.buf), e.n)
	}
	scratch := e.scratch
	e.clear()
	if !bytes.Equal(scratch, make([]byte, len(scratch))) {
		t.Error("clear left bytes in the scratch buffer")
	}
}

func TestOutputReserveClearsTheOldBuffer(t *testing.T) {
	t.Parallel()
	o := &output{keep: true, max: 1 << 20}
	if _, err := o.Write(bytes.Repeat([]byte("s"), firstBufferSize)); err != nil {
		t.Fatal(err)
	}
	old := o.buf[:cap(o.buf)]
	if _, err := o.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(old, make([]byte, len(old))) {
		t.Error("the old buffer was not cleared when the buffer grew")
	}
	if len(o.buf) != firstBufferSize+4 {
		t.Errorf("kept %d bytes", len(o.buf))
	}
}
