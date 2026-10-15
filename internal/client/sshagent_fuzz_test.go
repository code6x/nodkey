package client

// Fuzz tests of nodkey ssh-agent, from its security review (issue #13):
// the parser of the agent protocol, envValue, and handle with any
// message.

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
)

// FuzzParseSignRequest: a sign request that parses is exactly
// key, data and flags, with nothing more and nothing less.
func FuzzParseSignRequest(f *testing.F) {
	f.Add(signRequestMessage([]byte("k"), []byte("d"), 0)[1:])
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 1, 'k', 0xff, 0xff, 0xff, 0xf0, 'd', 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, body []byte) {
		key, data, flags, ok := parseSignRequest(body)
		if !ok {
			return
		}
		re := binary.BigEndian.AppendUint32(appendString(appendString(nil, key), data), flags)
		if !bytes.Equal(re, body) {
			t.Fatalf("parsed % x as key % x, data % x, flags %d", body, key, data, flags)
		}
	})
}

// FuzzParseExtension: an extension that parses is exactly its name
// and its contents.
func FuzzParseExtension(f *testing.F) {
	f.Add(extensionMessage(sessionBindRequest, []byte("x"))[1:])
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0x80, 0, 0, 0, 'x'})
	f.Fuzz(func(t *testing.T, body []byte) {
		name, contents, ok := parseExtension(body)
		if !ok {
			return
		}
		if re := append(appendString(nil, []byte(name)), contents...); !bytes.Equal(re, body) {
			t.Fatalf("parsed % x as %q and % x", body, name, contents)
		}
	})
}

// refEnvValue is a plain reading of an environment: the first entry that
// starts with name and "=".
func refEnvValue(env []byte, name string, limit int) (string, bool, bool) {
	for e := range bytes.SplitSeq(env, []byte{0}) {
		if v, ok := bytes.CutPrefix(e, []byte(name+"=")); ok {
			if len(v) > limit {
				return "", true, true
			}
			return string(v), true, false
		}
	}
	return "", false, false
}

// FuzzEnvValue: envValue agrees with a plain reading, in pieces of
// any size.
func FuzzEnvValue(f *testing.F) {
	f.Add([]byte("A=1\x00NODKEY_REASON=x\x00"), uint8(1))
	f.Add([]byte("NODKEY_REASON\x00NODKEY_REASON=y"), uint8(3))
	f.Add([]byte("NODKEY_REASONNODKEY_REASON=z\x00"), uint8(7))
	f.Add([]byte("NODKEY_REASON=0123456789\x00"), uint8(2))
	f.Fuzz(func(t *testing.T, env []byte, piece uint8) {
		const limit = 8
		want, wantFound, wantLong := refEnvValue(env, reasonVar, limit)
		var r io.Reader = bytes.NewReader(env)
		if piece%2 == 0 {
			r = iotest.OneByteReader(r)
		} else {
			r = iotest.HalfReader(r)
		}
		got, found, long := envValue(r, reasonVar, limit)
		if found != wantFound || long != wantLong || (!long && got != want) {
			t.Fatalf("envValue(%q) = %q, %v, %v; want %q, %v, %v", env, got, found, long, want, wantFound, wantLong)
		}
	})
}

// FuzzHandle: handle never panics, answers only failure, success
// for a kept session-bind, or nothing else (the broker cannot be
// reached), keeps a copy of each session-bind, and writes only fixed
// lines.
func FuzzHandle(f *testing.F) {
	f.Add([]byte{agentListRequest})
	f.Add(signRequestMessage([]byte("k"), []byte("d"), 7))
	f.Add(extensionMessage(sessionBindRequest, []byte("bind")))
	f.Add(extensionMessage("query", nil))
	f.Add([]byte{agentAddIdentity, 'x'})
	f.Add([]byte{agentExtension, 0xff, 0xff, 0xff, 0xff})
	key := newTLSKey(f)
	pin := newTLSKey(f).pin
	b, err := newBroker("127.0.0.1:1", key.cert, pin) // nothing listens there
	if err != nil {
		f.Fatal(err)
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		f.Fatal(err)
	}
	ours, theirs := os.NewFile(uintptr(fds[0]), "ours"), os.NewFile(uintptr(fds[1]), "theirs")
	f.Cleanup(func() { _ = ours.Close(); _ = theirs.Close() })
	nc, err := net.FileConn(ours)
	if err != nil {
		f.Fatal(err)
	}
	uc, ok := nc.(*net.UnixConn)
	if !ok {
		f.Fatal("not a Unix connection")
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		if len(msg) == 0 || len(msg) > maxAgentMessage {
			return
		}
		var out syncBuffer
		a := newSSHAgent(b, newAgentLog(&out), procFS{root: "/nonexistent"}, peerCredentials, 0)
		c := &agentConn{a: a, conn: uc}
		in := bytes.Clone(msg)
		answer := c.handle(context.Background(), in)
		kept := len(c.binds)
		if bytes.Equal(answer, []byte{agentSuccess}) {
			if kept != 1 || msg[0] != agentExtension {
				t.Fatalf("success for % x", msg)
			}
			clear(in) // as serveConn does
			_, contents, _ := parseExtension(msg[1:])
			if !bytes.Equal(c.binds[0], contents) {
				t.Fatal("the kept session-bind shares memory with the message")
			}
		} else if !bytes.Equal(answer, failureMessage) {
			t.Fatalf("answer % x to % x", answer, msg)
		}
		for _, l := range linesOf(out.String()) {
			if !strings.HasPrefix(l, "nodkey: ") || strings.ContainsAny(l[8:], "\x00\r\n") {
				t.Fatalf("line %q", l)
			}
		}
	})
}

// chunkReader gives data in pieces whose sizes come from sizes, in turn,
// and records the largest buffer that it gets.
type chunkReader struct {
	data  []byte
	sizes []byte
	i     int
	most  int // the largest buffer it got
}

func (r *chunkReader) Read(p []byte) (int, error) {
	r.most = max(r.most, len(p))
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := 1
	if len(r.sizes) > 0 {
		n = int(r.sizes[r.i%len(r.sizes)])*97 + 1
		r.i++
	}
	n = copy(p, r.data[:min(len(r.data), n)])
	r.data = r.data[n:]
	return n, nil
}

// FuzzReadMessage: readAgentMessage gives exactly the message of a plain
// reading, in pieces of any size, and an error for a short or bad
// message. Its buffer is never much larger than the bytes that came: at
// most firstPiece, or twice those bytes. (From the security review of
// issue #13.)
func FuzzReadMessage(f *testing.F) {
	f.Add(binary.BigEndian.AppendUint32(nil, 5), []byte("hello"), []byte{1, 2, 3})
	f.Add(binary.BigEndian.AppendUint32(nil, 300000), []byte("x"), []byte{255})
	f.Add(binary.BigEndian.AppendUint32(nil, 0), []byte{}, []byte{})
	f.Add([]byte{0, 0}, []byte{}, []byte{0})
	f.Fuzz(func(t *testing.T, head, body, sizes []byte) {
		stream := append(bytes.Clone(head), body...)
		r := &chunkReader{data: bytes.Clone(stream), sizes: sizes}
		msg, err := readAgentMessage(r)
		// The plain reading.
		var want []byte
		wantErr := false
		if len(stream) < 4 {
			wantErr = true
		} else {
			// On 386, a length of 2 GiB or more is less than 0 here.
			n := int(binary.BigEndian.Uint32(stream[:4]))
			switch {
			case n <= 0 || n > maxAgentMessage:
				wantErr = true
			case len(stream)-4 < n:
				wantErr = true
			default:
				want = stream[4 : 4+n]
			}
		}
		if wantErr != (err != nil) || (!wantErr && !bytes.Equal(msg, want)) {
			t.Fatalf("got % x, %v; want % x (an error: %v)", msg, err, want, wantErr)
		}
		if len(stream) >= 4 {
			n := int(binary.BigEndian.Uint32(stream[:4]))
			if n > 0 && n <= maxAgentMessage && r.most > max(4, min(n, firstPiece), min(len(stream)-4, n)*2) {
				t.Fatalf("a buffer of %d bytes for a message of %d bytes, of which %d came", r.most, n, len(stream)-4)
			}
		}
	})
}
