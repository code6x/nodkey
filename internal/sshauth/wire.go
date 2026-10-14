package sshauth

import (
	"encoding/binary"
	"fmt"
)

// The two methods of RFC 4252 section 7 that this package signs.
const (
	methodPublicKey = "publickey"
	methodHostbound = "publickey-hostbound-v00@openssh.com"
)

// serviceConnection is the only service a login may ask for.
const serviceConnection = "ssh-connection"

// msgUserAuthRequest is SSH_MSG_USERAUTH_REQUEST (RFC 4252 section 6).
const msgUserAuthRequest = 50

// reader reads SSH wire data (RFC 4251 section 5). After a read fails,
// every later read fails too, so a parser checks ok once at the end.
type reader struct {
	b  []byte
	ok bool
}

func newReader(b []byte) *reader { return &reader{b: b, ok: true} }

// readByte reads one byte.
func (r *reader) readByte() byte {
	if !r.ok || len(r.b) < 1 {
		r.ok = false
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

// readString reads a string: a uint32 length and that many bytes. The result
// shares memory with the data.
func (r *reader) readString() []byte {
	if !r.ok || len(r.b) < 4 {
		r.ok = false
		return nil
	}
	n := binary.BigEndian.Uint32(r.b)
	rest := r.b[4:]
	if int64(n) > int64(len(rest)) {
		r.ok = false
		return nil
	}
	s := rest[:n:n]
	r.b = rest[n:]
	return s
}

// done reports whether every read worked and no byte is left.
func (r *reader) done() bool { return r.ok && len(r.b) == 0 }

// validSessionID reports whether id has the length of a session
// identifier of a key exchange this package accepts: the output of
// SHA-256, SHA-384 or SHA-512. Key exchanges with SHA-1 give 20 bytes;
// OpenSSH 8.9 and newer do not use them by default.
func validSessionID(id []byte) bool {
	switch len(id) {
	case 32, 48, 64:
		return true
	}
	return false
}

// sessionBind is the content of one session-bind@openssh.com message
// (OpenSSH PROTOCOL.agent):
//
//	string  hostkey
//	string  session identifier
//	string  signature
//	bool    is_forwarding
//
// The signature is the one the server sent in the key exchange: the host
// key's signature over the session identifier. parseBind checks only the
// form; checkBind checks the host key and the signature.
type sessionBind struct {
	hostKey    []byte // the host key in SSH wire form
	sessionID  []byte
	signature  []byte // an SSH signature: string format, string blob
	forwarding bool
}

// parseBind parses the content of a session-bind@openssh.com message: the
// bytes after the extension name. It refuses a message that is too long
// or too short, a session identifier of an odd length, an is_forwarding
// byte other than 0 or 1, and bytes after the last field. The result
// shares memory with b.
func parseBind(b []byte) (*sessionBind, error) {
	if len(b) > MaxBindLen {
		return nil, fmt.Errorf("%w: it is longer than %d bytes", ErrBadBind, MaxBindLen)
	}
	r := newReader(b)
	sb := &sessionBind{
		hostKey:   r.readString(),
		sessionID: r.readString(),
		signature: r.readString(),
	}
	forwarding := r.readByte()
	switch {
	case !r.done():
		return nil, fmt.Errorf("%w: it does not have the form hostkey, session identifier, signature, is_forwarding", ErrBadBind)
	case !validSessionID(sb.sessionID):
		return nil, fmt.Errorf("%w: the session identifier is not 32, 48 or 64 bytes long", ErrBadBind)
	case forwarding > 1:
		return nil, fmt.Errorf("%w: is_forwarding is not 0 or 1", ErrBadBind)
	}
	sb.forwarding = forwarding == 1
	return sb, nil
}

// signature is an SSH signature as it is in a session-bind (RFC 4253
// section 6.6): string format, string blob.
type signature struct {
	format string
	blob   []byte
}

// parseSignature parses an SSH signature. It refuses bytes after the
// blob, so it refuses the extra fields of security key signatures too.
func parseSignature(b []byte) (*signature, error) {
	r := newReader(b)
	s := &signature{format: string(r.readString()), blob: r.readString()}
	if !r.done() {
		return nil, fmt.Errorf("%w: the signature does not have the form format, blob", ErrBadBind)
	}
	return s, nil
}

// loginData is the data that ssh signs to log in with a public key (RFC
// 4252 section 7):
//
//	string   session identifier
//	byte     SSH_MSG_USERAUTH_REQUEST (50)
//	string   user name
//	string   service name ("ssh-connection")
//	string   "publickey"
//	boolean  TRUE (the request has a signature)
//	string   public key algorithm name
//	string   public key
//
// For "publickey-hostbound-v00@openssh.com" (OpenSSH PROTOCOL), the
// server's host key follows:
//
//	string   server host key
type loginData struct {
	sessionID []byte
	user      string
	method    string
	algorithm string // the public key algorithm name
	key       []byte // the public key in SSH wire form
	hostKey   []byte // only for methodHostbound
}

// hostbound reports whether the data uses the hostbound method.
func (d *loginData) hostbound() bool { return d.method == methodHostbound }

// parseData parses the data to sign as a login request with a public key.
// It refuses data that is too long, any other message, service or method,
// a request without the signature flag, a session identifier of an odd
// length, and bytes after the last field. All its errors wrap
// ErrNotLogin. The result shares memory with b.
func parseData(b []byte) (*loginData, error) {
	if len(b) > MaxDataLen {
		return nil, fmt.Errorf("%w: it is longer than %d bytes", ErrNotLogin, MaxDataLen)
	}
	r := newReader(b)
	d := &loginData{sessionID: r.readString()}
	msg := r.readByte()
	d.user = string(r.readString())
	service := string(r.readString())
	d.method = string(r.readString())
	hasSignature := r.readByte()
	d.algorithm = string(r.readString())
	d.key = r.readString()
	if !r.ok {
		return nil, fmt.Errorf("%w: it is too short", ErrNotLogin)
	}
	switch {
	case msg != msgUserAuthRequest:
		return nil, fmt.Errorf("%w: it is not SSH_MSG_USERAUTH_REQUEST", ErrNotLogin)
	case service != serviceConnection:
		return nil, fmt.Errorf("%w: the service is not ssh-connection", ErrNotLogin)
	case d.method != methodPublicKey && d.method != methodHostbound:
		return nil, fmt.Errorf("%w: the method is not publickey or publickey-hostbound-v00@openssh.com", ErrNotLogin)
	case hasSignature != 1:
		// OpenSSH always writes 1. Any other value is not a request
		// that ssh signs.
		return nil, fmt.Errorf("%w: the signature flag is not 1", ErrNotLogin)
	case !validSessionID(d.sessionID):
		return nil, fmt.Errorf("%w: the session identifier is not 32, 48 or 64 bytes long", ErrNotLogin)
	}
	if d.hostbound() {
		d.hostKey = r.readString()
		if !r.ok {
			return nil, fmt.Errorf("%w: it is too short", ErrNotLogin)
		}
	}
	if !r.done() {
		return nil, fmt.Errorf("%w: it has bytes after the last field", ErrNotLogin)
	}
	return d, nil
}
