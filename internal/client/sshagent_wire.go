package client

import (
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/code6x/nodkey/internal/api"
)

// nodkey ssh-agent serves the SSH agent protocol itself (the IETF draft
// draft-miller-ssh-agent, and OpenSSH's PROTOCOL.agent). It does not use
// agent.ServeAgent of golang.org/x/crypto: that server writes the text of
// every error to Go's global logger, unescaped and without a limit, and it
// parses the private key of an add request before the agent can refuse it.
//
// Each message is a uint32 length and that many bytes. The first byte is
// the type of the message.

// The types of the messages that nodkey ssh-agent reads and writes.
const (
	agentFailure       = 5  // SSH_AGENT_FAILURE
	agentSuccess       = 6  // SSH_AGENT_SUCCESS
	agentListRequest   = 11 // SSH_AGENTC_REQUEST_IDENTITIES
	agentListAnswer    = 12 // SSH_AGENT_IDENTITIES_ANSWER
	agentSignRequest   = 13 // SSH_AGENTC_SIGN_REQUEST
	agentSignAnswer    = 14 // SSH_AGENT_SIGN_RESPONSE
	agentExtension     = 27 // SSH_AGENTC_EXTENSION
	sessionBindRequest = "session-bind@openssh.com"
)

// The requests that change the keys of an agent, or lock it. nodkey
// ssh-agent refuses all of them: the keys stay on the broker.
const (
	agentAddIdentity             = 17 // SSH_AGENTC_ADD_IDENTITY
	agentRemoveIdentity          = 18 // SSH_AGENTC_REMOVE_IDENTITY
	agentRemoveAll               = 19 // SSH_AGENTC_REMOVE_ALL_IDENTITIES
	agentAddSmartcardKey         = 20 // SSH_AGENTC_ADD_SMARTCARD_KEY
	agentRemoveSmartcardKey      = 21 // SSH_AGENTC_REMOVE_SMARTCARD_KEY
	agentLock                    = 22 // SSH_AGENTC_LOCK
	agentUnlock                  = 23 // SSH_AGENTC_UNLOCK
	agentAddConstrained          = 25 // SSH_AGENTC_ADD_ID_CONSTRAINED
	agentAddSmartcardConstrained = 26 // SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED
	// The same for keys of SSH protocol 1, which OpenSSH no longer has.
	// ssh-add -D still sends agentRemoveAllRSA.
	agentAddRSA            = 7  // SSH_AGENTC_ADD_RSA_IDENTITY
	agentRemoveRSA         = 8  // SSH_AGENTC_REMOVE_RSA_IDENTITY
	agentRemoveAllRSA      = 9  // SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES
	agentAddRSAConstrained = 24 // SSH_AGENTC_ADD_RSA_ID_CONSTRAINED
)

// maxAgentMessage is the longest message that the agent reads: 256 KiB,
// as OpenSSH's own agent (AGENT_MAX_LEN). A longer one closes the
// connection. A valid request of ssh is far shorter: the key, the data to
// sign and a session-bind are each at most a few KiB.
const maxAgentMessage = 256 << 10

// errMessageSize: a message is empty or longer than maxAgentMessage.
var errMessageSize = errors.New("client: an agent message is empty or longer than 256 KiB")

// failureMessage is the answer to every request that the agent refuses or
// cannot do. It says nothing about why.
var failureMessage = []byte{agentFailure}

// firstPiece is the first size of the buffer of a message. It grows as
// the bytes come.
const firstPiece = 4 << 10

// readAgentMessage reads one message. Its buffer grows as the bytes come,
// as in OpenSSH's own agent: a length alone, without the bytes, takes
// little memory. An old buffer is cleared when the buffer grows. The
// caller clears the message after use: an add request holds a private
// key, and a lock request a passphrase.
func readAgentMessage(r io.Reader) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(head[:])
	if size == 0 || size > maxAgentMessage {
		return nil, errMessageSize
	}
	n := int(size)
	msg := make([]byte, 0, min(n, firstPiece))
	for len(msg) < n {
		if len(msg) == cap(msg) {
			grown := make([]byte, len(msg), min(2*cap(msg), n))
			copy(grown, msg)
			clear(msg)
			msg = grown
		}
		k, err := r.Read(msg[len(msg):cap(msg)])
		msg = msg[:len(msg)+k]
		if err != nil && len(msg) < n {
			clear(msg)
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
	return msg, nil
}

// writeAgentMessage writes one message, with its length, in one write.
func writeAgentMessage(w io.Writer, msg []byte) error {
	if len(msg) == 0 || len(msg) > maxAgentMessage {
		return errMessageSize
	}
	b := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(msg)), uint32(len(msg))) //nolint:gosec // G115: the length is checked above.
	_, err := w.Write(append(b, msg...))
	return err
}

// wireReader reads SSH wire data (RFC 4251 section 5). After a read fails,
// every later read fails too, so a parser checks ok once at the end.
type wireReader struct {
	b  []byte
	ok bool
}

func newWireReader(b []byte) *wireReader { return &wireReader{b: b, ok: true} }

// uint32 reads a uint32.
func (r *wireReader) uint32() uint32 {
	if !r.ok || len(r.b) < 4 {
		r.ok = false
		return 0
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v
}

// string reads a string: a uint32 length and that many bytes. The result
// shares memory with the data.
func (r *wireReader) string() []byte {
	n := r.uint32()
	if !r.ok || uint64(n) > uint64(len(r.b)) {
		r.ok = false
		return nil
	}
	s := r.b[:n:n]
	r.b = r.b[n:]
	return s
}

// rest returns the bytes that are left.
func (r *wireReader) rest() []byte {
	s := r.b
	r.b = nil
	return s
}

// done reports whether every read worked and no byte is left.
func (r *wireReader) done() bool { return r.ok && len(r.b) == 0 }

// parseSignRequest reads the body of a sign request, after its type:
//
//	string  key blob
//	string  data
//	uint32  flags
//
// It refuses bytes after the flags. The results share memory with body.
func parseSignRequest(body []byte) (key, data []byte, flags uint32, ok bool) {
	r := newWireReader(body)
	key = r.string()
	data = r.string()
	flags = r.uint32()
	if !r.done() {
		return nil, nil, 0, false
	}
	return key, data, flags, true
}

// parseExtension reads the body of an extension request, after its type:
// string name, then the contents, which are the rest of the message. The
// results share memory with body.
func parseExtension(body []byte) (name string, contents []byte, ok bool) {
	r := newWireReader(body)
	n := r.string()
	if !r.ok {
		return "", nil, false
	}
	return string(n), r.rest(), true
}

// appendString appends s as an SSH string: its length and its bytes.
func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // G115: every string here is far shorter than 4 GiB: a key, a name or a signature.
	return append(b, s...)
}

// listAnswerMessage returns the answer to a list request: the number of
// keys, and for each its public key in SSH wire form and its comment,
// which is the key's name in the broker config.
func listAnswerMessage(keys []api.Key) []byte {
	b := binary.BigEndian.AppendUint32([]byte{agentListAnswer}, uint32(len(keys))) //nolint:gosec // G115: api.KeysAnswer holds at most api.MaxKeys keys.
	for _, k := range keys {
		b = appendString(b, k.PublicKey)
		b = appendString(b, []byte(k.Name))
	}
	return b
}

// signAnswerMessage returns the answer to a sign request: the signature,
// as an SSH string that holds its format and its blob.
func signAnswerMessage(sig *ssh.Signature) []byte {
	inner := appendString(appendString(nil, []byte(sig.Format)), sig.Blob)
	return appendString([]byte{agentSignAnswer}, inner)
}
