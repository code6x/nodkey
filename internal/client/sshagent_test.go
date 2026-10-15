package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
	"github.com/code6x/nodkey/internal/transport"
)

// agentSigner logs in with a key of the agent, as OpenSSH does: right
// before the agent signs, it sends the session-bind of the key exchange
// to the agent, on the same connection.
type agentSigner struct {
	ag   agent.ExtendedAgent
	pub  ssh.PublicKey
	bind func() []byte
}

func (s *agentSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s *agentSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(r, data, s.pub.Type())
}

func (s *agentSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if _, err := s.ag.Extension(sessionBindRequest, s.bind()); err != nil {
		return nil, err
	}
	var flags agent.SignatureFlags
	switch algorithm {
	case ssh.KeyAlgoRSASHA256:
		flags = agent.SignatureFlagRsaSha256
	case ssh.KeyAlgoRSASHA512:
		flags = agent.SignatureFlagRsaSha512
	}
	return s.ag.SignWithFlags(s.pub, data, flags)
}

// login logs in to srv as user, with the first key that the agent ag
// lists, as OpenSSH does with an agent. Give it a new agent connection.
// It may run in a goroutine of its own: it only returns errors.
func login(ctx context.Context, ag agent.ExtendedAgent, srv *sshServer, user string) error {
	keys, err := ag.List()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("the agent lists no key")
	}
	pub, err := ssh.ParsePublicKey(keys[0].Blob)
	if err != nil {
		return err
	}
	signer := &agentSigner{ag: ag, pub: pub, bind: func() []byte {
		b := srv.binds()
		return b[len(b)-1]
	}}
	nc, err := (&net.Dialer{Timeout: waitLimit}).DialContext(ctx, "tcp", srv.addr)
	if err != nil {
		return err
	}
	defer func() { _ = nc.Close() }()
	cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey)}
	conn, chans, reqs, err := ssh.NewClientConn(nc, srv.addr, cfg)
	if err != nil {
		return err
	}
	return ssh.NewClient(conn, chans, reqs).Close()
}

// TestAgentLogin logs in to an in-process SSH server through the agent
// and the real broker. Only a login that the person approves works. The
// agent prints the short code of the request, and why a request failed.
func TestAgentLogin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		answer audit.Answer // "" lets the request expire
		events string
	}{
		{"approved", audit.AnswerApproveOnce, "request decision:approve_once signed"},
		{"denied", audit.AnswerDeny, "request decision:deny denied:approver"},
		{"expired", "", "request denied:expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			host, _ := newSSHKey(t)
			sb := newSSHBroker(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
			srv := startSSHServer(t, host, sb.user.PublicKey())
			au := startAgent(t, sb.client(t), agentOptions{})
			sb.approver.Auto(tt.answer)
			ag := au.client(t)
			done := make(chan error, 1)
			go func() { done <- login(t.Context(), ag, srv, "deploy") }()
			asked := sb.waitAsked(t, 1)[0]
			if tt.answer == "" {
				sb.clock.Advance(sshTimeout)
			}
			err := <-done
			code := asked.Prompt.ShortCode
			waiting := "nodkey: waiting for approval (request " + code + ")"
			want := []string{waiting}
			if tt.answer == audit.AnswerApproveOnce {
				if err != nil || srv.loginCount() != 1 {
					t.Fatalf("the login failed: %v; agent lines %q", err, au.lines())
				}
			} else {
				if err == nil || srv.loginCount() != 0 {
					t.Fatalf("the login worked, %v", err)
				}
				want = append(want, "nodkey: no signature (request "+code+"): denied")
			}
			p := asked.Prompt
			if p.Key != "deploy" || !slices.Equal(p.Hosts, []string{"web-1"}) || p.RemoteUser != "deploy" ||
				p.Client != "laptop" {
				t.Errorf("the message shows %+v", p)
			}
			waitFor(t, "the agent's lines", func() bool { return len(au.lines()) >= len(want) })
			if got := au.lines(); !slices.Equal(got, want) {
				t.Errorf("the agent wrote %q, want %q", got, want)
			}
			if got := eventNames(sb.audit.waitFor(t, len(strings.Fields(tt.events)))); got != tt.events {
				t.Errorf("audit entries %q, want %q", got, tt.events)
			}
		})
	}
}

// TestAgentLists: the agent lists the keys of the broker's answer, each
// with its exact public key and its name as the comment. Each list asks
// the broker once.
func TestAgentLists(t *testing.T) {
	t.Parallel()
	deploy, _ := newSSHKey(t)
	backup, _ := newSSHKey(t)
	fb := newFakeSSHBroker(t, map[string]ssh.PublicKey{"deploy": deploy.PublicKey(), "backup": backup.PublicKey()},
		nil)
	au := startAgent(t, fb.b, agentOptions{})
	ag := au.client(t)
	for i := range 2 {
		keys, err := ag.List()
		if err != nil {
			t.Fatal(err)
		}
		got := map[string][]byte{}
		for _, k := range keys {
			got[k.Comment] = k.Blob
		}
		if len(keys) != 2 || !bytes.Equal(got["deploy"], deploy.PublicKey().Marshal()) ||
			!bytes.Equal(got["backup"], backup.PublicKey().Marshal()) {
			t.Errorf("the agent lists %v", keys)
		}
		if n := fb.requests.Load(); n != int32(i+1) {
			t.Errorf("the broker got %d requests after %d lists", n, i+1)
		}
	}
	if lines := au.lines(); len(lines) != 0 {
		t.Errorf("the agent wrote %q", lines)
	}
}

// TestAgentListFailures: a list request that the broker does not answer
// with a valid list gets SSH_AGENT_FAILURE, and one line says why.
func TestAgentListFailures(t *testing.T) {
	t.Parallel()
	pub, _ := newSSHKey(t)
	cert := &ssh.Certificate{Key: pub.PublicKey(), CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, pub); err != nil {
		t.Fatal(err)
	}
	keysJSON := func(name string, blob []byte) string {
		return string(mustJSON(t, api.KeysAnswer{Keys: []api.Key{{Name: name, PublicKey: blob}}}))
	}
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{"403", answer(http.StatusForbidden, `{"error":"Forbidden"}`), "denied"},
		{"503", answer(http.StatusServiceUnavailable, `{"error":"Service Unavailable"}`),
			"the broker answered 503 Service Unavailable"},
		{"not JSON", answer(http.StatusOK, "keys"), "the answer of the broker is not valid"},
		{"an unknown field", answer(http.StatusOK, `{"keys":[],"more":1}`), "the answer of the broker is not valid"},
		{"a certificate", answer(http.StatusOK, keysJSON("deploy", cert.Marshal())),
			"the answer of the broker has a key that is not valid"},
		{"not a key", answer(http.StatusOK, keysJSON("deploy", []byte("not a key"))),
			"the answer of the broker has a key that is not valid"},
		{"a name with a line break", answer(http.StatusOK, keysJSON("deploy\naudit anchor 1:x", pub.PublicKey().Marshal())),
			"the answer of the broker has a key that is not valid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fb := newFakeBroker(t, tt.handler)
			au := startAgent(t, fb.b, agentOptions{})
			ag := au.client(t)
			if keys, err := ag.List(); err == nil {
				t.Fatalf("the agent listed %v", keys)
			}
			want := []string{"nodkey: no key list: " + tt.want}
			if got := au.lines(); !slices.Equal(got, want) {
				t.Errorf("the agent wrote %q, want %q", got, want)
			}
			if fb.requests.Load() != 1 {
				t.Errorf("the broker got %d requests, want 1", fb.requests.Load())
			}
		})
	}
}

// TestAgentBrokerDown: without a broker, ssh gets no key and no
// signature, and a line says why.
func TestAgentBrokerDown(t *testing.T) {
	t.Parallel()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	b, err := newBroker(addr, newTLSKey(t).cert, newTLSKey(t).pin)
	if err != nil {
		t.Fatal(err)
	}
	au := startAgent(t, b, agentOptions{})
	ag, c := au.client(t), au.conn(t)
	if _, err := ag.List(); err == nil {
		t.Error("the agent listed keys")
	}
	pub, _ := newSSHKey(t)
	if !bindAgent(t, c, []byte("bind")) {
		t.Fatal("the session-bind was refused")
	}
	if sig := signatureOf(t, rawCall(t, c, signRequestMessage(pub.PublicKey().Marshal(), []byte("data"), 0))); sig != nil {
		t.Error("the agent signed")
	}
	// Another test may take the free port at once: then the TLS handshake
	// fails instead.
	want := "cannot connect to the broker at " + addr + ": "
	if got := au.lines(); len(got) != 2 || !strings.HasPrefix(got[0], "nodkey: no key list: "+want) ||
		!strings.HasPrefix(got[1], "nodkey: no signature: "+want) {
		t.Errorf("the agent wrote %q", got)
	}
}

// signOnce sends one session-bind and one sign request for key on a new
// connection, and returns the signature, or nil for SSH_AGENT_FAILURE.
func signOnce(t *testing.T, au *agentUnderTest, key ssh.PublicKey, data []byte, flags uint32) *ssh.Signature {
	t.Helper()
	c := au.conn(t)
	if !bindAgent(t, c, []byte("a session-bind")) {
		t.Fatal("the session-bind was refused")
	}
	return signatureOf(t, rawCall(t, c, signRequestMessage(key.Marshal(), data, flags)))
}

// TestAgentSignAnswers: only a final 200 whose body passes
// api.ReadAnswer, with a signature that fits the key and the flags and is
// valid for the data, goes to ssh. Every other answer is
// SSH_AGENT_FAILURE, and one line says why, as nodkey run says it: denied
// for 403 and 429, and the answer for the others. The agent sends each
// request once, and never writes an answer body or a header.
func TestAgentSignAnswers(t *testing.T) {
	t.Parallel()
	deploy, _ := newSSHKey(t)
	other, _ := newSSHKey(t)
	peerText := "PEER\nnodkey: approved (exit 0)"
	sigOf := func(signer ssh.AlgorithmSigner, data []byte) *ssh.Signature {
		sig, err := signer.SignWithAlgorithm(rand.Reader, data, "")
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	write := func(status int, v any) func(http.ResponseWriter, *api.SignRequest) {
		return func(w http.ResponseWriter, _ *api.SignRequest) {
			w.Header().Set("X-Note", peerText)
			_ = transport.WriteJSON(w, status, v)
		}
	}
	tests := []struct {
		name string
		sign func(http.ResponseWriter, *api.SignRequest)
		want string // the rest of the line after "nodkey: no signature: "; "" for a valid signature
	}{
		{"valid", signWith(deploy, "", ""), ""},
		{"403", write(http.StatusForbidden, api.ErrorAnswer{Error: peerText}), "denied"},
		{"429", write(http.StatusTooManyRequests, api.ErrorAnswer{Error: "Too Many Requests"}),
			"denied by a limit of the broker"},
		{"400", write(http.StatusBadRequest, api.ErrorAnswer{Error: "Bad Request"}),
			"the broker answered 400 Bad Request"},
		{"503", write(http.StatusServiceUnavailable, api.ErrorAnswer{Error: "Service Unavailable"}),
			"the broker answered 503 Service Unavailable"},
		{"201 with a valid signature", func(w http.ResponseWriter, req *api.SignRequest) {
			sig := sigOf(deploy, req.Data)
			_ = transport.WriteJSON(w, http.StatusCreated, api.SignAnswer{Format: sig.Format, Blob: sig.Blob})
		}, "the broker answered 201 Created"},
		{"a redirect", func(w http.ResponseWriter, _ *api.SignRequest) {
			w.Header().Set("Location", "https://192.0.2.10:7743/v1/sign")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}, "the broker answered 307 Temporary Redirect"},
		{"not JSON", func(w http.ResponseWriter, _ *api.SignRequest) {
			_ = transport.WriteJSONBody(w, http.StatusOK, []byte(`"`+strings.ReplaceAll(peerText, "\n", " ")+`"`))
		}, "the answer of the broker is not valid"},
		{"an unknown field", func(w http.ResponseWriter, req *api.SignRequest) {
			sig := sigOf(deploy, req.Data)
			_ = transport.WriteJSON(w, http.StatusOK, map[string]any{"format": sig.Format, "blob": sig.Blob, "x": 1})
		}, "the answer of the broker is not valid"},
		{"no blob", func(w http.ResponseWriter, _ *api.SignRequest) {
			_ = transport.WriteJSON(w, http.StatusOK, map[string]any{"format": ssh.KeyAlgoED25519})
		}, "the answer of the broker is not valid"},
		{"larger than api.MaxAnswer", func(w http.ResponseWriter, req *api.SignRequest) {
			sig := sigOf(deploy, req.Data)
			body := string(mustJSON(t, api.SignAnswer{Format: sig.Format, Blob: sig.Blob})) +
				strings.Repeat(" ", api.MaxAnswer)
			_ = transport.WriteJSONBody(w, http.StatusOK, []byte(body))
		}, "the answer of the broker is not valid"},
		{"a signature of another key", signWith(other, "", ""),
			"the signature of the broker is not a valid signature of the data"},
		{"a signature of other data", func(w http.ResponseWriter, req *api.SignRequest) {
			sig := sigOf(deploy, append(bytes.Clone(req.Data), 'x'))
			_ = transport.WriteJSON(w, http.StatusOK, api.SignAnswer{Format: sig.Format, Blob: sig.Blob})
		}, "the signature of the broker is not a valid signature of the data"},
		{"an empty blob", write(http.StatusOK, api.SignAnswer{Format: ssh.KeyAlgoED25519, Blob: []byte{}}),
			"the signature of the broker is not a valid signature of the data"},
		{"another format", signWith(deploy, "", ssh.KeyAlgoRSASHA256),
			"the signature of the broker does not fit the key and the sign flags"},
		{"a format in another case", signWith(deploy, "", "SSH-ED25519"),
			"the signature of the broker does not fit the key and the sign flags"},
		{"a dropped connection", func(http.ResponseWriter, *api.SignRequest) { panic(http.ErrAbortHandler) },
			"broke before the answer"},
		{"too many informational answers", func(w http.ResponseWriter, req *api.SignRequest) {
			for range maxInformational + 1 {
				if err := transport.WriteProcessing(w, http.Header{api.ShortCodeHeader: {"7qd2"}}); err != nil {
					return
				}
			}
			signWith(deploy, "", "")(w, req)
		}, "(request 7qd2): the broker sent more than 4 informational answers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fb := newFakeSSHBroker(t, map[string]ssh.PublicKey{"deploy": deploy.PublicKey()}, tt.sign)
			au := startAgent(t, fb.b, agentOptions{})
			data := []byte("the data to sign " + rand.Text())
			sig := signOnce(t, au, deploy.PublicKey(), data, 0)
			lines := au.lines()
			if tt.want == "" {
				if sig == nil || deploy.PublicKey().Verify(data, sig) != nil || len(lines) != 0 {
					t.Fatalf("no valid signature: %v; lines %q", sig, lines)
				}
				return
			}
			if sig != nil {
				t.Fatalf("the agent gave ssh a signature")
			}
			if tt.name == "too many informational answers" {
				if len(lines) != 2 || lines[0] != "nodkey: waiting for approval (request 7qd2)" ||
					lines[1] != "nodkey: no signature "+tt.want {
					t.Errorf("the agent wrote %q", lines)
				}
			} else if len(lines) != 1 || !strings.HasPrefix(lines[0], "nodkey: no signature: ") ||
				!strings.Contains(lines[0], tt.want) {
				t.Errorf("the agent wrote %q; want one line with %q", lines, tt.want)
			}
			if strings.Contains(au.log.String(), "PEER") {
				t.Errorf("the agent wrote text of the answer: %q", lines)
			}
			if n := fb.requests.Load(); n != 1 {
				t.Errorf("the broker got %d requests, want 1", n)
			}
		})
	}
}

// TestAgentSignFormats: the format of the broker's signature must be the
// one that the key and the sign flags ask for. RSA needs the flag of
// SHA-256 or SHA-512, and SHA-1 never passes; Ed25519 takes no flags.
func TestAgentSignFormats(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ssh.NewSignerFromSigner(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, ok := rs.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("the RSA signer cannot choose an algorithm")
	}
	ed, _ := newSSHKey(t)
	tests := []struct {
		name      string
		signer    ssh.AlgorithmSigner
		algorithm string // that the broker signs with
		flags     uint32
		ok        bool
	}{
		{"rsa-sha2-256", rsaSigner, ssh.KeyAlgoRSASHA256, uint32(agent.SignatureFlagRsaSha256), true},
		{"rsa-sha2-512", rsaSigner, ssh.KeyAlgoRSASHA512, uint32(agent.SignatureFlagRsaSha512), true},
		{"rsa-sha2-512 for the flag of SHA-256", rsaSigner, ssh.KeyAlgoRSASHA512,
			uint32(agent.SignatureFlagRsaSha256), false},
		{"ssh-rsa (SHA-1) without a flag", rsaSigner, ssh.KeyAlgoRSA, 0, false},
		{"RSA with both flags", rsaSigner, ssh.KeyAlgoRSASHA256,
			uint32(agent.SignatureFlagRsaSha256 | agent.SignatureFlagRsaSha512), false},
		{"ssh-ed25519", ed, ssh.KeyAlgoED25519, 0, true},
		{"ssh-ed25519 with a flag", ed, ssh.KeyAlgoED25519, uint32(agent.SignatureFlagRsaSha256), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fb := newFakeSSHBroker(t, nil, signWith(tt.signer, tt.algorithm, ""))
			au := startAgent(t, fb.b, agentOptions{})
			data := []byte("data " + rand.Text())
			sig := signOnce(t, au, tt.signer.PublicKey(), data, tt.flags)
			if !tt.ok {
				if sig != nil {
					t.Fatalf("the agent gave ssh a signature in %s", sig.Format)
				}
				want := "nodkey: no signature: the signature of the broker does not fit the key and the sign flags"
				if got := au.lines(); !slices.Equal(got, []string{want}) {
					t.Errorf("the agent wrote %q", got)
				}
				return
			}
			if sig == nil || sig.Format != tt.algorithm || tt.signer.PublicKey().Verify(data, sig) != nil {
				t.Fatalf("no valid signature in %s: %v; lines %q", tt.algorithm, sig, au.lines())
			}
		})
	}
}

// TestSignatureFormat: the formats that the agent takes.
func TestSignatureFormat(t *testing.T) {
	t.Parallel()
	sha256, sha512 := uint32(agent.SignatureFlagRsaSha256), uint32(agent.SignatureFlagRsaSha512)
	tests := []struct {
		keyType string
		flags   uint32
		want    string // "" when no format fits
	}{
		{ssh.KeyAlgoED25519, 0, ssh.KeyAlgoED25519},
		{ssh.KeyAlgoECDSA256, 0, ssh.KeyAlgoECDSA256},
		{ssh.KeyAlgoECDSA384, 0, ssh.KeyAlgoECDSA384},
		{ssh.KeyAlgoECDSA521, 0, ssh.KeyAlgoECDSA521},
		{ssh.KeyAlgoECDSA256, sha256, ""},
		{ssh.KeyAlgoRSA, sha256, ssh.KeyAlgoRSASHA256},
		{ssh.KeyAlgoRSA, sha512, ssh.KeyAlgoRSASHA512},
		{ssh.KeyAlgoRSA, 0, ""},
		{ssh.KeyAlgoRSA, sha256 | sha512, ""},
		{ssh.KeyAlgoRSA, 1, ""},
		{ssh.CertAlgoED25519v01, 0, ""},
		{ssh.KeyAlgoSKED25519, 0, ""},
		{"ssh-dss", 0, ""},
	}
	for _, tt := range tests {
		got, ok := signatureFormat(tt.keyType, tt.flags)
		if got != tt.want && ok || ok != (tt.want != "") {
			t.Errorf("signatureFormat(%s, %d) = %q, %v; want %q", tt.keyType, tt.flags, got, ok, tt.want)
		}
	}
}

// TestAgentShortCode: the agent prints the short code of the first
// 102 Processing once, and only a code that has the form of a short code,
// as nodkey run does. A code in the final answer is not printed.
func TestAgentShortCode(t *testing.T) {
	t.Parallel()
	deploy, _ := newSSHKey(t)
	informational := func(w http.ResponseWriter, status int, code string) {
		w.Header().Set(api.ShortCodeHeader, code)
		w.WriteHeader(status)
		w.Header().Del(api.ShortCodeHeader)
	}
	tests := []struct {
		name  string
		first func(http.ResponseWriter)
		final string
		want  string
	}{
		{"one", func(w http.ResponseWriter) { informational(w, http.StatusProcessing, "k3f9") }, "", "k3f9"},
		{"two", func(w http.ResponseWriter) {
			informational(w, http.StatusProcessing, "k3f9")
			informational(w, http.StatusProcessing, "7qd2")
		}, "", "k3f9"},
		{"not a short code", func(w http.ResponseWriter) {
			informational(w, http.StatusProcessing, "k3f9\nnodkey: approved")
		}, "", ""},
		{"not 102", func(w http.ResponseWriter) { informational(w, http.StatusEarlyHints, "k3f9") }, "", ""},
		{"in the final answer", func(http.ResponseWriter) {}, "k3f9", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fb := newFakeSSHBroker(t, nil, func(w http.ResponseWriter, _ *api.SignRequest) {
				tt.first(w)
				if tt.final != "" {
					w.Header().Set(api.ShortCodeHeader, tt.final)
				}
				transport.WriteError(w, http.StatusForbidden)
			})
			au := startAgent(t, fb.b, agentOptions{})
			if sig := signOnce(t, au, deploy.PublicKey(), []byte("data"), 0); sig != nil {
				t.Fatal("the agent gave ssh a signature")
			}
			want := []string{"nodkey: no signature: denied"}
			if tt.want != "" {
				want = []string{"nodkey: waiting for approval (request " + tt.want + ")",
					"nodkey: no signature (request " + tt.want + "): denied"}
			}
			if got := au.lines(); !slices.Equal(got, want) {
				t.Errorf("the agent wrote %q, want %q", got, want)
			}
		})
	}
}

// TestAgentSignDeadline: a sign request waits at most its deadline. Then
// ssh gets SSH_AGENT_FAILURE, the connection to the broker closes, so the
// broker cancels the request, and the agent does not ask again.
func TestAgentSignDeadline(t *testing.T) {
	t.Parallel()
	deploy, _ := newSSHKey(t)
	hungUp := make(chan struct{})
	fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := transport.ReadJSON[api.SignRequest](w, r); err != nil {
			return
		}
		if err := transport.WriteProcessing(w, http.Header{api.ShortCodeHeader: {"k3f9"}}); err != nil {
			return
		}
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
		close(hungUp)
	})
	const timeout = time.Second
	au := startAgent(t, fb.b, agentOptions{signTimeout: timeout})
	start := time.Now()
	if sig := signOnce(t, au, deploy.PublicKey(), []byte("data"), 0); sig != nil {
		t.Fatal("the agent gave ssh a signature")
	}
	if d := time.Since(start); d < timeout || d > waitLimit {
		t.Errorf("the request ended after %s; want its deadline, %s", d, timeout)
	}
	select {
	case <-hungUp:
	case <-time.After(waitLimit):
		t.Fatal("the broker did not see the client hang up")
	}
	const last = "no answer from the broker within 1s"
	switch got := au.lines(); {
	case slices.Equal(got, []string{"nodkey: waiting for approval (request k3f9)",
		"nodkey: no signature (request k3f9): " + last}):
	case slices.Equal(got, []string{"nodkey: no signature: " + last}):
		// A slow machine: the deadline came before the 102 Processing.
	default:
		t.Errorf("the agent wrote %q", got)
	}
	if n := fb.requests.Load(); n != 1 {
		t.Errorf("the broker got %d requests, want 1", n)
	}
}

// TestSignTimeoutIsBelowLoginGraceTime: the deadline of a sign request is
// longer than the longest ssh_timeout of the broker, so that a late tap
// still counts, and shorter than the LoginGraceTime of sshd (120 seconds
// by default), after which a signature cannot log in.
func TestSignTimeoutIsBelowLoginGraceTime(t *testing.T) {
	t.Parallel()
	const loginGraceTime = 120 * time.Second
	if signTimeout <= config.MaxSSHTimeout || signTimeout >= loginGraceTime {
		t.Errorf("signTimeout is %s; want more than %s and less than %s", signTimeout, config.MaxSSHTimeout,
			loginGraceTime)
	}
	if keysTimeout >= loginGraceTime {
		t.Errorf("keysTimeout is %s", keysTimeout)
	}
}

// TestAgentSendsTheRequestAsItIs: the agent sends the exact bytes of the
// key, the data and the flags that ssh sent, and every session-bind of
// that connection, in order, without the extension name, and the binds of
// no other connection. It answers each session-bind with success.
func TestAgentSendsTheRequestAsItIs(t *testing.T) {
	t.Parallel()
	fb := newFakeSSHBroker(t, nil, func(w http.ResponseWriter, _ *api.SignRequest) {
		transport.WriteError(w, http.StatusForbidden)
	})
	au := startAgent(t, fb.b, agentOptions{})
	one := au.conn(t)
	two := au.conn(t)
	b1, b2, b3 := []byte("bind one "+rand.Text()), []byte("bind two "+rand.Text()), []byte("bind three")
	if !bindAgent(t, one, b1) || !bindAgent(t, two, b3) || !bindAgent(t, one, b2) {
		t.Fatal("the agent refused a session-bind")
	}
	key := []byte("any key bytes \x00\xff")
	data := []byte("any data \x00\xff")
	if signatureOf(t, rawCall(t, one, signRequestMessage(key, data, 0xfffffffe))) != nil ||
		signatureOf(t, rawCall(t, two, signRequestMessage(key[:3], data[:3], 0))) != nil {
		t.Fatal("the agent gave ssh a signature")
	}
	reqs := fb.signRequests()
	if len(reqs) != 2 {
		t.Fatalf("the broker got %d sign requests", len(reqs))
	}
	if r := reqs[0]; !bytes.Equal(r.PublicKey, key) || !bytes.Equal(r.Data, data) || r.Flags != 0xfffffffe ||
		len(r.Binds) != 2 || !bytes.Equal(r.Binds[0], b1) || !bytes.Equal(r.Binds[1], b2) {
		t.Errorf("the first request is %+v", r)
	}
	if r := reqs[1]; !bytes.Equal(r.PublicKey, key[:3]) || !bytes.Equal(r.Data, data[:3]) || r.Flags != 0 ||
		len(r.Binds) != 1 || !bytes.Equal(r.Binds[0], b3) {
		t.Errorf("the second request is %+v", r)
	}
	// Without a session-bind, the broker decides: it refuses the request.
	three := au.conn(t)
	if signatureOf(t, rawCall(t, three, signRequestMessage(key, data, 0))) != nil {
		t.Fatal("the agent gave ssh a signature")
	}
	if reqs := fb.signRequests(); len(reqs) != 3 || len(reqs[2].Binds) != 0 || reqs[2].Binds == nil {
		t.Errorf("the request without a session-bind has %v", reqs[len(reqs)-1].Binds)
	}
}

// TestAgentRefusesAThirdBind: the agent keeps at most 2 session-binds of a
// connection, each at most 8 KiB, the most that the broker reads. It
// refuses more. Then it cannot send every session-bind of the connection,
// so the connection gets no signature, and the broker gets no request.
func TestAgentRefusesAThirdBind(t *testing.T) {
	t.Parallel()
	fb := newFakeSSHBroker(t, nil, func(w http.ResponseWriter, _ *api.SignRequest) {
		transport.WriteError(w, http.StatusForbidden)
	})
	au := startAgent(t, fb.b, agentOptions{})
	c := au.conn(t)
	if !bindAgent(t, c, []byte("one")) || !bindAgent(t, c, bytes.Repeat([]byte("2"), api.MaxBind)) {
		t.Fatal("the agent refused one of the first two session-binds")
	}
	if bindAgent(t, c, []byte("three")) {
		t.Fatal("the agent took a third session-bind")
	}
	if signatureOf(t, rawCall(t, c, signRequestMessage([]byte("key"), []byte("data"), 0))) != nil {
		t.Fatal("the agent gave ssh a signature")
	}
	long := au.conn(t)
	if bindAgent(t, long, bytes.Repeat([]byte("x"), api.MaxBind+1)) || bindAgent(t, long, []byte("short")) {
		t.Fatal("the agent took a session-bind over 8 KiB, or one after it")
	}
	if signatureOf(t, rawCall(t, long, signRequestMessage([]byte("key"), []byte("data"), 0))) != nil {
		t.Fatal("the agent gave ssh a signature")
	}
	if n := fb.requests.Load(); n != 0 {
		t.Errorf("the broker got %d requests, want none", n)
	}
	want := []string{
		"nodkey: refused a session-bind after 2 of them; this connection gets no signature",
		"nodkey: no signature: the agent refused a session-bind on this connection",
		"nodkey: refused a session-bind longer than 8192 bytes; this connection gets no signature",
		"nodkey: refused a session-bind: the agent refused one before on this connection",
		"nodkey: no signature: the agent refused a session-bind on this connection",
	}
	if got := au.lines(); !slices.Equal(got, want) {
		t.Errorf("the agent wrote %q, want %q", got, want)
	}
}

// TestAgentSignCaps: a key over api.MaxKey or data over api.MaxData is
// refused by the agent: the broker would not read the request.
func TestAgentSignCaps(t *testing.T) {
	t.Parallel()
	fb := newFakeSSHBroker(t, nil, func(w http.ResponseWriter, _ *api.SignRequest) {
		transport.WriteError(w, http.StatusForbidden)
	})
	au := startAgent(t, fb.b, agentOptions{})
	c := au.conn(t)
	for _, m := range [][]byte{
		signRequestMessage(bytes.Repeat([]byte("k"), api.MaxKey+1), []byte("data"), 0),
		signRequestMessage([]byte("key"), bytes.Repeat([]byte("d"), api.MaxData+1), 0),
	} {
		if signatureOf(t, rawCall(t, c, m)) != nil {
			t.Fatal("the agent gave ssh a signature")
		}
	}
	// At the caps, the request goes to the broker.
	if signatureOf(t, rawCall(t, c, signRequestMessage(bytes.Repeat([]byte("k"), api.MaxKey),
		bytes.Repeat([]byte("d"), api.MaxData), 0))) != nil {
		t.Fatal("the agent gave ssh a signature")
	}
	if n := fb.requests.Load(); n != 1 {
		t.Errorf("the broker got %d requests, want 1", n)
	}
	want := "nodkey: no signature: the key or the data to sign is longer than the broker reads"
	if got := au.lines(); !slices.Equal(got, []string{want, want, "nodkey: no signature: denied"}) {
		t.Errorf("the agent wrote %q", got)
	}
}

// TestAgentRefusesKeyChanges: the agent refuses to add, remove, lock and
// unlock keys, every extension but session-bind@openssh.com, and every
// request it does not know, with SSH_AGENT_FAILURE. Each refused request
// gives one fixed line, and none reaches the broker.
func TestAgentRefusesKeyChanges(t *testing.T) {
	t.Parallel()
	fb := newFakeSSHBroker(t, nil, nil)
	au := startAgent(t, fb.b, agentOptions{})
	ag, c := au.client(t), au.conn(t)
	pub, priv := newSSHKey(t)
	const changes = "nodkey: refused a request to add, remove, lock or unlock keys: the keys stay on the broker"
	calls := []struct {
		name string
		call func() error
		line string
	}{
		{"add", func() error { return ag.Add(agent.AddedKey{PrivateKey: priv, Comment: "added"}) }, changes},
		{"add with a constraint", func() error {
			return ag.Add(agent.AddedKey{PrivateKey: priv, LifetimeSecs: 60, ConfirmBeforeUse: true})
		}, changes},
		{"remove", func() error { return ag.Remove(pub.PublicKey()) }, changes},
		{"remove all", ag.RemoveAll, changes},
		{"lock", func() error { return ag.Lock([]byte("passphrase")) }, changes},
		{"unlock", func() error { return ag.Unlock([]byte("passphrase")) }, changes},
		{"query", func() error { _, err := ag.Extension("query", nil); return err },
			"nodkey: refused an extension request: the agent knows only session-bind@openssh.com"},
		{"another extension", func() error { _, err := ag.Extension("x@example.com", []byte("x")); return err },
			"nodkey: refused an extension request: the agent knows only session-bind@openssh.com"},
	}
	for _, cl := range calls {
		before := len(au.lines())
		if err := cl.call(); err == nil {
			t.Errorf("%s: the agent did it", cl.name)
		}
		if got := au.lines()[before:]; !slices.Equal(got, []string{cl.line}) {
			t.Errorf("%s: the agent wrote %q, want %q", cl.name, got, cl.line)
		}
	}
	raw := []struct {
		name string
		msg  []byte
		line string
	}{
		{"add a smartcard key", []byte{agentAddSmartcardKey, 0, 0, 0, 1, 'x', 0, 0, 0, 0}, changes},
		{"remove a smartcard key", []byte{agentRemoveSmartcardKey, 0, 0, 0, 0, 0, 0, 0, 0}, changes},
		{"add a smartcard key with a constraint", []byte{agentAddSmartcardConstrained, 0, 0, 0, 0}, changes},
		{"SSH1 list", []byte{1}, "nodkey: refused an agent request of the unknown type 1"},
		{"SSH1 remove all", []byte{9}, changes},
		{"SSH1 add", []byte{7, 'x'}, changes},
		{"SSH1 sign", []byte{3, 'x'}, "nodkey: refused an agent request of the unknown type 3"},
		{"unknown", []byte{99, 'x'}, "nodkey: refused an agent request of the unknown type 99"},
		{"a list request with more bytes", []byte{agentListRequest, 0}, "nodkey: refused a key list request that is not valid"},
		{"a sign request with more bytes", append(signRequestMessage([]byte("k"), []byte("d"), 0), 0),
			"nodkey: refused a sign request that is not valid"},
		{"a short sign request", []byte{agentSignRequest, 0, 0, 0, 9, 'k'},
			"nodkey: refused a sign request that is not valid"},
		{"an extension without a name", []byte{agentExtension, 0, 0},
			"nodkey: refused an extension request that is not valid"},
	}
	for _, r := range raw {
		before := len(au.lines())
		if answer := rawCall(t, c, r.msg); !bytes.Equal(answer, failureMessage) {
			t.Errorf("%s: the answer is % x", r.name, answer)
		}
		if got := au.lines()[before:]; !slices.Equal(got, []string{r.line}) {
			t.Errorf("%s: the agent wrote %q, want %q", r.name, got, r.line)
		}
	}
	if n := fb.requests.Load(); n != 0 {
		t.Errorf("the broker got %d requests", n)
	}
	if keys, err := ag.List(); err != nil || len(keys) != 0 {
		t.Errorf("after the refused requests, the agent lists %v, %v", keys, err)
	}
}

// TestAgentRefusedRequestLogsOneFixedLine: the agent server of
// golang.org/x/crypto writes the text of every error to Go's global
// logger, unescaped and without a limit (issue #13). nodkey ssh-agent
// serves the protocol itself: a refused request gives one fixed line on
// its own stderr, with no text that the client sent, and nothing in the
// global logger.
func TestAgentRefusedRequestLogsOneFixedLine(t *testing.T) { // not parallel: it changes the global logger
	var global syncBuffer
	prevW, prevF := log.Writer(), log.Flags()
	log.SetOutput(&global) //nolint:forbidigo // the test captures what a library writes to the global logger.
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevW) //nolint:forbidigo // restores the global logger.
		log.SetFlags(prevF)
	})
	fb := newFakeSSHBroker(t, nil, nil)
	au := startAgent(t, fb.b, agentOptions{})
	ag, c := au.client(t), au.conn(t)
	canary := "line one\naudit anchor 1:" + strings.Repeat("A", 64)
	_, priv := newSSHKey(t)
	if err := ag.Add(agent.AddedKey{PrivateKey: priv, Comment: canary}); err == nil {
		t.Fatal("the agent added a key")
	}
	want := []string{"nodkey: refused a request to add, remove, lock or unlock keys: the keys stay on the broker"}
	if got := au.lines(); !slices.Equal(got, want) {
		t.Errorf("the agent wrote %q, want %q", got, want)
	}
	// The same with requests that x/crypto's server does not even parse.
	for _, msg := range [][]byte{
		append([]byte{agentAddIdentity}, []byte(canary)...),
		extensionMessage(canary, []byte(canary)),
		append([]byte{200}, []byte(canary)...),
	} {
		before := len(au.lines())
		rawCall(t, c, msg)
		if got := au.lines()[before:]; len(got) != 1 {
			t.Errorf("one refused request gave %d lines: %q", len(got), got)
		}
	}
	if strings.Contains(au.log.String(), "audit anchor") || strings.Contains(au.log.String(), "line one") {
		t.Errorf("the agent wrote text of a request: %q", au.lines())
	}
	if global.String() != "" {
		t.Errorf("the global logger got %q", global.String())
	}
}

// TestAgentLogLimit: the lines with a short code, and the lines about
// refused and failed requests, are each at most agentLogLines in a
// minute, with a budget of their own, so neither kind crowds out the
// other. The lines over a budget are counted: the next line of the same
// kind in a later minute says how many were left out, and so does flush,
// when the agent stops. A line that comes once is not limited.
func TestAgentLogLimit(t *testing.T) {
	t.Parallel()
	var out syncBuffer
	l := newAgentLog(&out)
	now := noon
	l.now = func() time.Time { return now }
	for range agentLogLines + 10 {
		l.note("refused a request")
		l.waitingFor("k3f9")
	}
	l.say("the SSH agent listens on /run/a/agent.sock")
	lines := linesOf(out.String())
	if n := len(lines); n != 2*agentLogLines+1 || countLines(out.String(), "refused a request") != agentLogLines ||
		countLines(out.String(), "waiting for approval (request k3f9)") != agentLogLines ||
		lines[n-1] != "nodkey: the SSH agent listens on /run/a/agent.sock" {
		t.Fatalf("%d lines; the last is %q", len(lines), lines[len(lines)-1])
	}
	now = now.Add(agentLogWindow)
	l.waitingFor("7qd2")
	l.note("refused a request")
	lines = linesOf(out.String())[2*agentLogLines+1:]
	want := []string{
		"nodkey: left out 10 lines about requests that wait for approval, to keep the log short",
		"nodkey: waiting for approval (request 7qd2)",
		"nodkey: left out 10 lines about refused or failed requests, to keep the log short",
		"nodkey: refused a request",
	}
	if !slices.Equal(lines, want) {
		t.Errorf("after a minute: %q, want %q", lines, want)
	}
	for range agentLogLines + 3 {
		l.note("refused a request")
		l.waitingFor("7qd2")
	}
	l.flush()
	lines = linesOf(out.String())
	want = []string{
		"nodkey: left out 4 lines about requests that wait for approval, to keep the log short",
		"nodkey: left out 4 lines about refused or failed requests, to keep the log short",
	}
	if got := lines[len(lines)-2:]; !slices.Equal(got, want) {
		t.Errorf("flush wrote %q, want %q", got, want)
	}
	// A line is always one line.
	l.say("a\nb\rc")
	if last := lastLine(out.String()); last != "nodkey: a b c" {
		t.Errorf("a line with line breaks became %q", last)
	}
}

// countLines counts the lines of out that contain s.
func countLines(out, s string) int {
	n := 0
	for _, l := range linesOf(out) {
		if strings.Contains(l, s) {
			n++
		}
	}
	return n
}

// TestCheckPeer: only the user that runs the agent may use it; another
// user is refused, also root.
func TestCheckPeer(t *testing.T) {
	t.Parallel()
	if err := checkPeer(peer{uid: 1000, pid: 7}, 1000); err != nil {
		t.Errorf("the same user: %v", err)
	}
	for _, uid := range []uint32{1001, 0, 999, math.MaxUint32} {
		err := checkPeer(peer{uid: uid, pid: 7}, 1000)
		if want := fmt.Sprintf("refused a connection of user ID %d: only user ID 1000 may use this agent", uid); err == nil ||
			err.Error() != want {
			t.Errorf("user %d: %v", uid, err)
		}
	}
}

// TestAgentRefusesOtherUsers: a connection of another user is closed at
// once, without an answer, and one line says so. It reaches no broker. A
// connection whose user cannot be checked is closed too.
func TestAgentRefusesOtherUsers(t *testing.T) {
	t.Parallel()
	self, err := currentUID()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		peer func(*net.UnixConn) (peer, error)
		line string
	}{
		{"another user", func(*net.UnixConn) (peer, error) { return peer{uid: self + 1, pid: 1}, nil },
			fmt.Sprintf("nodkey: refused a connection of user ID %d: only user ID %d may use this agent", self+1, self)},
		{"root", func(*net.UnixConn) (peer, error) { return peer{uid: 0, pid: 1}, nil },
			fmt.Sprintf("nodkey: refused a connection of user ID 0: only user ID %d may use this agent", self)},
		{"unknown", func(*net.UnixConn) (peer, error) { return peer{}, errors.New("no credentials") },
			"nodkey: refused a connection: its user cannot be checked"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if self == 0 && tt.name == "root" {
				t.Skip("the test runs as root")
			}
			fb := newFakeSSHBroker(t, nil, nil)
			au := startAgent(t, fb.b, agentOptions{peer: tt.peer})
			ag := au.client(t)
			if _, err := ag.List(); err == nil {
				t.Fatal("the agent answered")
			}
			if got := au.lines(); !slices.Equal(got, []string{tt.line}) {
				t.Errorf("the agent wrote %q, want %q", got, tt.line)
			}
			if fb.requests.Load() != 0 {
				t.Error("a request reached the broker")
			}
		})
	}
}

// TestPeerCredentials: SO_PEERCRED gives the user and the process that
// connected.
func TestPeerCredentials(t *testing.T) {
	t.Parallel()
	got := make(chan peer, 1)
	self, err := currentUID()
	if err != nil {
		t.Fatal(err)
	}
	fb := newFakeSSHBroker(t, nil, nil)
	au := startAgent(t, fb.b, agentOptions{peer: func(c *net.UnixConn) (peer, error) {
		p, err := peerCredentials(c)
		got <- p
		return p, err
	}})
	ag := au.client(t)
	if _, err := ag.List(); err != nil {
		t.Fatal(err)
	}
	if p := <-got; p.uid != self || int(p.pid) != os.Getpid() {
		t.Errorf("SO_PEERCRED gives %+v; want user %d and process %d", p, self, os.Getpid())
	}
}

// TestAgentClosesOnBadLengths: a message that is empty or longer than
// 256 KiB closes the connection.
func TestAgentClosesOnBadLengths(t *testing.T) {
	t.Parallel()
	fb := newFakeSSHBroker(t, nil, nil)
	au := startAgent(t, fb.b, agentOptions{})
	for _, n := range []uint32{0, maxAgentMessage + 1, math.MaxUint32} {
		c := au.conn(t)
		if _, err := c.Write(binary.BigEndian.AppendUint32(nil, n)); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(waitLimit))
		if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Errorf("length %d: the read gave %v, want EOF", n, err)
		}
	}
	want := fmt.Sprintf("nodkey: closed a connection that sent a message that is empty or longer than %d bytes",
		maxAgentMessage)
	if got := au.lines(); !slices.Equal(got, []string{want, want, want}) {
		t.Errorf("the agent wrote %q", got)
	}
	// A message of the most bytes is read, and refused.
	c := au.conn(t)
	msg := append([]byte{agentAddIdentity}, bytes.Repeat([]byte("k"), maxAgentMessage-1)...)
	if answer := rawCall(t, c, msg); !bytes.Equal(answer, failureMessage) {
		t.Errorf("the answer is % x", answer)
	}
}

// TestLargestSignRequestFits: the largest request that the agent sends
// fits in the broker's cap (transport.MaxRequestBody), and the broker
// reads it: a key of api.MaxKey bytes, data of api.MaxData bytes, two
// session-binds of api.MaxBind bytes, 4 command lines and a reason at
// their limits, of characters that take the most bytes in JSON. Longer
// claimed fields become "[hidden: too long]", and more command lines are
// not sent.
func TestLargestSignRequestFits(t *testing.T) {
	t.Parallel()
	worst := strings.Repeat("\x01", api.MaxText)
	argv := make([]string, api.MaxArgs)
	for i := range argv {
		argv[i] = worst[:api.MaxText/api.MaxArgs]
	}
	binds := [][]byte{bytes.Repeat([]byte{0xff}, api.MaxBind), bytes.Repeat([]byte{0xfe}, api.MaxBind)}
	key, data := bytes.Repeat([]byte{0xfd}, api.MaxKey), bytes.Repeat([]byte{0xfc}, api.MaxData)
	commands := [][]string{argv, argv, argv, argv, argv}
	req := newSignRequest(key, data, math.MaxUint32, binds, commands, worst)
	if len(req.Commands) != api.MaxCommands || len(req.Commands[0]) != api.MaxArgs || req.Reason != worst {
		t.Fatalf("the request has %d command lines", len(req.Commands))
	}
	body, err := encodeSignRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > transport.MaxRequestBody {
		t.Errorf("the largest request has %d bytes, more than %d", len(body), transport.MaxRequestBody)
	}
	t.Logf("the largest sign request has %d bytes", len(body))
	// The broker reads it.
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, api.PathSign, bytes.NewReader(body))
	r.Header.Set("Content-Type", api.ContentType)
	got, err := transport.ReadJSON[api.SignRequest](httptest.NewRecorder(), r)
	if err != nil {
		t.Fatalf("the broker cannot read the largest request: %v", err)
	}
	if !bytes.Equal(got.PublicKey, key) || len(got.Commands) != api.MaxCommands || got.Flags != math.MaxUint32 {
		t.Error("the broker read another request")
	}
	// Longer claimed fields are hidden.
	long := newSignRequest(key, data, 0, binds, [][]string{append(argv, "x"), {worst + "x"}}, worst+"x")
	if !slices.Equal(long.Commands[0], []string{tooLong}) || !slices.Equal(long.Commands[1], []string{tooLong}) ||
		long.Reason != tooLong {
		t.Errorf("the long fields are not hidden")
	}
	if maxParents+1 != api.MaxCommands {
		t.Errorf("the agent sends %d command lines, the broker takes %d", maxParents+1, api.MaxCommands)
	}
	// A third session-bind is over the cap.
	if _, err := encodeSignRequest(newSignRequest(key, data, 0, append(binds, nil), nil, "")); err == nil {
		t.Error("encodeSignRequest took 3 session-binds")
	}
}

// TestCheckSignAnswer: the checks of a signature before ssh gets it.
func TestCheckSignAnswer(t *testing.T) {
	t.Parallel()
	signer, _ := newSSHKey(t)
	data := []byte("data")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}
	key := signer.PublicKey().Marshal()
	if got, err := checkSignAnswer(key, data, 0, &api.SignAnswer{Format: sig.Format, Blob: sig.Blob}); err != nil ||
		got.Format != sig.Format || !bytes.Equal(got.Blob, sig.Blob) {
		t.Errorf("a valid signature: %v, %v", got, err)
	}
	for _, tt := range []struct {
		name string
		key  []byte
		ans  api.SignAnswer
		want error
	}{
		{"not a key", []byte("key"), api.SignAnswer{Format: sig.Format, Blob: sig.Blob}, errSignatureKey},
		{"no format", key, api.SignAnswer{Blob: sig.Blob}, errSignatureFormat},
		{"a blob with more bytes", key, api.SignAnswer{Format: sig.Format, Blob: append(bytes.Clone(sig.Blob), 0)},
			errSignatureValid},
	} {
		if _, err := checkSignAnswer(tt.key, data, 0, &tt.ans); !errors.Is(err, tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, err, tt.want)
		}
	}
}

// TestAgentStopsCleanly: when the agent stops, it closes the open
// connections, also one whose request waits for the broker, and that
// request ends.
func TestAgentStopsCleanly(t *testing.T) {
	t.Parallel()
	deploy, _ := newSSHKey(t)
	waiting := make(chan struct{})
	hungUp := make(chan struct{})
	fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		if _, err := transport.ReadJSON[api.SignRequest](w, r); err != nil {
			return
		}
		close(waiting)
		<-r.Context().Done()
		close(hungUp)
	})
	self, err := currentUID()
	if err != nil {
		t.Fatal(err)
	}
	path := shortTempDir(t) + "/a/" + socketName
	sock, err := listenAgent(t.Context(), path, self, noDirCheck)
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuffer
	a := newSSHAgent(fb.b, newAgentLog(&out), procFS{root: t.TempDir()}, peerCredentials, self)
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.serve(ctx, sock.ln)
		sock.close()
	}()
	c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := writeAgentMessage(c, signRequestMessage(deploy.PublicKey().Marshal(), []byte("d"), 0)); err != nil {
		t.Fatal(err)
	}
	<-waiting
	cancel(interrupted{sig: 15})
	select {
	case <-done:
	case <-time.After(waitLimit):
		t.Fatal("the agent did not stop")
	}
	select {
	case <-hungUp:
	case <-time.After(waitLimit):
		t.Fatal("the broker did not see the agent hang up")
	}
	// The request may get its failure before the connection closes; it
	// never gets a signature.
	_ = c.SetReadDeadline(time.Now().Add(waitLimit))
	if answer, err := readAgentMessage(c); err == nil {
		if !bytes.Equal(answer, failureMessage) {
			t.Errorf("the request got % x", answer)
		}
		if _, err := readAgentMessage(c); err == nil {
			t.Error("the connection is still open")
		}
	}
	if got := linesOf(out.String()); !slices.Equal(got, []string{"nodkey: no signature: the agent stops"}) {
		t.Errorf("the agent wrote %q", got)
	}
	if _, err := (&net.Dialer{}).DialContext(t.Context(), "unix", path); err == nil {
		t.Error("the socket still takes connections")
	}
}

// TestAgentCancelsWhenSSHHangsUp: when ssh ends while its request waits
// for the person, such as after Ctrl-C, the agent closes its connection to
// the broker, so the broker cancels the request (DESIGN.md section 7).
func TestAgentCancelsWhenSSHHangsUp(t *testing.T) {
	t.Parallel()
	host, _ := newSSHKey(t)
	sb := newSSHBroker(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
	srv := startSSHServer(t, host, sb.user.PublicKey())
	au := startAgent(t, sb.client(t), agentOptions{})
	c := au.conn(t)
	ag := agent.NewClient(c)
	done := make(chan error, 1)
	go func() { done <- login(t.Context(), ag, srv, "deploy") }()
	code := sb.waitAsked(t, 1)[0].Prompt.ShortCode
	_ = c.Close()
	if err := <-done; err == nil {
		t.Fatal("the login worked")
	}
	if got := eventNames(sb.audit.waitFor(t, 2)); got != "request denied:cancelled" {
		t.Errorf("audit entries %q", got)
	}
	const last = "ssh closed its connection while the request waited"
	waitFor(t, "the agent's last line", func() bool { return strings.Contains(au.log.String(), last) })
	switch got := au.lines(); {
	case slices.Equal(got, []string{"nodkey: waiting for approval (request " + code + ")",
		"nodkey: no signature (request " + code + "): " + last}):
	case slices.Equal(got, []string{"nodkey: no signature: " + last}):
		// ssh hung up before the agent read the 102 Processing.
	default:
		t.Errorf("the agent wrote %q", got)
	}
}

// TestAgentKeepsAPipelinedRequest: a client may send its next request
// before the answer. The watch for a hang-up does not take it, and does
// not cancel the request that waits.
func TestAgentKeepsAPipelinedRequest(t *testing.T) {
	t.Parallel()
	deploy, _ := newSSHKey(t)
	waiting := make(chan struct{})
	release := make(chan struct{})
	stillThere := make(chan bool, 1)
	keys := api.KeysAnswer{Keys: []api.Key{{Name: "deploy", PublicKey: deploy.PublicKey().Marshal()}}}
	fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == api.PathKeys {
			_ = transport.WriteJSON(w, http.StatusOK, keys)
			return
		}
		req, err := transport.ReadJSON[api.SignRequest](w, r)
		if err != nil {
			return
		}
		close(waiting)
		<-release
		stillThere <- r.Context().Err() == nil
		signWith(deploy, "", "")(w, req)
	})
	au := startAgent(t, fb.b, agentOptions{})
	c := au.conn(t)
	if !bindAgent(t, c, []byte("bind")) {
		t.Fatal("the session-bind was refused")
	}
	data := []byte("data")
	if err := writeAgentMessage(c, signRequestMessage(deploy.PublicKey().Marshal(), data, 0)); err != nil {
		t.Fatal(err)
	}
	<-waiting
	if err := writeAgentMessage(c, []byte{agentListRequest}); err != nil {
		t.Fatal(err)
	}
	// Time for a wrong watch to take the request, or to hang up.
	time.Sleep(50 * time.Millisecond)
	close(release)
	if !<-stillThere {
		t.Error("the agent hung up on the broker")
	}
	_ = c.SetReadDeadline(time.Now().Add(waitLimit))
	first, err := readAgentMessage(c)
	if err != nil {
		t.Fatal(err)
	}
	if sig := signatureOf(t, first); sig == nil || deploy.PublicKey().Verify(data, sig) != nil {
		t.Fatalf("no valid signature; lines %q", au.lines())
	}
	second, err := readAgentMessage(c)
	if err != nil || len(second) == 0 || second[0] != agentListAnswer {
		t.Fatalf("the list request got % x, %v", second, err)
	}
}

// TestAgentCancelsWhenSSHHangsUpAfterMoreBytes: ssh hangs up while its
// request waits, also after it sent more bytes, such as the start of a
// next request that nobody reads. The agent still sees the hang-up, and
// closes its connection to the broker, so the broker cancels the request.
// (From the security review of issue #13: the watch stopped at the first
// byte.)
func TestAgentCancelsWhenSSHHangsUpAfterMoreBytes(t *testing.T) {
	t.Parallel()
	for _, extra := range [][]byte{nil, {0}, {0, 0, 0, 9, agentListRequest}} {
		t.Run(fmt.Sprintf("%d more bytes", len(extra)), func(t *testing.T) {
			t.Parallel()
			deploy, _ := newSSHKey(t)
			waiting := make(chan struct{})
			cancelled := make(chan bool, 1)
			fb := newFakeBroker(t, func(w http.ResponseWriter, r *http.Request) {
				if _, err := transport.ReadJSON[api.SignRequest](w, r); err != nil {
					return
				}
				close(waiting)
				select {
				case <-r.Context().Done():
					cancelled <- true
				case <-time.After(waitLimit):
					cancelled <- false
				}
				transport.WriteError(w, http.StatusForbidden)
			})
			au := startAgent(t, fb.b, agentOptions{})
			c := au.conn(t)
			if !bindAgent(t, c, []byte("bind")) {
				t.Fatal("the session-bind was refused")
			}
			if err := writeAgentMessage(c, signRequestMessage(deploy.PublicKey().Marshal(), []byte("d"), 0)); err != nil {
				t.Fatal(err)
			}
			<-waiting
			if len(extra) > 0 {
				if _, err := c.Write(extra); err != nil {
					t.Fatal(err)
				}
				time.Sleep(50 * time.Millisecond) // time for the agent to see the bytes first
			}
			_ = c.Close()
			if !<-cancelled {
				t.Fatal("ssh hung up, and the request still waits at the broker")
			}
			const last = "nodkey: no signature: ssh closed its connection while the request waited"
			waitFor(t, "the agent's line", func() bool { return slices.Contains(au.lines(), last) })
		})
	}
}

// captureSigner records the data that the ssh client of golang.org/x/crypto
// asks it to sign, and fails the login.
type captureSigner struct {
	pub  ssh.PublicKey
	data chan []byte
}

func (s *captureSigner) PublicKey() ssh.PublicKey { return s.pub }

func (s *captureSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	select {
	case s.data <- bytes.Clone(data):
	default:
	}
	return nil, errors.New("captured")
}

// validLogin returns a session-bind and data to sign that pass every check
// of the real broker for the key deploy, from one real key exchange with
// srv. The broker does not refuse a second use of them, so a process can
// send them again and again.
func validLogin(t *testing.T, sb *sshBroker, srv *sshServer) (bind, data []byte) {
	t.Helper()
	cs := &captureSigner{pub: sb.user.PublicKey(), data: make(chan []byte, 1)}
	nc, err := (&net.Dialer{Timeout: waitLimit}).DialContext(t.Context(), "tcp", srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = nc.Close() }()
	cfg := &ssh.ClientConfig{User: "deploy", Auth: []ssh.AuthMethod{ssh.PublicKeys(cs)},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey)}
	_, _, _, _ = ssh.NewClientConn(nc, srv.addr, cfg)
	select {
	case data = <-cs.data:
	default:
		t.Fatal("no data to sign")
	}
	b := srv.binds()
	return b[len(b)-1], data
}

// TestAgentShortCodeLinesAreLimited: the broker sends a short code for
// every request that starts to wait, also in its queue, and a request
// that hangs up frees its place. So any process of the user can make the
// agent get many short codes. The agent writes at most agentLogLines of
// them in a minute, and then says how many it left out. (From the
// security review of issue #13: one process made 150 lines in 1.7 s.)
func TestAgentShortCodeLinesAreLimited(t *testing.T) {
	t.Parallel()
	host, _ := newSSHKey(t)
	sb := newSSHBroker(t, map[string]ssh.PublicKey{"web-1": host.PublicKey()})
	srv := startSSHServer(t, host, sb.user.PublicKey())
	// A clock that does not move: the whole test is in one minute.
	au := startAgent(t, sb.client(t), agentOptions{now: func() time.Time { return noon }})
	bind, data := validLogin(t, sb, srv)
	msg := signRequestMessage(sb.user.PublicKey().Marshal(), data, 0)
	// Fill the 5 places for messages; nobody answers them.
	for range 5 {
		c := au.conn(t)
		if !bindAgent(t, c, bind) {
			t.Fatal("the session-bind was refused")
		}
		if err := writeAgentMessage(c, msg); err != nil {
			t.Fatal(err)
		}
	}
	sb.waitAsked(t, 5)
	waitFor(t, "5 short codes", func() bool { return au.shortCodes() == 5 })
	// Each new request goes into the queue, gets a short code, and hangs
	// up, which frees its place.
	const rounds = agentLogLines + 10
	for i := 0; i < rounds; {
		before := au.shortCodes()
		c, err := (&net.Dialer{}).DialContext(t.Context(), "unix", au.socket)
		if err != nil {
			t.Fatal(err)
		}
		if !bindAgent(t, c, bind) {
			t.Fatal("the session-bind was refused")
		}
		if err := writeAgentMessage(c, msg); err != nil {
			t.Fatal(err)
		}
		queued := false
		deadline := time.Now().Add(waitLimit)
		for !queued && time.Now().Before(deadline) {
			if au.shortCodes() > before {
				queued = true
				break
			}
			_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
			if _, err := readAgentMessage(c); err == nil {
				break // denied, such as by a full queue: try again
			}
		}
		_ = c.Close()
		if queued {
			i++
		}
	}
	au.stop()
	out := au.log.String()
	if n := countLines(out, "waiting for approval"); n != agentLogLines {
		t.Errorf("%d lines with a short code; want %d", n, agentLogLines)
	}
	want := fmt.Sprintf("nodkey: left out %d lines about requests that wait for approval, to keep the log short",
		5+rounds-agentLogLines)
	if !slices.Contains(linesOf(out), want) {
		t.Errorf("no line %q", want)
	}
}

// pieceReader gives data in pieces of at most 1000 bytes, and records the
// size of each buffer that it gets.
type pieceReader struct {
	data  []byte
	sizes []int
}

func (r *pieceReader) Read(p []byte) (int, error) {
	r.sizes = append(r.sizes, len(p))
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data[:min(len(r.data), 1000)])
	r.data = r.data[n:]
	return n, nil
}

// TestReadAgentMessageGrows: the buffer of a message grows as its bytes
// come. A length alone, without the bytes, takes at most firstPiece
// bytes. (From the security review of issue #13: 200 connections that
// sent only a length held about 55 MiB.)
func TestReadAgentMessageGrows(t *testing.T) {
	t.Parallel()
	body := make([]byte, maxAgentMessage)
	for i := range body {
		body[i] = byte(i)
	}
	r := &pieceReader{data: append(binary.BigEndian.AppendUint32(nil, maxAgentMessage), body...)}
	msg, err := readAgentMessage(r)
	if err != nil || !bytes.Equal(msg, body) {
		t.Fatalf("the message of %d bytes: %v", len(msg), err)
	}
	if len(r.sizes) < 2 || r.sizes[1] > firstPiece {
		t.Errorf("the first buffer for the bytes has %v bytes; want at most %d", r.sizes[1:min(2, len(r.sizes))], firstPiece)
	}
	// Only a length and a few bytes: the buffer stays small, and the
	// short message is an error.
	r = &pieceReader{data: append(binary.BigEndian.AppendUint32(nil, maxAgentMessage), "short"...)}
	if _, err := readAgentMessage(r); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a short message: %v", err)
	}
	if most := slices.Max(r.sizes); most > firstPiece {
		t.Errorf("a short message got a buffer of %d bytes", most)
	}
}

// TestAgentCapsConnections: the agent serves at most maxConns connections
// at the same time, and closes a connection over that at once, with one
// line. When a connection ends, a new one is served again.
func TestAgentCapsConnections(t *testing.T) {
	t.Parallel()
	deploy, _ := newSSHKey(t)
	fb := newFakeSSHBroker(t, map[string]ssh.PublicKey{"deploy": deploy.PublicKey()}, nil)
	au := startAgent(t, fb.b, agentOptions{maxConns: 3})
	var open []net.Conn
	for range 3 {
		open = append(open, au.conn(t))
	}
	over := au.conn(t)
	_ = over.SetReadDeadline(time.Now().Add(waitLimit))
	if _, err := over.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("a connection over the cap: %v; want it closed", err)
	}
	want := "nodkey: refused a connection: 3 connections are open, the most that the agent serves"
	if got := au.lines(); !slices.Equal(got, []string{want}) {
		t.Errorf("the agent wrote %q", got)
	}
	_ = open[0].Close()
	waitFor(t, "the closed connection to end", func() bool { return au.openConns() == 2 })
	if keys, err := au.client(t).List(); err != nil || len(keys) != 1 {
		t.Errorf("after a connection ended: %v, %v", keys, err)
	}
}

// TestAgentIdleConnectionsHoldLittleMemory: many connections that send
// only the length of a long message hold little memory: the buffers grow
// as bytes come, and the agent serves at most maxAgentConns connections.
func TestAgentIdleConnectionsHoldLittleMemory(t *testing.T) { // not parallel: it measures the heap
	fb := newFakeSSHBroker(t, nil, nil)
	au := startAgent(t, fb.b, agentOptions{})
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const n = 200
	for range n {
		// The agent closes the connections over its cap at once, so a
		// write to them may fail.
		_, _ = au.conn(t).Write(binary.BigEndian.AppendUint32(nil, maxAgentMessage))
	}
	waitFor(t, "the agent to take the connections", func() bool { return au.openConns() == maxAgentConns })
	time.Sleep(300 * time.Millisecond) // time to read the lengths
	runtime.GC()
	runtime.ReadMemStats(&after)
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc) //nolint:gosec // G115: heap sizes fit in an int64.
	t.Logf("%d connections that sent only a length: the heap grew by %d KiB", n, grew>>10)
	if grew > 8<<20 {
		t.Errorf("the heap grew by %d MiB", grew>>20)
	}
}

// TestAgentStopsWithStuckConnections: when the agent stops, it waits for
// its connections at most stopWait, also when one of them is stuck.
func TestAgentStopsWithStuckConnections(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	defer close(release)
	stuck := make(chan struct{}, 1)
	fb := newFakeSSHBroker(t, nil, nil)
	au := startAgent(t, fb.b, agentOptions{stopWait: 100 * time.Millisecond,
		peer: func(*net.UnixConn) (peer, error) {
			stuck <- struct{}{}
			<-release
			return peer{}, errors.New("released")
		}})
	au.conn(t)
	<-stuck
	start := time.Now()
	au.stop()
	if d := time.Since(start); d > waitLimit/2 {
		t.Errorf("the agent stopped after %s", d)
	}
	if got := au.lines(); !slices.Contains(got, "nodkey: stopped without waiting longer for its connections (1 still open)") {
		t.Errorf("the agent wrote %q", got)
	}
}

// TestAgentProcTimeout: a read of /proc that blocks, such as on a stuck
// FUSE or NFS file system, holds a request at most procTimeout. The
// request then goes without the command lines and the reason, and a line
// says why. When maxProcReads reads are stuck, the agent starts no new
// one. (From the security review of issue #13.)
func TestAgentProcTimeout(t *testing.T) {
	t.Parallel()
	p := newFakeProc(t)
	p.add(t, 4242, 1, []string{"ssh", "web-1"}, []string{"NODKEY_REASON=r"})
	fifo := filepath.Join(p.root, "4242", "cmdline")
	if err := os.Remove(fifo); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// A writer ends the opens that wait; the reads then end.
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil { //nolint:gosec // G304: the FIFO that the test made.
			_ = w.Close()
		}
	})
	self, err := currentUID()
	if err != nil {
		t.Fatal(err)
	}
	fb := newFakeSSHBroker(t, nil, func(w http.ResponseWriter, _ *api.SignRequest) {
		transport.WriteError(w, http.StatusForbidden)
	})
	au := startAgent(t, fb.b, agentOptions{proc: p.fs(), procTimeout: 100 * time.Millisecond,
		peer: func(*net.UnixConn) (peer, error) { return peer{uid: self, pid: 4242}, nil }})
	for range maxProcReads + 1 {
		start := time.Now()
		if signOnce(t, au, deploy0(t), []byte("data"), 0) != nil {
			t.Fatal("the agent gave ssh a signature")
		}
		if d := time.Since(start); d > waitLimit/2 {
			t.Fatalf("the request took %s", d)
		}
	}
	reqs := fb.signRequests()
	if len(reqs) != maxProcReads+1 {
		t.Fatalf("the broker got %d requests", len(reqs))
	}
	for _, r := range reqs {
		if len(r.Commands) != 0 || r.Reason != "" {
			t.Errorf("a request has the claimed context %q, %q", r.Commands, r.Reason)
		}
	}
	timeout := "nodkey: sent a sign request without the command lines and the reason: /proc did not answer within 100ms"
	stuck := fmt.Sprintf("nodkey: sent a sign request without the command lines and the reason: %d reads of /proc "+
		"are stuck", maxProcReads)
	if got := au.lines(); countLines(au.log.String(), timeout[len("nodkey: "):]) != maxProcReads ||
		got[len(got)-2] != stuck {
		t.Errorf("the agent wrote %q", got)
	}
}

// deploy0 returns an Ed25519 public key for requests that a fake broker
// answers.
func deploy0(t *testing.T) ssh.PublicKey {
	t.Helper()
	k, _ := newSSHKey(t)
	return k.PublicKey()
}
