package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
)

// fakeNtfy is the smallest ntfy server that the broker needs: publish as
// JSON on "/", a POST of text to the answer topic, and its JSON stream.
// The token is made at run time.
type fakeNtfy struct {
	t     *testing.T
	srv   *httptest.Server
	token string // the token that publish and read accept

	mu        sync.Mutex
	published []ntfyMessage
	subs      []chan []byte
	nextID    int
}

type ntfyMessage struct {
	Topic   string `json:"topic"`
	Title   string `json:"title"`
	Message string `json:"message"`
	Actions []struct {
		Label  string `json:"label"`
		URL    string `json:"url"`
		Method string `json:"method"`
		Body   string `json:"body"`
	} `json:"actions"`
}

const (
	ntfyRequests = "fake-requests"
	ntfyAnswers  = "fake-answers"
)

func newFakeNtfy(t *testing.T) *fakeNtfy {
	t.Helper()
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	f := &fakeNtfy{t: t, token: "tk_" + hex.EncodeToString(b)}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// useIn puts a token file and a CA file into e, and returns cfg with
// [ntfy] in place of [telegram]. The token file holds token, which is not
// the token of the server when the caller changed f.token.
func (f *fakeNtfy) useIn(e *brokerEnv, cfg string) string {
	creds := filepath.Join(e.dir, "creds")
	writeTestFile(f.t, filepath.Join(creds, "ntfy-token"), []byte(f.token+"\n"), 0o600)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	e.caFile = filepath.Join(e.dir, "ntfy-ca.pem")
	writeTestFile(f.t, e.caFile, ca, 0o600)
	i, j := strings.Index(cfg, "[telegram]"), strings.Index(cfg, "[client.laptop]")
	section := fmt.Sprintf("[ntfy]\nserver = %q\nrequest_topic = %q\nanswer_topic = %q\ntoken_file = %q\n\n",
		f.srv.URL, ntfyRequests, ntfyAnswers, "${CREDENTIALS_DIRECTORY}/ntfy-token")
	return cfg[:i] + section + cfg[j:]
}

func (f *fakeNtfy) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/":
		var m ntfyMessage
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&m); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.published = append(f.published, m)
		f.nextID++
		id := fmt.Sprintf("m%011d", f.nextID)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "time": time.Now().Unix(), "event": "message", "topic": m.Topic})
	case r.Method == http.MethodPost && r.URL.Path == "/"+ntfyAnswers:
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		f.answer(string(body))
		_, _ = io.WriteString(w, `{"id":"x","event":"message"}`)
	case r.Method == http.MethodGet && r.URL.Path == "/"+ntfyAnswers+"/json":
		f.stream(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (f *fakeNtfy) answer(body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	line, _ := json.Marshal(map[string]any{"id": fmt.Sprintf("m%011d", f.nextID), "time": time.Now().Unix(),
		"event": "message", "topic": ntfyAnswers, "message": body})
	for _, c := range f.subs {
		c <- append(line, '\n')
	}
}

func (f *fakeNtfy) stream(w http.ResponseWriter, r *http.Request) {
	c := make(chan []byte, 64)
	f.mu.Lock()
	f.subs = append(f.subs, c)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/x-ndjson")
	_, _ = fmt.Fprintf(w, `{"id":"open1","time":%d,"event":"open","topic":%q}`+"\n", time.Now().Unix(), ntfyAnswers)
	w.(http.Flusher).Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case l := <-c:
			_, _ = w.Write(l)
			w.(http.Flusher).Flush()
		}
	}
}

// waitRequest waits until a published message has a button with label,
// and returns it.
func (f *fakeNtfy) waitRequest(label string) ntfyMessage {
	f.t.Helper()
	for end := time.Now().Add(brokerWait); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		f.mu.Lock()
		for _, m := range f.published {
			for _, a := range m.Actions {
				if a.Label == label {
					f.mu.Unlock()
					return m
				}
			}
		}
		f.mu.Unlock()
	}
	f.t.Fatalf("no request with the button %q was published", label)
	return ntfyMessage{}
}

// press presses the button with label, as the phone does.
func (f *fakeNtfy) press(m ntfyMessage, label string) {
	f.t.Helper()
	for _, a := range m.Actions {
		if a.Label != label {
			continue
		}
		req, err := http.NewRequestWithContext(context.Background(), a.Method, a.URL, bytes.NewReader([]byte(a.Body)))
		if err != nil {
			f.t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.token)
		resp, err := f.srv.Client().Do(req)
		if err != nil {
			f.t.Fatal(err)
		}
		_ = resp.Body.Close()
		return
	}
	f.t.Fatalf("no button %q", label)
}

// TestBrokerNtfyApproves: with [ntfy] in the config, a request for a
// secret reaches the ntfy server as a message with buttons, and a press
// of "Approve once" approves it. The broker stops clean with SIGTERM.
func TestBrokerNtfyApproves(t *testing.T) {
	t.Parallel()
	f := newFakeNtfy(t)
	e := startListening(t, brokerOptions{ntfy: f})
	c := e.httpClient()
	res := make(chan brokerAnswer, 1)
	go func() { res <- e.post(c, api.PathSecrets, secretsRequest("GH_TOKEN", "github-token")) }()
	m := f.waitRequest("Approve once")
	// A press can come before the broker knows the message ID; the
	// answer then does nothing, and the person presses again.
	var a brokerAnswer
loop:
	for end := time.Now().Add(2 * brokerWait); time.Now().Before(end); {
		f.press(m, "Approve once")
		select {
		case a = <-res:
			break loop
		case <-time.After(100 * time.Millisecond):
		}
	}
	mustStatus(t, a, http.StatusOK)
	if got := secretValues(t, a); got["GH_TOKEN"] != e.values["github-token"] {
		t.Errorf("the secret is not the one that the store holds")
	}
	if strings.Contains(e.stderr.text(), f.token) {
		t.Error("the log of the broker has the ntfy token")
	}
	e.signal(syscall.SIGTERM)
	e.mustExit(exitOK)
}

// TestBrokerNtfyRefused: when the server refuses the token on the answer
// topic (403), the broker stops with exit code 77, as for a refused
// Telegram token, and the log does not show the token.
func TestBrokerNtfyRefused(t *testing.T) {
	t.Parallel()
	f := newFakeNtfy(t)
	e := newBrokerEnv(t, brokerOptions{ntfy: f})
	// The server knows another token than the file.
	f.mu.Lock()
	f.token += "x"
	f.mu.Unlock()
	e.start()
	e.mustExit(exitTokenRefused)
	if strings.Contains(e.stderr.text(), f.token) {
		t.Error("the log of the broker has the ntfy token")
	}
}
