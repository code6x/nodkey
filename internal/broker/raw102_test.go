package broker

// Regression test from the security review of issue #11 (part A): the
// exact bytes of the 102 Processing answer, as a raw client sees them.

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/transport"
)

func TestRaw102(t *testing.T) {
	e := newEnv(t, envOptions{})
	d := tls.Dialer{Config: transport.ClientTLSConfig(e.clients["laptop"].cert, e.broker.pin)}
	conn, err := d.DialContext(t.Context(), "tcp", e.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	body, err := json.Marshal(secretsRequest("GH_TOKEN", "github-token"))
	if err != nil {
		t.Fatal(err)
	}
	req := fmt.Sprintf("POST /v1/secrets HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n"+
		"Content-Length: %d\r\n\r\n%s", len(body), body)
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(waitLimit))
	br := bufio.NewReader(conn)
	var head strings.Builder
	for !strings.HasSuffix(head.String(), "\r\n\r\n") {
		b, err := br.ReadByte()
		if err != nil {
			t.Fatalf("reading the 102: %v (so far %q)", err, head.String())
		}
		head.WriteByte(b)
	}
	want := regexp.MustCompile("^HTTP/1\\.1 102 Processing\r\nNodkey-Short-Code: [2-9a-hjkmnp-z]{4}\r\n\r\n$")
	if !want.MatchString(head.String()) {
		t.Errorf("the 102 answer is %q", head.String())
	}
	asked := e.waitAsked(1)
	if !strings.Contains(head.String(), asked[0].Prompt.ShortCode) {
		t.Errorf("the 102 has another short code than the message: %q vs %q", head.String(), asked[0].Prompt.ShortCode)
	}
}
