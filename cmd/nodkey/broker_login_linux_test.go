package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/client"
)

// The login item of the slow fake bw, its collection and its page.
const (
	slowItem = "11111111-1111-4111-8111-111111111111"
	slowColl = "22222222-2222-4222-8222-222222222222"
	slowPage = "https://example.com/sign-in"
)

// slowBWPause is how long each run of the slow fake bw takes: about the
// time that one run of bw takes on a small host (issue #190).
const slowBWPause = 5 * time.Second

// TestBrokerLoginWithSlowStore: on a host where each run of bw takes 5 s,
// a login after "nodkey preapprove --login" is answered from the
// broker's memory, through nodkey agent-browser-plugin, in under 2 s and
// with no run of bw (DESIGN.md section 21.3, issue #190).
func TestBrokerLoginWithSlowStore(t *testing.T) {
	if testing.Short() {
		t.Skip("each run of the fake bw takes 5 s")
	}
	e := newBrokerEnv(t, brokerOptions{updatesOff: true})
	pw := madeUp("shop-password")
	calls := filepath.Join(e.dir, "bw-calls")
	item := fmt.Sprintf(`{"id":%q,"type":1,"name":"Example shop","collectionIds":[%q],`+
		`"login":{"username":"alice@example.com","password":%q,"uris":[{"uri":"https://example.com","match":null}]}}`,
		slowItem, slowColl, pw)
	itemFile := filepath.Join(e.dir, "bw-item.json")
	writeTestFile(t, itemFile, []byte(item), 0o600)
	// A fake bw: each run writes its command to calls, sleeps, and answers
	// as bw does.
	bw := fmt.Sprintf(`#!/bin/sh
echo "$1" >> %[1]q
sleep %[2]d
case "$1" in
unlock) printf '%%s' 'c2Vzc2lvbi1rZXktb2YtdGhlLWZha2UtYnc=' ;;
sync) printf 'Syncing complete.' ;;
status) printf '%%s' '{"status":"unlocked"}' ;;
get) [ "$3" = %[3]q ] || exit 1; cat %[4]q ;;
list) printf '['; cat %[4]q; printf ']' ;;
*) exit 1 ;;
esac
`, calls, int(slowBWPause/time.Second), slowItem, itemFile)
	writeTestFile(t, filepath.Join(e.dir, "bin", "bw"), []byte(bw), 0o700)
	writeTestFile(t, filepath.Join(e.dir, "creds", "bw-password"), []byte(madeUp("master")+"\n"), 0o600)
	cfg, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg = append(cfg, fmt.Sprintf(`
[store.web]
type = "bw"
program = %q
password_file = "${CREDENTIALS_DIRECTORY}/bw-password"

[logins.web]
store = "web"
collection = %q
clients = ["laptop"]
ask = "always"
preapprove = true
`, filepath.Join(e.dir, "bin", "bw"), slowColl)...)
	writeTestFile(t, e.cfgPath, cfg, 0o600)
	e.start()
	e.stderr.wait(t, lineListenOpen)

	// The tap of the pre-approval: the broker fetches the item before and
	// after it.
	c := e.httpClient()
	mustStatus(t, e.approve(c, api.PathPreapprove, api.PreapproveRequest{Login: slowItem, URL: slowPage, Uses: 1}), http.StatusOK)
	before := bwCalls(t, calls)

	// agent-browser's credential.resolve, through the plugin.
	home := filepath.Join(e.dir, "home")
	if err := os.MkdirAll(filepath.Join(home, ".config", "nodkey"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(home, ".config", "nodkey", "client.toml"), []byte(fmt.Sprintf(
		"broker = %q\nbroker_pin = %q\ntls_key = %q\n", e.addr, e.brokerPin.String(), filepath.Join(e.dir, "client.key"))), 0o600)
	t.Setenv("HOME", home)
	req, err := json.Marshal(map[string]any{
		"capability": "credential.read", "protocol": "agent-browser.plugin.v1", "type": "credential.resolve",
		"request": map[string]string{"itemRef": slowItem, "url": slowPage},
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	start := time.Now()
	code := client.AgentBrowserPlugin(nil, bytes.NewReader(req), &stdout, &stderr, "dev")
	took := time.Since(start)
	if code != 0 || !strings.Contains(stdout.String(), `"success":true`) {
		t.Fatalf("the plugin: exit %d, %s %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"username":"alice@example.com"`) {
		t.Error("the answer has no username")
	}
	if took >= 2*time.Second {
		t.Errorf("credential.resolve took %s; want under 2s", took)
	}
	if after := bwCalls(t, calls); after != before {
		t.Errorf("the login ran bw %d times; want 0", after-before)
	}
	// The journal shows the slow steps of the pre-approval, without the
	// password.
	if !e.stderr.has("a store step was slow") {
		t.Error("the journal has no line about a slow store step")
	}
	if strings.Contains(e.stderr.text(), pw) {
		t.Error("the password is in the journal")
	}
}

// bwCalls returns the number of runs of the fake bw so far.
func bwCalls(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // G304: the file of the test's fake bw.
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "\n")
}
