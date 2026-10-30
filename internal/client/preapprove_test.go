package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/audit"
)

// preArgs are the arguments of a request for logins as deploy with the key
// deploy to web-1, from noon for one hour, for 2 uses, and then extra.
func preArgs(extra ...string) []string {
	return append([]string{"--key", "deploy", "--user", "deploy", "--host", "web-1",
		"--from", "2026-10-15T12:00:00Z", "--until", "2026-10-15T13:00:00+00:00", "--uses", "2"}, extra...)
}

// preIn runs nodkey preapprove in the test, and returns the exit code,
// what it wrote to stdout and to stderr.
func preIn(ctx context.Context, g granter, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := g.runPreapprove(ctx, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestPreapproveApproves: the person approves. nodkey preapprove prints
// the ID of the grant on stdout, and its last line says the grant and the
// span. The message shows the key, the user, the hosts, the uses and the
// span. Then the broker signs the logins without a tap, twice, and the
// third asks.
func TestPreapproveApproves(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveOnce)
	laptop := gb.client(t, "laptop")
	code, stdout, stderr := preIn(t.Context(), testGranter(laptop, []string{"NODKEY_REASON=from the environment"}),
		preArgs()...)
	p := gb.waitAsked(t, 1)[0].Prompt
	id := strings.TrimSuffix(stdout, "\n")
	want := "nodkey: waiting for approval (request " + p.ShortCode + ")\nnodkey: grant " + id +
		": 2 uses from 2026-10-15T12:00:00Z until 2026-10-15T13:00:00Z (exit 0)\n"
	if code != exitOK || stderr != want || !validGrantID(id) || strings.Count(stdout, "\n") != 1 {
		t.Fatalf("exit code %d, stdout %q, stderr %q; want 0, an ID, and %q", code, stdout, stderr, want)
	}
	if p.Kind != audit.KindPreapprove || p.Key != "deploy" || p.RemoteUser != "deploy" || !slices.Equal(p.Hosts, []string{"web-1"}) ||
		p.Uses != 2 || !p.From.Equal(noon) || !p.Until.Equal(noon.Add(time.Hour)) || !p.Once || p.WindowMinutes != 0 ||
		p.Claim.Reason != "from the environment" {
		t.Errorf("the message shows %+v", p)
	}
	if got := gb.lastEvents(); got != "request decision:approve_once" {
		t.Errorf("audit entries: %s", got)
	}
	gb.approver.Auto("")
	for i := range 2 {
		if err := gb.sign(t, laptop, "deploy", gb.signRequest(t, "deploy", "web-1", i, "deploy")); err != nil {
			t.Fatalf("login %d: %v", i+1, err)
		}
	}
	if n := len(gb.approver.Asked()); n != 1 {
		t.Errorf("%d messages, want 1", n)
	}
	if n := len(gb.approver.Notices()); n != 2 {
		t.Errorf("%d notices, want 2", n)
	}
	gb.mustAsk(t, laptop, gb.signRequest(t, "deploy", "web-1", 0, "deploy"), 2)
}

// TestPreapproveCancelCommand: --cancel ends the grant without a tap and
// says so. The same ID again, the ID of another client and an unknown ID
// all end with 77 and the same line.
func TestPreapproveCancelCommand(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveOnce)
	laptop := gb.client(t, "laptop")
	_, stdout, _ := preIn(t.Context(), testGranter(laptop, nil), preArgs()...)
	id := strings.TrimSuffix(stdout, "\n")
	gb.approver.Auto("")
	ci := testGranter(gb.client(t, "ci"), nil)
	g := testGranter(laptop, nil)
	code1, out1, err1 := preIn(t.Context(), ci, "--cancel", id)
	code2, out2, err2 := preIn(t.Context(), g, "--cancel", "AAAAAAAAAAAAAAAAAAAAAA")
	if code1 != exitDenied || code2 != exitDenied || out1 != "" || out2 != "" || err1 != err2 ||
		lastLine(err1) != "nodkey: denied (exit 77)" {
		t.Errorf("another client: %d %q %q; unknown: %d %q %q; want the same, 77", code1, out1, err1, code2, out2, err2)
	}
	code, out, errText := preIn(t.Context(), g, "--cancel", id)
	if want := "nodkey: grant " + id + " cancelled (exit 0)\n"; code != exitOK || out != "" || errText != want {
		t.Errorf("cancel: %d, stdout %q, stderr %q; want 0 and %q", code, out, errText, want)
	}
	// The entry names the request of the pre-approval.
	if got := gb.lastEvents(); got != "request decision:approve_once grant_ended:cancelled" {
		t.Errorf("audit entries: %s", got)
	}
	if code, _, _ := preIn(t.Context(), g, "--cancel", id); code != exitDenied {
		t.Errorf("a second cancel: exit code %d, want 77", code)
	}
	gb.mustAsk(t, laptop, gb.signRequest(t, "deploy", "web-1", 0, "deploy"), 2)
	if n := len(gb.approver.Asked()); n != 2 {
		t.Errorf("%d messages: the cancel asked the person", n)
	}
}

// TestPreapproveDenied: the person taps Deny, or the broker refuses the
// request: 77, no ID on stdout. A refusal comes without a waiting line.
func TestPreapproveDenied(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerDeny)
	g := testGranter(gb.client(t, "laptop"), nil)
	code, stdout, stderr := preIn(t.Context(), g, preArgs()...)
	if code != exitDenied || stdout != "" || lastLine(stderr) != "nodkey: denied (exit 77)" || len(waitingCodes(stderr)) != 1 ||
		strings.Contains(stderr, "may have started") {
		t.Errorf("a Deny: exit code %d, stdout %q, stderr %q; want 77 and one waiting line", code, stdout, stderr)
	}
	for name, args := range map[string][]string{
		"preapprove is off for the key": {"--key", "admin", "--user", "deploy", "--host", "web-1",
			"--from", "2026-10-15T12:00", "--until", "2026-10-15T13:00", "--uses", "1"},
		"over max_uses": {"--key", "deploy", "--user", "deploy", "--host", "web-1",
			"--from", "2026-10-15T12:00", "--until", "2026-10-15T13:00", "--uses", "11"},
		"over max_open": {"--key", "deploy", "--user", "deploy", "--host", "web-1",
			"--from", "2026-10-15T12:00", "--until", "2026-10-15T21:00:01", "--uses", "1"},
	} {
		gb.clock.Advance(approval.DenyPause)
		code, stdout, stderr = preIn(t.Context(), g, args...)
		if code != exitDenied || stdout != "" || stderr != "nodkey: denied (exit 77)\n" || strings.Contains(stderr, "may have started") {
			t.Errorf("%s: exit code %d, stdout %q, stderr %q; want 77 and only the last line", name, code, stdout, stderr)
		}
	}
}

// TestPreapproveCancelByInterrupt: SIGINT while nodkey preapprove waits
// cancels the request, as for nodkey ssh-grant, and no grant starts.
func TestPreapproveCancelByInterrupt(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	laptop := gb.client(t, "laptop")
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	done := make(chan int, 1)
	var stdout, stderr string
	go func() {
		var code int
		code, stdout, stderr = preIn(ctx, testGranter(laptop, nil), preArgs()...)
		done <- code
	}()
	p := gb.waitAsked(t, 1)[0].Prompt
	cancel(interrupted{sig: syscall.SIGINT})
	if code := <-done; code != 130 || stdout != "" || lastLine(stderr) != "nodkey: cancelled by SIGINT (exit 130)" {
		t.Errorf("exit code %d, stdout %q, stderr %q; want 130", code, stdout, stderr)
	}
	gb.waitEvents(t, p.RequestID, "request denied:cancelled")
	gb.mustAsk(t, laptop, gb.signRequest(t, "deploy", "web-1", 0, "deploy"), 2)
}

// TestPreapproveUnreachable: a broker that cannot be reached, or a config
// that cannot be read, ends with 69.
func TestPreapproveUnreachable(t *testing.T) {
	t.Parallel()
	g := testGranter(nil, nil) // load fails
	code, stdout, stderr := preIn(t.Context(), g, preArgs()...)
	if code != exitUnavailable || stdout != "" || !strings.HasSuffix(stderr, "(exit 69)\n") {
		t.Errorf("exit code %d, stdout %q, stderr %q; want 69", code, stdout, stderr)
	}
	code, _, stderr = preIn(t.Context(), g, "--cancel", "AAAAAAAAAAAAAAAAAAAAAA")
	if code != exitUnavailable || !strings.HasSuffix(stderr, "(exit 69)\n") {
		t.Errorf("cancel: exit code %d, stderr %q; want 69", code, stderr)
	}
}

// TestPreapproveAnswerForms: the client takes an ID and times of the form
// that the broker writes, and nothing else.
func TestPreapproveAnswerForms(t *testing.T) {
	for _, valid := range []string{"AAAAAAAAAAAAAAAAAAAAAA", "abcdefghijklmnopqrstuv"} {
		if !validGrantID(valid) {
			t.Errorf("%q is refused", valid)
		}
	}
	for _, bad := range []string{"", "AAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAA\n",
		"AAAAAAAAAAAAAAAAAAAA A"} {
		if validGrantID(bad) {
			t.Errorf("%q is accepted", bad)
		}
	}
	if !validAnswerTime("2026-10-15T12:00:00+02:00") || validAnswerTime("2026-10-15 12:00") || validAnswerTime("") {
		t.Error("validAnswerTime is wrong")
	}
}

// TestPreapproveUsage: wrong arguments end with 64, after the usage, and
// ask nothing.
func TestPreapproveUsage(t *testing.T) {
	t.Parallel()
	key := preArgs()
	secret := []string{"--secret", "backup-token", "--from", "2026-10-15T12:00", "--until", "2026-10-15T13:00", "--uses", "1"}
	drop := func(args []string, option string) []string {
		out := slices.Clone(args)
		i := slices.Index(out, option)
		return slices.Delete(out, i, i+2)
	}
	many := []string{"--key", "deploy", "--user", "deploy", "--from", "2026-10-15T12:00", "--until", "2026-10-15T13:00",
		"--uses", "1"}
	for i := range api.MaxGrantHosts + 1 {
		many = append(many, "--host", "web-"+strings.Repeat("x", i%5)+string(rune('a'+i)))
	}
	var secrets []string
	secrets = append(secrets, "--from", "2026-10-15T12:00", "--until", "2026-10-15T13:00", "--uses", "1")
	for i := range api.MaxSecrets + 1 {
		secrets = append(secrets, "--secret", fmt.Sprintf("s%d", i))
	}
	for name, args := range map[string][]string{
		"nothing":                    {},
		"no key and no secret":       {"--from", "2026-10-15T12:00", "--until", "2026-10-15T13:00", "--uses", "1"},
		"no user":                    drop(key, "--user"),
		"no host":                    drop(key, "--host"),
		"no from":                    drop(key, "--from"),
		"no until":                   drop(key, "--until"),
		"no uses":                    drop(key, "--uses"),
		"a key and a secret":         append(slices.Clone(key), "--secret", "x"),
		"a secret and a user":        append(slices.Clone(secret), "--user", "deploy"),
		"a secret and a host":        append(slices.Clone(secret), "--host", "web-1"),
		"a bad secret name":          append(drop(secret, "--secret"), "--secret", "a b"),
		"a secret twice":             append(slices.Clone(secret), "--secret", "backup-token"),
		"too many secrets":           secrets,
		"too many hosts":             many,
		"a bad key name":             append(drop(key, "--key"), "--key", "-x"),
		"a bad user":                 append(drop(key, "--user"), "--user", "a b"),
		"a host twice":               append(slices.Clone(key), "--host", "web-1"),
		"from twice":                 append(slices.Clone(key), "--from", "2026-10-15T12:00"),
		"uses twice":                 append(slices.Clone(key), "--uses", "3"),
		"0 uses":                     append(drop(key, "--uses"), "--uses", "0"),
		"negative uses":              append(drop(key, "--uses"), "--uses=-1"),
		"uses that are not a number": append(drop(key, "--uses"), "--uses", "two"),
		"too many uses":              append(drop(key, "--uses"), "--uses", "99999999"),
		"a time that is not a time":  append(drop(key, "--from"), "--from", "tomorrow"),
		"a time with a fraction":     append(drop(key, "--from"), "--from", "2026-10-15T12:00:00.5Z"),
		"a date only":                append(drop(key, "--until"), "--until", "2026-10-15"),
		"an unknown option":          append(slices.Clone(key), "--for", "15m"),
		"an argument":                append(slices.Clone(key), "web-2"),
		"a value is missing":         append(slices.Clone(key), "--reason"),
		"cancel with other options":  append(slices.Clone(key), "--cancel", "AAAAAAAAAAAAAAAAAAAAAA"),
		"cancel with a bad ID":       {"--cancel", "nope"},
		"cancel twice":               {"--cancel", "AAAAAAAAAAAAAAAAAAAAAA", "--cancel", "AAAAAAAAAAAAAAAAAAAAAA"},
		"help with other arguments":  {"--help", "--uses", "1"},
	} {
		code, stdout, stderr := preIn(t.Context(), testGranter(nil, nil), args...)
		if code != exitUsage || stdout != "" || !strings.HasPrefix(stderr, "nodkey preapprove: ") ||
			!strings.HasSuffix(stderr, `see "nodkey preapprove --help" (exit 64)`+"\n") || strings.Count(stderr, "\n") != 1 {
			t.Errorf("%s: exit code %d, stdout %q, stderr %.200q; want 64 and one line", name, code, stdout, stderr)
		}
	}
	for _, help := range []string{"-h", "--help", "-help"} {
		code, stdout, stderr := preIn(t.Context(), testGranter(nil, nil), help)
		if code != exitOK || stdout != "" || stderr != preapproveUsage {
			t.Errorf("%s: exit code %d, stdout %q; want 0 and the usage", help, code, stdout)
		}
	}
	// The forms that are valid.
	for name, args := range map[string][]string{
		"a key":                 key,
		"secrets":               append(slices.Clone(secret), "--secret", "npm-token", "--reason", "r"),
		"options with one dash": {"-secret=a", "-from=2026-10-15T12:00Z", "-until", "2026-10-15T13:00:00-02:00", "-uses=1"},
		"the largest number":    {"--secret", "a", "--from", "2026-10-15T12:00", "--until", "2026-10-15T13:00", "--uses", "1048576"},
		"the most secrets":      append(secrets[:6:6], flatSecrets(api.MaxSecrets)...),
		"cancel":                {"--cancel", "AAAAAAAAAAAAAAAAAAAAAA"},
		"cancel with an equals": {"--cancel=AAAAAAAAAAAAAAAAAAAAAA"},
		"the most hosts":        append(slices.Clone(many[:10]), flatHosts(api.MaxGrantHosts)...),
		"a reason with a dash":  append(slices.Clone(key), "--reason", "--not-an-option"),
		"an empty reason":       append(slices.Clone(key), "--reason", ""),
	} {
		if _, err := parsePreapproveArgs(args); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func flatSecrets(n int) []string {
	var out []string
	for i := range n {
		out = append(out, "--secret", fmt.Sprintf("s%d", i))
	}
	return out
}

func flatHosts(n int) []string {
	var out []string
	for i := range n {
		out = append(out, "--host", "h"+string(rune('a'+i)))
	}
	return out
}

// TestPreapproveRequest: the body for secrets and for a key has the fields
// of the protocol and nothing the person did not type; a long reason is
// hidden as for nodkey run; the cancel body holds only the ID.
func TestPreapproveRequest(t *testing.T) {
	o, err := parsePreapproveArgs([]string{"--secret", "github-token", "--secret", "npm-token", "--from",
		"2026-10-15T03:00", "--until", "2026-10-15T04:00+02:00", "--uses", "3"})
	if err != nil {
		t.Fatal(err)
	}
	path, body, err := newPreapprove(o, "job nightly-backup")
	if err != nil || path != api.PathPreapprove {
		t.Fatalf("%q, %v", path, err)
	}
	var got api.PreapproveRequest
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	want := api.PreapproveRequest{Secrets: []string{"github-token", "npm-token"}, Hosts: []string{},
		From: "2026-10-15T03:00", Until: "2026-10-15T04:00+02:00", Uses: 3, Reason: "job nightly-backup"}
	if !slices.Equal(got.Secrets, want.Secrets) || got.From != want.From || got.Until != want.Until || got.Uses != 3 ||
		got.Reason != want.Reason || got.Key != "" || got.User != "" || len(got.Hosts) != 0 {
		t.Errorf("secrets body %+v, want %+v", got, want)
	}
	_, body, err = newPreapprove(o, strings.Repeat("x", api.MaxText+1))
	if err != nil || !bytes.Contains(body, []byte("[hidden: too long]")) {
		t.Errorf("a long reason: %v, %.100s", err, body)
	}
	o, err = parsePreapproveArgs([]string{"--cancel", "AAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	path, body, err = newPreapprove(o, "ignored")
	if err != nil || path != api.PathPreapproveCancel || string(body) != `{"id":"AAAAAAAAAAAAAAAAAAAAAA"}` {
		t.Errorf("cancel body: %q, %s, %v", path, body, err)
	}
}

// TestPreapproveCancelLeftover: a signal that comes with the answer of the
// broker must not lose the grant. The client cancels it with a new
// deadline, although its context has ended; if that fails, it names the
// grant and the command that cancels it.
func TestPreapproveCancelLeftover(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveOnce)
	laptop := gb.client(t, "laptop")
	_, stdout, _ := preIn(t.Context(), testGranter(laptop, nil), preArgs()...)
	id := strings.TrimSuffix(stdout, "\n")
	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(interrupted{sig: syscall.SIGINT})
	var stderr bytes.Buffer
	cancelLeftover(ctx, laptop, id, &stderr)
	if stderr.Len() != 0 {
		t.Errorf("a cancel that worked wrote %q", stderr.String())
	}
	if got := gb.lastEvents(); got != "request decision:approve_once grant_ended:cancelled" {
		t.Errorf("audit entries: %s", got)
	}
	// The grant is gone: a second cancel finds nothing, and says how to cancel.
	cancelLeftover(ctx, laptop, id, &stderr)
	if want := "nodkey: grant " + id + " may be active; cancel it with: nodkey preapprove --cancel " + id + "\n"; stderr.String() != want {
		t.Errorf("a cancel that failed wrote %q, want %q", stderr.String(), want)
	}
}

// signalAfterAnswer wraps the transport of b: when the answer of
// /v1/preapprove has come, it cancels ctx with SIGINT, as a signal would.
// With a nil cancel, no signal comes. With lose, the answer is lost too: the round trip fails.
func signalAfterAnswer(b *Broker, cancel context.CancelCauseFunc, lose bool) {
	inner := b.client.Transport
	c := *b.client
	c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := inner.RoundTrip(r)
		if err != nil || r.URL.Path != api.PathPreapprove {
			return resp, err
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if cancel != nil {
			cancel(interrupted{sig: syscall.SIGINT})
		}
		if lose || err != nil {
			return nil, errors.New("made-up: the answer is lost")
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp, nil
	})
	b.client = &c
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestPreapproveSignalWithAnswer: SIGINT comes as the whole answer is read.
// runPreapprove cancels the new grant at the broker and says cancelled.
func TestPreapproveSignalWithAnswer(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveOnce)
	laptop := gb.client(t, "laptop")
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	signalAfterAnswer(laptop, cancel, false)
	code, stdout, stderr := preIn(ctx, testGranter(laptop, nil), preArgs()...)
	if code != 130 || stdout != "" || lastLine(stderr) != "nodkey: cancelled by SIGINT (exit 130)" ||
		strings.Contains(stderr, "may be active") {
		t.Errorf("exit code %d, stdout %q, stderr %q; want 130", code, stdout, stderr)
	}
	if got := gb.lastEvents(); got != "request decision:approve_once grant_ended:cancelled" {
		t.Errorf("audit entries: %s", got)
	}
}

// TestPreapproveSignalLosesAnswer: SIGINT comes and the answer is lost
// after the person tapped. The client cannot cancel, because it has no ID.
// It says that a grant may have started, with the request code, and the
// exit code is the one of a signal.
func TestPreapproveSignalLosesAnswer(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveOnce)
	laptop := gb.client(t, "laptop")
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	signalAfterAnswer(laptop, cancel, true)
	code, stdout, stderr := preIn(ctx, testGranter(laptop, nil), preArgs()...)
	prompt := gb.approver.Asked()[0].Prompt
	want := "nodkey: a grant may have started; its ID is in the audit log, in the grant_id of the entries of the request whose message shows " + prompt.ShortCode +
		"; cancel it with: nodkey preapprove --cancel ID\n" +
		"nodkey: cancelled by SIGINT (exit 130)\n"
	if code != 130 || stdout != "" || !strings.HasSuffix(stderr, want) {
		t.Errorf("exit code %d, stdout %q, stderr %q; want 130 and the end %q", code, stdout, stderr, want)
	}
}

// TestPreapproveConnectionBreaks: the connection breaks after the person
// tapped, and no signal comes. The grant may have started, so the client
// says so. The exit code is 69, as before.
func TestPreapproveConnectionBreaks(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveOnce)
	laptop := gb.client(t, "laptop")
	signalAfterAnswer(laptop, nil, true)
	code, stdout, stderr := preIn(t.Context(), testGranter(laptop, nil), preArgs()...)
	if !strings.Contains(stderr, "nodkey: a grant may have started; its ID is in the audit log") ||
		code != exitUnavailable || stdout != "" || !strings.HasSuffix(stderr, "(exit 69)\n") {
		t.Errorf("exit code %d, stdout %q, stderr %q; want 69 and the warning", code, stdout, stderr)
	}
}

// TestPreapproveBadAnswer: a 200 whose body cannot be read, or that holds a
// bad ID or a bad time, loses the grant ID. The client says that a grant may
// have started, and exits with 69.
func TestPreapproveBadAnswer(t *testing.T) {
	t.Parallel()
	for name, rewrite := range map[string]func([]byte) []byte{
		"broken body": func([]byte) []byte { return []byte("{not json") },
		"bad ID":      func(b []byte) []byte { return bytes.Replace(b, []byte(`"id":"`), []byte(`"id":"!`), 1) },
		"bad time":    func(b []byte) []byte { return bytes.Replace(b, []byte(`"from":"`), []byte(`"from":"x`), 1) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gb := newGrantBroker(t)
			gb.approver.Auto(audit.AnswerApproveOnce)
			laptop := gb.client(t, "laptop")
			inner := laptop.client.Transport
			c := *laptop.client
			c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				resp, err := inner.RoundTrip(r)
				if err != nil || r.URL.Path != api.PathPreapprove {
					return resp, err
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					return nil, err
				}
				out := rewrite(body)
				resp.Body = io.NopCloser(bytes.NewReader(out))
				resp.ContentLength = int64(len(out))
				return resp, nil
			})
			laptop.client = &c
			code, stdout, stderr := preIn(t.Context(), testGranter(laptop, nil), preArgs()...)
			if code != exitUnavailable || stdout != "" || !strings.Contains(stderr, "nodkey: a grant may have started;") ||
				!strings.HasSuffix(stderr, "(exit 69)\n") {
				t.Errorf("exit code %d, stdout %q, stderr %q; want 69 and the warning", code, stdout, stderr)
			}
			// The value from the bad answer is never shown.
			if strings.Contains(stderr, "!") || strings.Contains(stderr, "x20") {
				t.Errorf("stderr %q shows a value from the bad answer", stderr)
			}
		})
	}
}

// TestPreapproveSignalWithBadAnswer: SIGINT comes with a 200 that holds a
// bad ID. The signal wins, as in nodkey ssh-grant: the client says that a
// grant may have started, and then cancelled.
func TestPreapproveSignalWithBadAnswer(t *testing.T) {
	t.Parallel()
	gb := newGrantBroker(t)
	gb.approver.Auto(audit.AnswerApproveOnce)
	laptop := gb.client(t, "laptop")
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	inner := laptop.client.Transport
	c := *laptop.client
	c.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := inner.RoundTrip(r)
		if err != nil || r.URL.Path != api.PathPreapprove {
			return resp, err
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		cancel(interrupted{sig: syscall.SIGINT})
		out := bytes.Replace(body, []byte(`"id":"`), []byte(`"id":"!`), 1)
		resp.Body = io.NopCloser(bytes.NewReader(out))
		resp.ContentLength = int64(len(out))
		return resp, nil
	})
	laptop.client = &c
	code, stdout, stderr := preIn(ctx, testGranter(laptop, nil), preArgs()...)
	if code != 130 || stdout != "" || !strings.Contains(stderr, "nodkey: a grant may have started;") ||
		lastLine(stderr) != "nodkey: cancelled by SIGINT (exit 130)" || strings.Contains(stderr, "!") {
		t.Errorf("exit code %d, stdout %q, stderr %q; want 130 and the warning", code, stdout, stderr)
	}
	// No cancel went out for the bad ID.
	if got := gb.lastEvents(); got != "request decision:approve_once" {
		t.Errorf("audit entries: %s", got)
	}
}
