package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/client"
)

// timingReportVar names the file of the timing report. The Release check
// workflow sets it (docs/releasing.md, check 9); without it the test is
// skipped.
const timingReportVar = "NODKEY_TIMING_REPORT"

// timingBWPause is how long each run of the fake bw takes in the report:
// a slow host.
const timingBWPause = 6 * time.Second

// timingCase is one step of the report.
type timingCase struct {
	Seconds float64 `json:"seconds"`
	Success bool    `json:"success"`
	Error   string  `json:"error,omitempty"`
	BWCalls int     `json:"bw_calls"`
	InLimit bool    `json:"within_resolve_time"`
}

// timingReport is the file of the report.
type timingReport struct {
	BWPauseSeconds     float64 `json:"bw_pause_seconds"`
	ResolveTimeSeconds float64 `json:"plugin_resolve_time_seconds"`
	// NoPreapproval is a login with no pre-approval: the plugin refuses it
	// at once and points to nodkey preapprove (DESIGN.md section 21).
	NoPreapproval timingCase `json:"login_without_preapproval"`
	// Preapproval is nodkey preapprove --login on a cold broker, with an
	// instant tap: the broker runs bw before and after the tap.
	Preapproval timingCase `json:"preapproval_cold"`
	// Login is the login of agent-browser after the pre-approval.
	Login timingCase `json:"login_after_preapproval"`
	Note  string     `json:"note"`
}

// TestLoginTimingReport measures a login of agent-browser (plugin, broker,
// a fake bw that takes timingBWPause per run) on a cold broker: without a
// pre-approval, the pre-approval itself, and the login after it. It
// writes the times and the runs of bw to the file of
// NODKEY_TIMING_REPORT. It fails only when it cannot measure: the times
// on a shared runner are not stable, so a person reads them
// (docs/releasing.md).
func TestLoginTimingReport(t *testing.T) {
	path := os.Getenv(timingReportVar)
	if path == "" {
		t.Skip("set " + timingReportVar + " to the file of the report")
	}
	l := newSlowLogin(t, timingBWPause)
	rep := timingReport{BWPauseSeconds: timingBWPause.Seconds(), ResolveTimeSeconds: client.PluginResolveTime.Seconds(),
		Note: "timing on shared runners is not stable: a person reads it; it never fails the workflow"}
	step := func(r resolveResult, calls int) timingCase {
		return timingCase{Seconds: r.took.Seconds(), Success: r.success && r.rightLogin, Error: r.err,
			BWCalls: calls, InLimit: r.took < client.PluginResolveTime}
	}

	before := bwCalls(t, l.calls)
	r := l.resolve(t)
	rep.NoPreapproval = step(r, bwCalls(t, l.calls)-before)

	before = bwCalls(t, l.calls)
	start := time.Now()
	a := l.e.approve(l.e.httpClient(), api.PathPreapprove, api.PreapproveRequest{Login: slowItem, URL: slowPage, Uses: 1})
	took := time.Since(start)
	rep.Preapproval = timingCase{Seconds: took.Seconds(), Success: a.err == nil && a.status == http.StatusOK,
		BWCalls: bwCalls(t, l.calls) - before, InLimit: took < client.PluginResolveTime}
	if !rep.Preapproval.Success {
		rep.Preapproval.Error = fmt.Sprintf("status %d", a.status)
	}

	before = bwCalls(t, l.calls)
	r = l.resolve(t)
	rep.Login = step(r, bwCalls(t, l.calls)-before)

	if strings.Contains(l.e.stderr.text(), l.pw) || strings.Contains(rep.NoPreapproval.Error+rep.Login.Error, l.pw) {
		t.Fatal("the password is in the journal or in an error; no report is written")
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil { //nolint:gosec // G703: the file that the person who runs the test named.
		t.Fatal(err)
	}
	t.Logf("timing report:\n%s", data)
}
