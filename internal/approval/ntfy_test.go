package approval_test

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/code6x/nodkey/internal/approval"
	"github.com/code6x/nodkey/internal/approval/approvaltest"
	"github.com/code6x/nodkey/internal/audit"
	"github.com/code6x/nodkey/internal/config"
)

// useNtfy makes cfg a config with the ntfy channel and no Telegram.
func useNtfy(cfg *config.Broker) {
	cfg.Telegram = config.Telegram{}
	cfg.Ntfy = &config.Ntfy{
		Server: "https://ntfy.example.com", RequestTopic: "req-topic", AnswerTopic: "ans-topic",
		TokenFile: "/nonexistent/token", Timeout: 2 * time.Minute, SSHTimeout: 90 * time.Second,
	}
}

// TestNtfyAnswerWithoutUserID: with [ntfy], an answer without a user ID
// counts, and the entry names the channel and the answer topic. An answer
// with a user ID is refused.
func TestNtfyAnswerWithoutUserID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newEnv(t, useNtfy)
		defer e.stop()
		ch := e.decide(secretsReq("laptop", "db-password"))
		mustWait(t, ch)
		e.asked(1)
		if err := e.answer(1, func(x *approval.Answer) { x.UserID = approverID }); !errors.Is(err, approval.ErrNotApprover) {
			t.Errorf("an answer with a user ID: %v, want ErrNotApprover", err)
		}
		mustWait(t, ch)
		if err := e.answer(1, func(x *approval.Answer) { x.UserID = 0 }); err != nil {
			t.Fatalf("an answer without a user ID: %v", err)
		}
		r := mustResult(t, ch)
		checkAllowed(t, r)
		var found bool
		for _, ev := range r.Events() {
			if d, ok := ev.(audit.Decision); ok {
				found = true
				if d.UserID != 0 || d.Channel != "ntfy:ans-topic" {
					t.Errorf("decision entry: user %d, channel %q", d.UserID, d.Channel)
				}
			}
		}
		if !found {
			t.Error("no decision entry")
		}
	})
}

// TestNtfyConfigNeedsTimeouts: with [ntfy], New needs the timeouts of the
// ntfy section, and no Telegram user ID.
func TestNtfyConfigNeedsTimeouts(t *testing.T) {
	cfg, _ := testConfig(t)
	useNtfy(cfg)
	if _, err := approval.New(cfg, approvaltest.NewApprover(approverID), approval.Options{Clock: approvaltest.NewClock(noon)}); err != nil {
		t.Fatalf("New with ntfy: %v", err)
	}
	cfg.Ntfy.Timeout = 0
	if _, err := approval.New(cfg, approvaltest.NewApprover(approverID), approval.Options{Clock: approvaltest.NewClock(noon)}); err == nil {
		t.Error("New accepted ntfy without a timeout")
	}
}
