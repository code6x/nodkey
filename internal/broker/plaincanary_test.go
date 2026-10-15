package broker

// Regression test from the security review of issue #11 (part A): the
// canary of TestCanaryNeverLeaks is a long random word, which claim.Mask
// hides in any form. This one is a plain word, so only the rules for -p,
// --token=, password= and Authorization: can hide it, in every claimed
// field.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/api"
	"github.com/code6x/nodkey/internal/audit"
)

func TestPlainCanary(t *testing.T) {
	e := newEnv(t, envOptions{})
	x := "Plain-Canary-Word" // not random-looking: only the form rules mask it
	forms := []string{"-p" + x, "--token=" + x, "password=" + x, "Authorization: Bearer " + x}
	reason := strings.Join(forms, " ")
	laptop := e.httpClient("laptop")
	e.approver.Auto(audit.AnswerApproveOnce)
	req := api.SecretsRequest{
		Secrets: []api.SecretRef{{Var: "GH_TOKEN", Name: "github-token"}},
		Command: append([]string{"mysql"}, forms...),
		Dir:     "/srv/password=" + x,
		Reason:  reason,
	}
	secretsOf(t, e.post(t.Context(), laptop, api.PathSecrets, req))
	req.Secrets = []api.SecretRef{{Var: "A", Name: "nope"}}
	mustStatus(t, e.post(t.Context(), laptop, api.PathSecrets, req), http.StatusForbidden)
	sign := e.signRequest(t, "deploy", "web-1", "deploy")
	sign.Commands = [][]string{{"ssh", "-p" + x, "deploy@web-1"}, {"bash", "-c", "deploy --token " + x}, append([]string{"make"}, forms...)}
	sign.Reason = reason
	mustStatus(t, e.post(t.Context(), laptop, api.PathSign, sign), http.StatusOK)
	grant := api.GrantRequest{Key: "deploy", User: "deploy", Hosts: []string{"web-1"}, Seconds: 600, Reason: reason}
	e.approver.Auto(audit.AnswerDeny)
	mustStatus(t, e.post(t.Context(), laptop, api.PathSSHGrant, grant), http.StatusForbidden)
	for where, text := range map[string]string{
		"the messages": e.approverTexts(), "the audit log": encodeEvents(t, e.audit.all()), "the log": e.logs.String(),
	} {
		if strings.Contains(text, x) {
			i := strings.Index(text, x)
			t.Errorf("%s holds the plain canary: …%s…", where, text[max(0, i-60):min(len(text), i+30)])
		}
	}
}
