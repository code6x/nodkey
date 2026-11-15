package ntfy

import "testing"

// TestProjectSecretsInMessages: as in package telegram.
func TestProjectSecretsInMessages(t *testing.T) {
	p := secretsPrompt(t)
	p.Secrets = []string{"ci/GITHUB_TOKEN (project rule, ID …0000a001)", "ci/K (rule of secret ci-one, ID …0000a001)"}
	if err := checkPrompt(p, false); err != nil {
		t.Errorf("project secrets: %v", err)
	}
	for _, s := range []string{"ci/K/x", "ci/K (project rule, ID …0000A001)", "ci/K\nx"} {
		p.Secrets = []string{s}
		if err := checkPrompt(p, false); err == nil {
			t.Errorf("%q: no error", s)
		}
	}
}
