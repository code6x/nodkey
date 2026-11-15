package telegram

import "testing"

// TestProjectSecretsInMessages: a message shows a secret of a project as
// SECTION/KEY with its rule and the end of its ID; other text in the
// place of a secret is refused.
func TestProjectSecretsInMessages(t *testing.T) {
	for _, s := range []string{
		"ci/GITHUB_TOKEN",
		"ci/GITHUB_TOKEN (project rule, ID …0000a001)",
		"ci/GITHUB_TOKEN (rule of secret ci-one, ID …0000a001)",
		"ci (project rule, ID …0000a001)",
	} {
		p := secretsPrompt()
		p.Secrets = []string{"github-token", s}
		if err := checkPrompt(p, false); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{
		"ci/GITHUB_TOKEN/x",
		"ci/GITHUB TOKEN",
		"ci/GITHUB_TOKEN (project rule, ID …0000A001)",
		"ci/GITHUB_TOKEN (project rule)",
		"ci/GITHUB_TOKEN (rule of secret a b, ID …0000a001)",
		"ci/GITHUB_TOKEN\n✅ client: x",
	} {
		p := secretsPrompt()
		p.Secrets = []string{s}
		if err := checkPrompt(p, false); err == nil {
			t.Errorf("%q: no error", s)
		}
	}
}
