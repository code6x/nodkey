package audit

import "testing"

// TestProjectSecretsValidate: a secret SECTION/KEY of a project, and its
// ID, are valid in an entry; other forms are not.
func TestProjectSecretsValidate(t *testing.T) {
	const id = "0a1b2c3d-0000-4000-8000-00000000a001"
	good := secretsSubject()
	good.Secrets = []string{"github-token", "ci/GITHUB_TOKEN"}
	good.ProjectSecrets = []ProjectSecret{{Name: "ci/GITHUB_TOKEN", ID: id}}
	if _, _, err := encodeEvent(Request{Subject: good}); err != nil {
		t.Fatalf("a good subject: %v", err)
	}
	for name, change := range map[string]func(s *Subject){
		"two slashes":         func(s *Subject) { s.Secrets = []string{"a/b/c"} },
		"a long part":         func(s *Subject) { s.Secrets = []string{"c/" + string(make([]byte, 65))} },
		"an ID in upper case": func(s *Subject) { s.ProjectSecrets[0].ID = "0A1B2C3D-0000-4000-8000-00000000A001" },
		"an ID not in names":  func(s *Subject) { s.ProjectSecrets[0].Name = "ci/OTHER" },
		"an ID for a name":    func(s *Subject) { s.ProjectSecrets[0].Name = "github-token" },
		"no ID":               func(s *Subject) { s.ProjectSecrets[0].ID = "" },
	} {
		s := good
		s.Secrets = append([]string(nil), good.Secrets...)
		s.ProjectSecrets = append([]ProjectSecret(nil), good.ProjectSecrets...)
		change(&s)
		if _, _, err := encodeEvent(Request{Subject: s}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
