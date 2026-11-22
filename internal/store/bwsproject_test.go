package store

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/config"
)

const (
	testProjectID = "0a1b2c3d-0000-4000-8000-000000000002" // as in bwsSecretJSON
	otherSecretID = "7a1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0c" //nolint:gosec // G101: a made-up secret ID, not a credential.
)

// bwsListedJSON is one secret of a project as bws shows it.
func bwsListedJSON(id, key, project, value string) map[string]any {
	return map[string]any{
		"id": id, "organizationId": "0a1b2c3d-0000-4000-8000-000000000001", "projectId": project,
		"key": key, "value": value, "note": madeUp("note"), "creationDate": "2026-10-14T12:00:00.000000Z",
		"revisionDate": "2026-10-14T12:00:00.000000Z",
	}
}

func jsonText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestBWSListSecrets: "bws secret list PROJECT" runs with the token in the
// environment, and the store returns only the ID, the key and the
// project of each secret. A key that breaks the name rule is not kept:
// only its SHA-256. No value and no note of the answer is in the result.
func TestBWSListSecrets(t *testing.T) {
	t.Parallel()
	token, v1, v2, v3 := madeUp("token"), madeUp("v1"), madeUp("v2"), madeUp("v3")
	list := []any{
		bwsListedJSON(strings.ToUpper(testItemID), "GITHUB_TOKEN", testProjectID, v1),
		bwsListedJSON(otherSecretID, "bad key with spaces", testProjectID, v2),
		bwsListedJSON("8a1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0d", strings.Repeat("k", 65), testProjectID, v3),
	}
	sc := fakeScenario{Token: token, Lists: map[string]string{testProjectID: jsonText(t, list)}}
	f := newTestFake(t, config.StoreBWS, sc, testDeps())
	got, err := f.store.(ProjectStore).ListSecrets(t.Context(), testProjectID)
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	want := []ProjectSecret{{ID: testItemID, Key: "GITHUB_TOKEN", Project: testProjectID},
		{ID: otherSecretID, Project: testProjectID, keySum: sha256.Sum256([]byte("bad key with spaces"))},
		{ID: "8a1e2d3c-4b5a-4987-8a6b-5c4d3e2f1a0d", Project: testProjectID,
			keySum: sha256.Sum256([]byte(strings.Repeat("k", 65)))}}
	if !slices.Equal(got, want) {
		t.Errorf("ListSecrets = %+v, want %+v", got, want)
	}
	calls := f.calls()
	if len(calls) != 1 {
		t.Fatalf("bws ran %d times, want 1", len(calls))
	}
	if want := []string{"secret", "list", testProjectID, "--output", "json", "--color", "no"}; !slices.Equal(calls[0].Args, want) {
		t.Errorf("arguments = %q, want %q", calls[0].Args, want)
	}
	if envValue(calls[0].Env, "BWS_ACCESS_TOKEN") != token {
		t.Error("BWS_ACCESS_TOKEN is not the token")
	}
	// Not a UUID: bws does not run.
	if _, err := f.store.(ProjectStore).ListSecrets(t.Context(), "--help"); !errors.Is(err, ErrBadID) {
		t.Errorf("a project that is not a UUID: %v, want ErrBadID", err)
	}
	if n := len(f.calls()); n != 1 {
		t.Errorf("bws ran for a project that is not a UUID")
	}
}

// TestReadListClears: the answer of "bws secret list" holds every value of
// the project; readList clears all of it, also when the answer is bad.
func TestReadListClears(t *testing.T) {
	t.Parallel()
	value := madeUp("value")
	good := jsonText(t, []any{bwsListedJSON(testItemID, "GITHUB_TOKEN", testProjectID, value)})
	for _, text := range []string{good, good[:len(good)-1], "[" + good + "]"} {
		out := []byte(text)
		list, _ := readList(out, testProjectID)
		for i, c := range out {
			if c != 0 {
				t.Fatalf("readList left byte %d of the answer", i)
			}
		}
		for _, s := range list {
			noCanary(t, "the list", s.ID+s.Key+s.Project, value)
		}
	}
}

// TestParseBWSListBad: an answer that is not an array of secrets of the
// project, with an id, a key and a projectId each, is refused whole.
func TestParseBWSListBad(t *testing.T) {
	t.Parallel()
	one := func(change func(map[string]any)) string {
		s := bwsListedJSON(testItemID, "GITHUB_TOKEN", testProjectID, madeUp("v"))
		change(s)
		return jsonText(t, []any{s})
	}
	for name, text := range map[string]string{
		"an object":         jsonText(t, bwsListedJSON(testItemID, "K", testProjectID, "v")),
		"another project":   one(func(s map[string]any) { s["projectId"] = "0a1b2c3d-0000-4000-8000-000000000009" }),
		"no project":        one(func(s map[string]any) { delete(s, "projectId") }),
		"a null project":    one(func(s map[string]any) { s["projectId"] = nil }),
		"no id":             one(func(s map[string]any) { delete(s, "id") }),
		"an id not a UUID":  one(func(s map[string]any) { s["id"] = "x" }),
		"no key":            one(func(s map[string]any) { delete(s, "key") }),
		"a key not a text":  one(func(s map[string]any) { s["key"] = 7 }),
		"text after":        jsonText(t, []any{}) + "x",
		"two keys in one":   `[{"id":"` + testItemID + `","key":"A","key":"B","projectId":"` + testProjectID + `"}]`,
		"invalid UTF-8 key": "[{\"id\":\"" + testItemID + "\",\"key\":\"\xff\",\"projectId\":\"" + testProjectID + "\"}]",
	} {
		if list, err := parseBWSList([]byte(text), testProjectID); err == nil {
			t.Errorf("%s: no error, list %+v", name, list)
		}
	}
	if list, err := parseBWSList([]byte("[]"), testProjectID); err != nil || len(list) != 0 {
		t.Errorf("an empty project: %v, %v", list, err)
	}
}

// TestBWSFetchListed: the value comes only when the answer of "bws secret
// get" has the key and the project of the list. A rename or a move
// between the two runs is ErrOtherSecret, and no value comes.
func TestBWSFetchListed(t *testing.T) {
	t.Parallel()
	token, value := madeUp("token"), madeUp("value")
	listed := ProjectSecret{ID: testItemID, Key: "GITHUB_TOKEN", Project: testProjectID}
	for _, c := range []struct {
		name         string
		key, project string
		want         error
	}{
		{"the same", "GITHUB_TOKEN", testProjectID, nil},
		{"the project in upper case", "GITHUB_TOKEN", strings.ToUpper(testProjectID), nil},
		{"renamed", "GITHUB_TOKEN_OLD", testProjectID, ErrOtherSecret},
		{"another case", "github_token", testProjectID, ErrOtherSecret},
		{"moved", "GITHUB_TOKEN", "0a1b2c3d-0000-4000-8000-000000000009", ErrOtherSecret},
	} {
		sc := fakeScenario{Token: token, Items: map[string]string{
			testItemID: jsonText(t, bwsListedJSON(testItemID, c.key, c.project, value)),
		}}
		f := newTestFake(t, config.StoreBWS, sc, testDeps())
		v, err := f.store.(ProjectStore).FetchListed(t.Context(), listed)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
		if c.want == nil {
			checkValue(t, v, value)
		} else if v.Bytes() != nil {
			t.Errorf("%s: a value came", c.name)
		}
		if err != nil {
			noCanary(t, c.name, err.Error(), value)
		}
		v.Clear()
	}
	// The answer for another ID is refused.
	sc := fakeScenario{Token: token, Items: map[string]string{
		testItemID: jsonText(t, bwsListedJSON(otherSecretID, "GITHUB_TOKEN", testProjectID, value)),
	}}
	f := newTestFake(t, config.StoreBWS, sc, testDeps())
	if _, err := f.store.(ProjectStore).FetchListed(t.Context(), listed); !errors.Is(err, ErrBadAnswer) {
		t.Errorf("another ID: %v, want ErrBadAnswer", err)
	}
}

// TestBWSFetchListedKeyless: a listed secret whose key breaks the name
// rule gives its value only when the answer of "bws secret get" has the
// same key. Another key, also one that follows the name rule, is
// ErrOtherSecret. A secret with no key and no SHA-256 is refused before
// bws runs.
func TestBWSFetchListedKeyless(t *testing.T) {
	t.Parallel()
	token, value := madeUp("token"), madeUp("value")
	const key = "my-tool token example.org wide access"
	listed := ProjectSecret{ID: testItemID, Project: testProjectID, keySum: sha256.Sum256([]byte(key))}
	for _, c := range []struct {
		name, key string
		want      error
	}{
		{"the same", key, nil},
		{"renamed", key + " 2", ErrOtherSecret},
		{"renamed to a valid key", "GITHUB_TOKEN", ErrOtherSecret},
		{"renamed to the empty key", "", ErrOtherSecret},
	} {
		sc := fakeScenario{Token: token, Items: map[string]string{
			testItemID: jsonText(t, bwsListedJSON(testItemID, c.key, testProjectID, value)),
		}}
		f := newTestFake(t, config.StoreBWS, sc, testDeps())
		v, err := f.store.(ProjectStore).FetchListed(t.Context(), listed)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
		if c.want == nil {
			checkValue(t, v, value)
		} else if v.Bytes() != nil {
			t.Errorf("%s: a value came", c.name)
		}
		if err != nil {
			noCanary(t, c.name, err.Error(), value)
			noCanary(t, c.name, err.Error(), "example.org")
		}
		v.Clear()
	}
	sc := fakeScenario{Token: token, Items: map[string]string{
		testItemID: jsonText(t, bwsListedJSON(testItemID, "", testProjectID, value)),
	}}
	f := newTestFake(t, config.StoreBWS, sc, testDeps())
	for _, ps := range []ProjectSecret{
		{ID: testItemID, Project: testProjectID},                     // no key and no SHA-256
		{ID: testItemID, Key: "bad key", Project: testProjectID},     // a key that breaks the rule
		{ID: testItemID, Key: "GITHUB_TOKEN", Project: "not-a-uuid"}, // a project that is not a UUID
	} {
		if _, err := f.store.(ProjectStore).FetchListed(t.Context(), ps); !errors.Is(err, ErrBadID) {
			t.Errorf("%+v: %v, want ErrBadID", ps, err)
		}
	}
	if n := len(f.calls()); n != 0 {
		t.Errorf("bws ran %d times for a listed secret that is not valid", n)
	}
}
