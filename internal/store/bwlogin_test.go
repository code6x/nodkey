package store

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/code6x/nodkey/internal/config"
)

const (
	testCollection  = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	otherCollection = "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e"
	testItemID2     = "7a2e3d4c-5b6a-4f98-9b7c-6d5e4f3a2b1c"
)

// loginJSON returns a login item as bw writes it. password, totp and
// other are made-up secrets; other goes in the notes, a custom field and
// the password history.
func loginJSON(id string, typ int, collections []string, password, totp, other string, extra map[string]any) string {
	item := map[string]any{
		"object": "item", "id": id, "organizationId": "2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f",
		"folderId": nil, "type": typ, "reprompt": 0, "name": "Example shop", "notes": other,
		"favorite": false, "collectionIds": collections,
		"fields":          []any{map[string]any{"name": "pin", "value": other, "type": 1}},
		"passwordHistory": []any{map[string]any{"lastUsedDate": "2026-10-01T12:00:00.000Z", "password": other}},
		"login": map[string]any{
			"uris": []any{
				map[string]any{"match": nil, "uri": "https://example.com/login"},
				map[string]any{"match": 1, "uri": "https://shop.example.org"},
			},
			"username": "alice@example.com", "password": password, "totp": totp,
			"passwordRevisionDate": nil, "fido2Credentials": []any{},
		},
		"revisionDate": "2026-10-01T12:00:00.000Z", "creationDate": "2026-10-01T12:00:00.000Z",
		"deletedDate": nil, "archivedDate": nil,
	}
	for k, v := range extra {
		item[k] = v
	}
	b, _ := json.Marshal(item)
	return string(b)
}

func TestBWListLogins(t *testing.T) {
	t.Parallel()
	pw, seed, other := madeUp("password"), madeUp("totp"), madeUp("other")
	cols := []string{testCollection}
	list := "[" + strings.Join([]string{
		loginJSON(testItemID, 1, cols, pw, seed, other, nil),
		loginJSON(testItemID2, 1, []string{testCollection, otherCollection}, pw, seed, other, nil),
		loginJSON("8b3f4e5d-6c7b-4a09-8c8d-7e6f5a4b3c2d", 2, cols, pw, seed, other, nil),                                                    // a note
		loginJSON("9c4a5f6e-7d8c-4b1a-9d9e-8f7a6b5c4d3e", 1, cols, pw, seed, other, map[string]any{"deletedDate": "2026-10-02T00:00:00Z"}),  // trash
		loginJSON("ad5b6a7f-8e9d-4c2b-8eaf-9a8b7c6d5e4f", 1, cols, pw, seed, other, map[string]any{"archivedDate": "2026-10-02T00:00:00Z"}), // archived
		loginJSON("be6c7b8a-9f0e-4d3c-9fba-ab9c8d7e6f5a", 1, []string{otherCollection}, pw, seed, other, nil),                               // not in it
	}, ",") + "]"
	sc := bwScenario(madeUp("password"), "", madeUp("value"), other)
	sc.Lists = map[string]string{testCollection: list}
	f := newTestFake(t, config.StoreBW, sc, testDeps())
	ls := f.store.(LoginStore)
	items, err := ls.ListLogins(t.Context(), testCollection)
	if err != nil {
		t.Fatalf("ListLogins: %v", err)
	}
	if len(items) != 2 || items[0].ID != testItemID || items[1].ID != testItemID2 {
		t.Fatalf("items = %+v", items)
	}
	it := items[0]
	if it.Name != "Example shop" || it.Username != "alice@example.com" || len(it.URIs) != 2 ||
		it.URIs[0].URI != "https://example.com/login" || it.URIs[0].Match != nil ||
		it.URIs[1].Match == nil || *it.URIs[1].Match != 1 {
		t.Fatalf("item = %+v", it)
	}
	if it.Reprompt {
		t.Fatal("reprompt 0 read as true")
	}
	if !slices.Equal(items[1].Collections, []string{testCollection, otherCollection}) {
		t.Fatalf("collections = %q", items[1].Collections)
	}
	dump := fmt.Sprintf("%+v %#v", items, items)
	for _, s := range []string{pw, seed, other} {
		noCanary(t, "the list", dump, s)
	}
	if got, want := f.steps(), []string{"unlock", "sync", "list items"}; !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
	if want := []string{"list", "items", "--collectionid", testCollection, "--nointeraction"}; !slices.Equal(f.calls()[2].Args, want) {
		t.Errorf("arguments = %q, want %q", f.calls()[2].Args, want)
	}
}

func TestBWListLoginsRefused(t *testing.T) {
	t.Parallel()
	pw, other := madeUp("password"), madeUp("other")
	tests := map[string]struct {
		list string
		want error
	}{
		"an object":       {loginJSON(testItemID, 1, []string{testCollection}, pw, "", other, nil), ErrBadAnswer},
		"bad item id":     {`[{"id":"x","type":1,"collectionIds":["` + testCollection + `"]}]`, ErrBadAnswer},
		"cut short":       {`[{"id":"` + testItemID + `"}`, ErrBadAnswer},
		"type text":       {`[{"id":"` + testItemID + `","type":"1"}]`, ErrBadAnswer},
		"type negative":   {`[{"id":"` + testItemID + `","type":-1}]`, ErrBadAnswer},
		"match fraction":  {`[{"id":"` + testItemID + `","type":1,"login":{"uris":[{"uri":"https://example.com","match":0.5}]}}]`, ErrBadAnswer},
		"long name":       {`[{"id":"` + testItemID + `","type":1,"name":"` + strings.Repeat("a", maxLoginName+1) + `"}]`, ErrBadAnswer},
		"password number": {`[{"id":"` + testItemID + `","type":1,"login":{"password":7}}]`, ErrBadAnswer},
		"trailing":        {`[] []`, ErrBadAnswer},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := bwScenario(madeUp("password"), "", madeUp("value"), other)
			sc.Lists = map[string]string{testCollection: tc.list}
			f := newTestFake(t, config.StoreBW, sc, testDeps())
			items, err := f.store.(LoginStore).ListLogins(t.Context(), testCollection)
			checkErr(t, err, tc.want)
			if items != nil {
				t.Error("items with an error")
			}
			if err != nil {
				noCanary(t, "the error", err.Error(), pw)
				noCanary(t, "the error", err.Error(), other)
			}
		})
	}
	f := newTestFake(t, config.StoreBW, bwScenario(madeUp("password"), "", madeUp("value"), other), testDeps())
	_, err := f.store.(LoginStore).ListLogins(t.Context(), "not-a-uuid")
	checkErr(t, err, ErrBadID)
	if len(f.steps()) != 0 {
		t.Error("bw ran for a bad collection ID")
	}
}

func TestBWFetchLogin(t *testing.T) {
	t.Parallel()
	pw, seed, other := madeUp("password"), madeUp("totp"), madeUp("other")
	sc := bwScenario(madeUp("password"), "", madeUp("value"), other)
	sc.Items[testItemID] = loginJSON(strings.ToUpper(testItemID), 1, []string{testCollection}, pw, seed, other,
		map[string]any{"reprompt": 1})
	f := newTestFake(t, config.StoreBW, sc, testDeps())
	l, err := f.store.(LoginStore).FetchLogin(t.Context(), testItemID)
	if err != nil {
		t.Fatalf("FetchLogin: %v", err)
	}
	defer l.Clear()
	checkValue(t, l.Password, pw)
	checkValue(t, l.TOTP, seed)
	if !l.Reprompt {
		t.Error("reprompt 1 read as false")
	}
	if l.Username != "alice@example.com" || len(l.URIs) != 2 || !slices.Equal(l.Collections, []string{testCollection}) {
		t.Fatalf("login = %+v", l.LoginItem)
	}
	for _, s := range []string{fmt.Sprint(l), fmt.Sprintf("%+v %#v %s %q", l, l, l, l)} {
		noCanary(t, "the login's format", s, pw)
		noCanary(t, "the login's format", s, seed)
	}
	if got, want := f.steps(), []string{"unlock", "sync", "get item"}; !slices.Equal(got, want) {
		t.Errorf("steps = %q, want %q", got, want)
	}
	pwBuf := l.Password.Bytes()
	l.Clear()
	for _, c := range pwBuf {
		if c != 0 {
			t.Fatal("Clear left the password")
		}
	}
}

func TestBWFetchLoginRefused(t *testing.T) {
	t.Parallel()
	pw, seed, other := madeUp("password"), madeUp("totp"), madeUp("other")
	cols := []string{testCollection}
	tests := map[string]struct {
		item string
		want error
	}{
		"in the trash": {loginJSON(testItemID, 1, cols, pw, seed, other, map[string]any{"deletedDate": "2026-10-02T00:00:00Z"}), ErrTrashed},
		"archived":     {loginJSON(testItemID, 1, cols, pw, seed, other, map[string]any{"archivedDate": "2026-10-02T00:00:00Z"}), ErrArchived},
		"a note":       {loginJSON(testItemID, 2, cols, pw, seed, other, nil), ErrNotLogin},
		"no type":      {`{"id":"` + testItemID + `","login":{"password":"` + pw + `"}}`, ErrNotLogin},
		"other item":   {loginJSON(testItemID2, 1, cols, pw, seed, other, nil), errOtherItem},
		"no password":  {loginJSON(testItemID, 1, cols, "", seed, other, nil), ErrNoValue},
		"NUL password": {loginJSON(testItemID, 1, cols, "a\x00b", seed, other, nil), ErrBadValue},
		"a list":       {"[" + loginJSON(testItemID, 1, cols, pw, seed, other, nil) + "]", ErrBadAnswer},
		"two totps":    {`{"id":"` + testItemID + `","type":1,"login":{"totp":"a","totp":"b"}}`, ErrBadAnswer},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := bwScenario(madeUp("password"), "", madeUp("value"), other)
			sc.Items[testItemID] = tc.item
			f := newTestFake(t, config.StoreBW, sc, testDeps())
			l, err := f.store.(LoginStore).FetchLogin(t.Context(), testItemID)
			checkErr(t, err, tc.want)
			if l.Password.Bytes() != nil || l.TOTP.Bytes() != nil || l.ID != "" {
				t.Error("FetchLogin returned a login with its error")
			}
			for _, s := range []string{pw, seed, other} {
				if err != nil {
					noCanary(t, "the error", err.Error(), s)
				}
			}
		})
	}
}

func FuzzParseBWLogin(f *testing.F) {
	f.Add(loginJSON(testItemID, 1, []string{testCollection}, "pw", "seed", "other", nil))
	f.Fuzz(func(t *testing.T, data string) {
		l, err := parseBWLogin([]byte(data), testItemID)
		if err == nil {
			l.Clear()
		}
		_, _ = parseBWLoginList([]byte("["+data+"]"), testCollection)
	})
}
