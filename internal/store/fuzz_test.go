package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// The fuzz tests compare nodkey's JSON reader with encoding/json. nodkey's
// reader is stricter, so the check goes one way: an answer that nodkey
// takes must be valid for encoding/json too, and both must read the same
// value from it.

// fuzzSeeds are answers for every fuzz test.
var fuzzSeeds = []string{
	`{}`, `{"value":"x"}`, `{"value":null}`, `{"value":""}`, `{"value":"a","value":"b"}`,
	`{"id":"` + testItemID + `","value":"x"}`, `{"value":"x","id":"` + strings.ToUpper(testItemID) + `"}`,
	`{"id":"` + testItemID + `","login":{"password":"p"},"deletedDate":null,"archivedDate":null}`,
	`{"id":"` + testItemID + `","login":{"password":"p` + esc("0000") + `"}}`,
	`{"id":"` + testItemID + `","archivedDate":"2026-10-14","login":{"password":"p"}}`,
	`{"login":{"password":"p"},"deletedDate":null}`, `{"login":null}`, `{"deletedDate":"2026-10-14"}`,
	`{"status":"locked"}`, `{"status":"unlocked","userEmail":"nodkey@example.com"}`,
	`{"value":"` + esc("d83d", "de00") + `"}`, `{"value":"` + esc("d800") + `"}`, "{\"value\":\"\xff\"}",
	`{"a":[1,-0.5e+3,true,false,null,{"b":[]}],"value":"x"}`, ` {"value":"x"} `, `{"value":"x"}{}`,
	`{"` + esc("0076") + `alue":"x"}`, `{"Value":"x"}`,
}

func FuzzBWSSecret(f *testing.F) {
	for _, s := range append(fuzzSeeds, realBWSAnswer, bwsSecretJSON(testItemID, "made-up")) {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := parseBWSSecret(data, testItemID)
		if err != nil {
			if v.Bytes() != nil {
				t.Fatal("a value with an error")
			}
			return
		}
		top := fuzzTop(t, data)
		var s string
		if err := json.Unmarshal(top["value"], &s); err != nil || s != string(v.Bytes()) || s == "" || strings.ContainsRune(s, 0) {
			t.Fatalf("encoding/json reads another value: %d bytes, %v; nodkey: %d bytes", len(s), err, len(v.Bytes()))
		}
	})
}

func FuzzBWItem(f *testing.F) {
	for _, s := range append(fuzzSeeds, realBWItem, bwItemJSON(testItemID, "made-up", nil, "other")) {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := parseBWItem(data, testItemID)
		if err != nil {
			if v.Bytes() != nil {
				t.Fatal("a value with an error")
			}
			return
		}
		top := fuzzTop(t, data)
		for _, date := range []string{"deletedDate", "archivedDate"} {
			if d, ok := top[date]; ok && string(d) != "null" {
				t.Fatalf("nodkey took an item with %s %s", date, d)
			}
		}
		var login map[string]json.RawMessage
		if err := json.Unmarshal(top["login"], &login); err != nil {
			t.Fatalf("encoding/json reads no login: %v", err)
		}
		var s string
		if err := json.Unmarshal(login["password"], &s); err != nil || s != string(v.Bytes()) || s == "" || strings.ContainsRune(s, 0) {
			t.Fatalf("encoding/json reads another password: %d bytes, %v; nodkey: %d bytes", len(s), err, len(v.Bytes()))
		}
	})
}

// fuzzTop reads an answer that nodkey took with encoding/json, and checks
// what both readers must agree on: the answer is valid, its "id" is the
// asked ID, and the value has no NUL byte.
func fuzzTop(t *testing.T, data []byte) map[string]json.RawMessage {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		t.Fatalf("nodkey took an answer that encoding/json refuses: %v", err)
	}
	var id string
	if err := json.Unmarshal(top["id"], &id); err != nil || !strings.EqualFold(id, testItemID) || len(id) != len(testItemID) {
		t.Fatalf("nodkey took an answer for another item: %q, %v", id, err)
	}
	return top
}

func FuzzBWStatus(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		status, err := parseBWStatus(data)
		if err != nil {
			return
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(data, &top); err != nil {
			t.Fatalf("nodkey took an answer that encoding/json refuses: %v", err)
		}
		var s string
		if err := json.Unmarshal(top["status"], &s); err != nil || s != status {
			t.Fatalf("encoding/json reads another status: %q, %v; nodkey: %q", s, err, status)
		}
	})
}
