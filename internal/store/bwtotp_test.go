package store

import (
	"fmt"
	"slices"
	"testing"

	"github.com/code6x/nodkey/internal/config"
)

// TestBWFetchTOTP: FetchTOTP runs the fake bw with "bw sync --force" and
// "bw get item", and returns only the seed of login.totp. A login with no
// password is fine. The seed is hidden in every format.
func TestBWFetchTOTP(t *testing.T) {
	t.Parallel()
	for name, pw := range map[string]string{"with a password": madeUp("password"), "no password": ""} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			seed, other := madeUp("totp"), madeUp("other")
			sc := bwScenario(madeUp("password"), "", madeUp("value"), other)
			sc.Items[testItemID] = loginJSON(testItemID, 1, []string{testCollection}, pw, seed, other, nil)
			f := newTestFake(t, config.StoreBW, sc, testDeps())
			v, err := f.store.(TOTPStore).FetchTOTP(t.Context(), testItemID)
			if err != nil {
				t.Fatalf("FetchTOTP: %v", err)
			}
			checkValue(t, v, seed)
			noCanary(t, "the seed's format", fmt.Sprintf("%v %+v %#v %s %q", v, v, v, v, v), seed)
			if got, want := f.steps(), []string{"unlock", "sync", "get item"}; !slices.Equal(got, want) {
				t.Errorf("steps = %q, want %q", got, want)
			}
			buf := v.Bytes()
			v.Clear()
			for _, c := range buf {
				if c != 0 {
					t.Fatal("Clear left the seed")
				}
			}
		})
	}
}

// TestBWFetchTOTPRefused: no seed, an item in the trash, an archived item,
// an item that is not a login, another item and a bad ID are refused, and
// the error holds no secret of the item.
func TestBWFetchTOTPRefused(t *testing.T) {
	t.Parallel()
	pw, seed, other := madeUp("password"), madeUp("totp"), madeUp("other")
	cols := []string{testCollection}
	tests := map[string]struct {
		item string
		want error
	}{
		"no seed":    {loginJSON(testItemID, 1, cols, pw, "", other, nil), ErrNoTOTP},
		"null seed":  {`{"id":"` + testItemID + `","type":1,"login":{"password":"` + pw + `","totp":null}}`, ErrNoTOTP},
		"trash":      {loginJSON(testItemID, 1, cols, pw, seed, other, map[string]any{"deletedDate": "2026-10-02T00:00:00Z"}), ErrTrashed},
		"archived":   {loginJSON(testItemID, 1, cols, pw, seed, other, map[string]any{"archivedDate": "2026-10-02T00:00:00Z"}), ErrArchived},
		"a note":     {loginJSON(testItemID, 2, cols, pw, seed, other, nil), ErrNotLogin},
		"other item": {loginJSON(testItemID2, 1, cols, pw, seed, other, nil), errOtherItem},
		"a list":     {"[" + loginJSON(testItemID, 1, cols, pw, seed, other, nil) + "]", ErrBadAnswer},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := bwScenario(madeUp("password"), "", madeUp("value"), other)
			sc.Items[testItemID] = tc.item
			f := newTestFake(t, config.StoreBW, sc, testDeps())
			v, err := f.store.(TOTPStore).FetchTOTP(t.Context(), testItemID)
			checkErr(t, err, tc.want)
			if v.Bytes() != nil {
				t.Error("FetchTOTP returned a seed with its error")
			}
			if err != nil {
				for _, s := range []string{pw, seed, other} {
					noCanary(t, "the error", err.Error(), s)
				}
			}
		})
	}
	sc := bwScenario(madeUp("password"), "", madeUp("value"), other)
	f := newTestFake(t, config.StoreBW, sc, testDeps())
	if _, err := f.store.(TOTPStore).FetchTOTP(t.Context(), "not-a-uuid"); err == nil {
		t.Error("a bad ID was accepted")
	}
}

// TestOnlyBWHandsOutTOTP: no other store type is a TOTPStore.
func TestOnlyBWHandsOutTOTP(t *testing.T) {
	t.Parallel()
	for _, s := range []Store{&bwsStore{}, &opStore{}, &infStore{}} {
		if _, ok := s.(TOTPStore); ok {
			t.Errorf("%T is a TOTPStore", s)
		}
	}
}
