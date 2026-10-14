package store

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"testing"
)

// TestValueHidesItself prints, logs and encodes a Value in every way we
// know, also inside other values, and checks that the secret never shows.
func TestValueHidesItself(t *testing.T) {
	t.Parallel()
	secret := madeUp("value")
	v := newValue([]byte(secret))
	hexSecret := fmt.Sprintf("%x", secret)

	type exported struct{ V Value }
	type unexported struct{ v Value }
	type pointer struct{ v *Value }
	var texts []string
	for _, x := range []any{
		v, &v, exported{v}, &exported{v}, unexported{v}, &unexported{v}, pointer{&v},
		[]Value{v}, map[string]Value{"k": v}, []any{v}, v.p, *v.p,
	} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
			texts = append(texts, fmt.Sprintf(verb, x))
		}
		texts = append(texts, fmt.Sprint(x), fmt.Sprintln(x))
	}
	texts = append(texts, v.String(), v.GoString())

	var logs bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&logs, nil), slog.NewJSONHandler(&logs, nil)} {
		l := slog.New(h)
		l.Info("fetched", "value", v, "pointer", &v, "struct", exported{v}, "inner", unexported{v})
		l.Info("fetched", slog.Any("value", v), slog.Group("g", "value", v))
	}
	texts = append(texts, logs.String())

	for _, x := range []any{v, exported{v}, map[string]Value{"k": v}} {
		out, err := json.Marshal(x)
		if err == nil {
			t.Errorf("json.Marshal(%T) worked", x)
		} else {
			texts = append(texts, err.Error())
		}
		texts = append(texts, string(out))
		out, err = xml.Marshal(x)
		if err != nil {
			texts = append(texts, err.Error())
		}
		texts = append(texts, string(out))
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		texts = append(texts, err.Error())
	}
	texts = append(texts, buf.String())

	for i, text := range texts {
		noCanary(t, fmt.Sprintf("text %d", i), text, secret)
		noCanary(t, fmt.Sprintf("text %d", i), text, hexSecret)
	}
	if got := fmt.Sprintf("%v|%s|%+v", v, v, exported{v}); got != "[hidden]|[hidden]|{V:[hidden]}" {
		t.Errorf("fmt = %q", got)
	}
}

func TestValueClear(t *testing.T) {
	t.Parallel()
	b := []byte(madeUp("value"))
	v := newValue(b)
	c := v // a copy shares the bytes
	c.Clear()
	if v.Bytes() != nil || c.Bytes() != nil {
		t.Error("Clear left the value in a copy")
	}
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Error("Clear did not overwrite the bytes")
	}
	v.Clear() // again: nothing happens
	var zero Value
	zero.Clear()
	if zero.Bytes() != nil {
		t.Error("the zero Value has bytes")
	}
	if got := fmt.Sprint(zero); got != "[hidden]" {
		t.Errorf("fmt of the zero Value = %q", got)
	}
}

// TestStoresHideTheirSecrets prints the stores in every way we know.
func TestStoresHideTheirSecrets(t *testing.T) {
	t.Parallel()
	token, password, session := madeUp("token"), madeUp("password"), madeUp("session")
	bws := newTestFake(t, "bws", fakeScenario{Token: token}, testDeps())
	bw := newTestFake(t, "bw", fakeScenario{Password: password, Session: session}, testDeps())
	if err := bw.store.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	type inner struct{ s Store }
	for _, s := range []Store{bws.store, bw.store} {
		var logs bytes.Buffer
		slog.New(slog.NewTextHandler(&logs, nil)).Info("store", "s", s)
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("store", "s", s)
		for _, text := range []string{
			fmt.Sprintf("%v %+v %#v %s %q %x %d", s, s, s, s, s, s, s),
			fmt.Sprintf("%v %+v %#v", inner{s}, inner{s}, []Store{s}),
			logs.String(),
		} {
			for _, secret := range []string{token, password, session} {
				noCanary(t, "a printed store", text, secret)
				noCanary(t, "a printed store", text, fmt.Sprintf("%x", secret))
			}
		}
	}
	if got := fmt.Sprintf("%v", bw.store); got != `bw store "vault"` {
		t.Errorf("fmt = %q", got)
	}
}
