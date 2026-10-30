package client

import (
	"strings"
	"testing"
)

func TestProbe(t *testing.T) {
	tb := newTestBrokerWith(t, "0.3.0")
	keys, warnings, err := tb.client(t).Probe(t.Context(), "0.3.0")
	if err != nil || keys != 0 || len(warnings) != 0 {
		t.Fatalf("Probe = %d, %q, %v; want 0 keys, no warnings, no error", keys, warnings, err)
	}
	if len(tb.approver.Asked()) != 0 {
		t.Error("Probe asked the approver")
	}
}

func TestProbeWarnsAboutVersions(t *testing.T) {
	tb := newTestBrokerWith(t, "0.2.0")
	_, warnings, err := tb.client(t).Probe(t.Context(), "0.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "older than nodkey 0.3.0") {
		t.Errorf("warnings %q, want one about the older broker", warnings)
	}
}

func TestProbeWrongPin(t *testing.T) {
	tb := newTestBroker(t)
	b, err := newBroker(tb.addr, tb.laptop.cert, newTLSKey(t).pin)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Probe(t.Context(), "0.3.0"); err == nil {
		t.Fatal("Probe with a wrong broker_pin passed")
	}
}
