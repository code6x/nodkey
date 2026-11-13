package totp

import (
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func b32(s string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(s))
}

// The test vectors of RFC 6238, appendix B.
func TestRFC6238Vectors(t *testing.T) {
	seeds := map[Algorithm]string{
		SHA1:   "12345678901234567890",
		SHA256: "12345678901234567890123456789012",
		SHA512: "1234567890123456789012345678901234567890123456789012345678901234",
	}
	cases := []struct {
		unix int64
		alg  Algorithm
		code string
	}{
		{59, SHA1, "94287082"}, {59, SHA256, "46119246"}, {59, SHA512, "90693936"},
		{1111111109, SHA1, "07081804"}, {1111111109, SHA256, "68084774"}, {1111111109, SHA512, "25091201"},
		{1111111111, SHA1, "14050471"}, {1111111111, SHA256, "67062674"}, {1111111111, SHA512, "99943326"},
		{1234567890, SHA1, "89005924"}, {1234567890, SHA256, "91819424"}, {1234567890, SHA512, "93441116"},
		{2000000000, SHA1, "69279037"}, {2000000000, SHA256, "90698825"}, {2000000000, SHA512, "38618901"},
		{20000000000, SHA1, "65353130"}, {20000000000, SHA256, "77737706"}, {20000000000, SHA512, "47863826"},
	}
	for _, c := range cases {
		uri := fmt.Sprintf("otpauth://totp/Example:alice@example.com?secret=%s&algorithm=%s&digits=8&period=30&issuer=Example", b32(seeds[c.alg]), c.alg)
		k, err := Parse([]byte(uri))
		if err != nil {
			t.Fatalf("%s: Parse: %v", c.alg, err)
		}
		got, err := k.Code(time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("Code: %v", err)
		}
		if got != c.code {
			t.Errorf("%d %s: got %s, want %s", c.unix, c.alg, got, c.code)
		}
	}
}

func TestPlainBase32(t *testing.T) {
	plain := strings.ToLower(b32("12345678901234567890"))
	// Spaces and groups, as sites show them.
	spaced := plain[:4] + " " + plain[4:8] + "-" + plain[8:]
	for _, in := range []string{plain, spaced, "  " + strings.ToUpper(plain) + "  "} {
		k, err := Parse([]byte(in))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if k.Digits() != 6 || k.Period() != 30*time.Second || k.Algorithm() != SHA1 {
			t.Fatalf("defaults: %d %v %s", k.Digits(), k.Period(), k.Algorithm())
		}
		got, _ := k.Code(time.Unix(59, 0))
		if got != "287082" {
			t.Errorf("got %s, want 287082", got)
		}
	}
}

func TestOtherDigitsAndPeriod(t *testing.T) {
	k, err := Parse([]byte("otpauth://totp/x?secret=" + b32("12345678901234567890") + "&digits=7&period=60"))
	if err != nil {
		t.Fatal(err)
	}
	if k.Digits() != 7 || k.Period() != time.Minute {
		t.Fatalf("got %d %v", k.Digits(), k.Period())
	}
	a, _ := k.Code(time.Unix(60, 0))
	b, _ := k.Code(time.Unix(119, 0))
	c, _ := k.Code(time.Unix(120, 0))
	if len(a) != 7 || a != b || a == c {
		t.Fatalf("codes %s %s %s", a, b, c)
	}
	if k.Step(time.Unix(119, 0)) != 1 || k.Step(time.Unix(120, 0)) != 2 {
		t.Fatal("step")
	}
}

func TestRefused(t *testing.T) {
	sec := b32("12345678901234567890")
	cases := []struct {
		in   string
		want error
	}{
		{"", ErrEmpty},
		{"   ", ErrEmpty},
		{"steam://" + sec, ErrForm},
		{"otpauth://hotp/x?secret=" + sec + "&counter=1", ErrForm},
		{"https://example.com/?secret=" + sec, ErrForm},
		{"otpauth://totp/x?secret=" + sec + "&algorithm=MD5", ErrAlgorithm},
		{"otpauth://totp/x?secret=" + sec + "&digits=5", ErrDigits},
		{"otpauth://totp/x?secret=" + sec + "&digits=9", ErrDigits},
		{"otpauth://totp/x?secret=" + sec + "&digits=six", ErrDigits},
		{"otpauth://totp/x?secret=" + sec + "&period=0", ErrPeriod},
		{"otpauth://totp/x?secret=" + sec + "&period=3601", ErrPeriod},
		{"otpauth://totp/x?secret=" + sec + "&period=-30", ErrPeriod},
		{"otpauth://totp/x?secret=" + sec + "&secret=" + sec, ErrForm},
		{"otpauth://totp/x?digits=6", ErrEmpty},
		{"otpauth://totp/x?secret=", ErrEmpty},
		{"otpauth://totp/x?secret=abc1", ErrBase32},
		{"otpauth://totp/x?secret=GEZD%47NBV", ErrBase32},
		{"otpauth://totp/x?secret=GEZD+GNBV", ErrBase32},
		{"otpauth://totp", ErrForm},
		{"otpauth://totp/x?" + sec, ErrForm},
		{"otpauth://totp/x?secret=" + sec + "&SECRET=" + sec, ErrForm},
		{"otpauth://totp/x", ErrEmpty},
		{"otpauth://totpx/x?secret=" + sec, ErrForm},
		{"not base32!", ErrBase32},
		{"A", ErrBase32},
		{strings.Repeat("A", maxField+1), ErrForm},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.in))
		if !errors.Is(err, c.want) {
			t.Errorf("Parse(%.30q): got %v, want %v", c.in, err, c.want)
		}
	}
}

func TestErrorsHoldNoSeed(t *testing.T) {
	seed := "JBSWY3DPEHPK3PXP"
	for _, in := range []string{
		"steam://" + seed,
		"otpauth://totp/x?secret=" + seed + "&algorithm=MD5",
		"otpauth://totp/x?secret=" + seed + "!",
		seed + "1",
	} {
		_, err := Parse([]byte(in))
		if err == nil {
			t.Fatalf("no error for %q", in)
		}
		if strings.Contains(err.Error(), seed) {
			t.Fatal("an error holds the seed")
		}
	}
}

func TestKeyHidesSeed(t *testing.T) {
	seed := "12345678901234567890"
	k, err := Parse([]byte(b32(seed)))
	if err != nil {
		t.Fatal(err)
	}
	enc := b32(seed)
	for _, s := range []string{
		fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s %q %x", k, k, k, k, k, k),
		fmt.Sprint(&k), fmt.Sprintf("%+v", struct{ K Key }{k}),
	} {
		if strings.Contains(s, seed) || strings.Contains(s, enc) || strings.Contains(s, "3132") {
			t.Fatalf("format shows the seed: %s", s)
		}
	}
	if _, err := json.Marshal(k); err == nil {
		t.Fatal("JSON encoded the key")
	}
	var b strings.Builder
	slog.New(slog.NewTextHandler(&b, nil)).Info("x", "key", k)
	if strings.Contains(b.String(), enc) || strings.Contains(b.String(), seed) {
		t.Fatal("log shows the seed")
	}
}

func TestClear(t *testing.T) {
	k, _ := Parse([]byte(b32("12345678901234567890")))
	seed := k.seed
	k.Clear()
	for _, c := range seed {
		if c != 0 {
			t.Fatal("seed not cleared")
		}
	}
	if _, err := k.Code(time.Unix(59, 0)); !errors.Is(err, ErrCleared) {
		t.Fatalf("Code after Clear: %v", err)
	}
	var zero Key
	if _, err := zero.Code(time.Unix(59, 0)); !errors.Is(err, ErrCleared) {
		t.Fatalf("Code of zero key: %v", err)
	}
}

func TestInputNotKept(t *testing.T) {
	in := []byte("otpauth://totp/x?secret=" + b32("12345678901234567890"))
	k, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	clear(in)
	if got, _ := k.Code(time.Unix(59, 0)); got != "287082" {
		t.Fatalf("the key uses the caller's buffer: %s", got)
	}
}

func TestBeforeEpoch(t *testing.T) {
	k, _ := Parse([]byte(b32("12345678901234567890")))
	if _, err := k.Code(time.Unix(-1, 0)); err == nil {
		t.Fatal("no error before 1970")
	}
}

func FuzzParse(f *testing.F) {
	f.Add("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8")
	f.Add("JBSWY3DPEHPK3PXP")
	f.Add("steam://JBSWY3DPEHPK3PXP")
	f.Fuzz(func(t *testing.T, in string) {
		k, err := Parse([]byte(in))
		if err != nil {
			return
		}
		code, err := k.Code(time.Unix(1234567890, 0))
		if err != nil || len(code) != k.Digits() {
			t.Fatalf("parsed key makes no code: %v", err)
		}
	})
}
