package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// join makes a log from lines: each line and a newline.
func join(lines ...[]byte) []byte {
	var b []byte
	for _, line := range lines {
		b = append(append(b, line...), '\n')
	}
	return b
}

// without returns a copy of lines without line i (from 0).
func without(lines [][]byte, i int) [][]byte {
	return slices.Delete(slices.Clone(lines), i, i+1)
}

// replaced returns a copy of lines with line i (from 0) replaced.
func replaced(lines [][]byte, i int, line []byte) [][]byte {
	c := slices.Clone(lines)
	c[i] = line
	return c
}

// inserted returns a copy of lines with line put in before line i.
func inserted(lines [][]byte, i int, line []byte) [][]byte {
	return slices.Insert(slices.Clone(lines), i, line)
}

// swapped returns a copy of lines with lines i and j swapped.
func swapped(lines [][]byte, i, j int) [][]byte {
	c := slices.Clone(lines)
	c[i], c[j] = c[j], c[i]
	return c
}

// anchorOf returns the anchor of a line with the given seq.
func anchorOf(seq uint64, line []byte) Anchor {
	return Anchor{Seq: seq, Hash: sha256.Sum256(line)}
}

// firstLine is a valid first entry, with the canary in a field of its
// event. Tests change parts of it.
const firstLine = `{"seq":1,"time":"2026-10-14T12:00:00.000Z","event":"broker_started",` +
	`"prev":"0000000000000000000000000000000000000000000000000000000000000000","version":"dev","reason":"` + canary + `"}`

// changed returns firstLine with old replaced by new.
func changed(t *testing.T, old, new string) []byte {
	t.Helper()
	if !strings.Contains(firstLine, old) {
		t.Fatalf("firstLine has no %q", old)
	}
	return []byte(strings.Replace(firstLine, old, new, 1))
}

func TestVerifyAcceptsGoodLogs(t *testing.T) {
	plain := newChain(t).addAll()

	torn := newChain(t)
	torn.add(BrokerStarted{Version: "dev"})
	torn.add(Request{Subject: secretsSubject()})
	torn.tear(half(torn.lines[1]))
	torn.add(Decision{Subject: secretsSubject(), UserID: 1, Answer: AnswerApproveOnce})
	torn.tear([]byte{0, 0, 0}) // a power cut can leave zeros too
	torn.add(BrokerStarted{Version: "dev"})

	// A log that starts with a torn line: the first write was cut.
	tornFirst := newChain(t)
	tornFirst.tear([]byte(`{"seq":1,"time":"2026-10-14T12:00:00.000Z","event":"broker_sta`))
	tornFirst.add(BrokerStarted{Version: "dev"})

	// A torn line can be a whole entry that lost only its newline.
	whole := newChain(t)
	whole.add(BrokerStarted{Version: "dev"})
	next := newChain(t)
	next.lines, next.last = slices.Clone(whole.lines), whole.last
	next.add(Request{Subject: loginSubject()})
	whole.tear(next.lines[1])
	whole.add(Signed{Subject: loginSubject()})

	// A line of exactly MaxLineSize bytes.
	longest := newChain(t)
	longest.add(BrokerStarted{Version: "dev"})
	probe := appendLine(nil, 2, testTime, eventRequest, longest.last.Hash, mustEncode(t, Request{Subject: secretsSubject()}))
	longest.add(Request{Subject: secretsSubject(), Message: strings.Repeat("m", MaxLineSize-len(probe)-len(`,"message":""`))})
	if n := len(longest.lines[1]); n != MaxLineSize {
		t.Fatalf("the long line has %d bytes, want %d", n, MaxLineSize)
	}

	tests := []struct {
		name    string
		c       *chain
		entries uint64
		torn    uint64
	}{
		{"plain", plain, uint64(len(sampleEvents())), 0},
		{"torn lines", torn, 6, 2},
		{"torn first line", tornFirst, 2, 1},
		{"torn line that is a whole entry", whole, 3, 1},
		{"line of MaxLineSize bytes", longest, 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Verify(bytes.NewReader(tt.c.bytes()))
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			want := Result{Entries: tt.entries, TornLines: tt.torn, Last: tt.c.last}
			if res != want {
				t.Errorf("Verify = %+v, want %+v", res, want)
			}
			// Every entry can be an anchor, and all of them together too.
			var anchors []Anchor
			var seq uint64
			for i, line := range tt.c.lines {
				if i+1 < len(tt.c.lines) && isTornBefore(tt.c.lines[i+1], line) {
					continue
				}
				seq++
				anchors = append(anchors, anchorOf(seq, line))
			}
			if _, err := Verify(bytes.NewReader(tt.c.bytes()), anchors...); err != nil {
				t.Errorf("Verify with every anchor: %v", err)
			}
		})
	}
}

// isTornBefore reports whether line is the log_recovered entry of torn.
func isTornBefore(line, torn []byte) bool {
	e, bad := parseEntry(line)
	return bad == "" && e.event == eventLogRecovered && e.tornLength == len(torn) && e.tornHash == sha256.Sum256(torn)
}

func mustEncode(t *testing.T, ev Event) []byte {
	t.Helper()
	_, body, err := encodeEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestVerifyAcceptsUnknownFields: a newer nodkey may add events and
// fields. Verify checks the chain, not each event.
func TestVerifyAcceptsUnknownFields(t *testing.T) {
	line := changed(t, `"event":"broker_started"`, `"event":"some_new_event","extra":{"a":[1,2,null]}`)
	if _, err := Verify(bytes.NewReader(join(line))); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyFindsProblems(t *testing.T) {
	c := newChain(t).addAll()
	lines := c.lines
	if len(lines) != 14 {
		t.Fatalf("the sample log has %d lines; the cases below expect 14", len(lines))
	}
	hashOf := func(i int) [sha256.Size]byte { return sha256.Sum256(lines[i]) }

	// A log with a torn line: lines 1 and 2, the torn line 3, its
	// log_recovered entry on line 4 (seq 3), then line 5 (seq 4).
	tc := newChain(t)
	tc.add(BrokerStarted{Version: "dev"})
	tc.add(Request{Subject: secretsSubject()})
	torn := half(tc.lines[1])
	tc.tear(torn)
	tc.add(Decision{Subject: secretsSubject(), UserID: 1, Answer: AnswerDeny})
	tl := tc.lines
	recovered := tl[3]
	// A second log_recovered entry that names the first one as its torn
	// line, with the seq and prev that the first one has.
	sum := sha256.Sum256(recovered)
	again := appendLine(nil, 3, testTime, eventLogRecovered, sha256.Sum256(tl[1]),
		mustEncode(t, logRecovered{TornLength: len(recovered), TornSHA256: hex.EncodeToString(sum[:])}))
	// A log_recovered entry with the wrong length for the torn line.
	wrongLength := bytes.Replace(recovered, []byte(`"torn_length":`), []byte(`"torn_length":1`), 1)

	tests := []struct {
		name    string
		log     []byte
		anchors []Anchor
		line    uint64 // 0: not about one line
		want    string // the whole problem
	}{
		{name: "changed line", log: join(replaced(lines, 1, bytes.Replace(lines[1], []byte("publish"), []byte("publisH"), 1))...),
			line: 3, want: "has a prev that is not the hash of the entry before it, on line 2"},
		{name: "changed last line, found by the anchor", anchors: []Anchor{c.last},
			log:  join(replaced(lines, 13, bytes.Replace(lines[13], []byte("broker_stopped"), []byte("broker_stoppee"), 1))...),
			line: 14, want: "is entry 14, and its hash is not the hash in the anchor"},
		{name: "removed line", log: join(without(lines, 2)...), line: 3, want: "has seq 4, want 3"},
		{name: "removed first line", log: join(without(lines, 0)...), line: 1, want: "has seq 2, want 1"},
		{name: "removed last line, found by the anchor", log: join(without(lines, 13)...), anchors: []Anchor{c.last},
			want: "no entry 14: the log ends at entry 13"},
		{name: "swapped lines", log: join(swapped(lines, 1, 2)...), line: 2, want: "has seq 3, want 2"},
		{name: "swapped last lines", log: join(swapped(lines, 12, 13)...), line: 13, want: "has seq 14, want 13"},
		{name: "copied line", log: join(inserted(lines, 2, lines[1])...), line: 3, want: "has seq 2, want 3"},
		{name: "wrong anchor", log: join(lines...), anchors: []Anchor{{Seq: 3, Hash: hashOf(3)}},
			line: 3, want: "is entry 3, and its hash is not the hash in the anchor"},
		{name: "anchor for an entry that is not there", log: join(lines...), anchors: []Anchor{{Seq: 99, Hash: hashOf(3)}},
			want: "no entry 99: the log ends at entry 14"},
		{name: "two anchors that disagree", log: join(lines...), anchors: []Anchor{{Seq: 2, Hash: hashOf(1)}, {Seq: 2, Hash: hashOf(2)}},
			want: "two anchors for entry 2 have different hashes: the log was cut or changed, and the entry was written again, " +
				"or the anchors come from two logs"},
		{name: "anchor 0", log: join(lines...), anchors: []Anchor{{}}, want: "an anchor needs an entry number from 1"},
		{name: "bad JSON", log: join(replaced(lines, 1, []byte(`{"seq":2,"reason":"`+canary))...),
			line: 2, want: problemJSON},
		{name: "too long line", log: join(replaced(lines, 1, []byte(`{"reason":"`+strings.Repeat(canary, MaxLineSize/len(canary)+1)+`"}`))...),
			line: 2, want: "is longer than 65536 bytes"},
		{name: "too long line after a bad line", log: join(lines[0], []byte(canary), bytes.Repeat([]byte("x"), MaxLineSize+1)),
			line: 2, want: problemJSON},
		{name: "empty log", log: nil, want: "the log is empty"},
		{name: "empty line", log: join(inserted(lines, 1, nil)...), line: 2, want: problemJSON},
		{name: "no newline at the end", log: bytes.TrimSuffix(join(lines...), []byte("\n")),
			line: 14, want: "has no newline at the end: it is a torn line, and no log_recovered entry follows it"},
		{name: "torn line at the end", log: append(join(lines...), half(lines[1])...),
			line: 15, want: "has no newline at the end: it is a torn line, and no log_recovered entry follows it"},

		// Torn lines.
		{name: "torn line without log_recovered", log: join(inserted(lines, 2, half(lines[2]))...), line: 3, want: problemJSON},
		{name: "torn line removed", log: join(without(tl, 2)...),
			line: 3, want: "is a log_recovered entry, but the line before it is not the torn line that it names"},
		{name: "torn line changed", log: join(replaced(tl, 2, bytes.Replace(torn, []byte("2026"), []byte("2027"), 1))...),
			line: 3, want: problemJSON},
		{name: "log_recovered removed", log: join(without(tl, 3)...), line: 3, want: problemJSON},
		{name: "log_recovered with the wrong length", log: join(replaced(tl, 3, wrongLength)...), line: 3, want: problemJSON},
		{name: "two torn lines before one log_recovered", log: join(inserted(tl, 2, half(tl[1]))...), line: 3, want: problemJSON},
		{name: "log_recovered used as a torn line", log: join(append(slices.Clone(tl[:4]), again)...),
			line: 5, want: "is a log_recovered entry, but the line before it is not the torn line that it names"},
		{name: "log_recovered first", log: join(tl[3:]...),
			line: 1, want: "is a log_recovered entry, but the line before it is not the torn line that it names"},

		// The form of a line.
		{name: "not an object", log: join([]byte(`["` + canary + `"]`)), line: 1, want: problemNotObject},
		{name: "a string", log: join([]byte(`"` + canary + `"`)), line: 1, want: problemNotObject},
		{name: "null", log: join([]byte(`null`)), line: 1, want: problemNotObject},
		{name: "more after the object", log: join([]byte(firstLine + ` "` + canary + `"`)), line: 1, want: problemJSON},
		{name: "two objects", log: join([]byte(firstLine + firstLine)), line: 1, want: problemJSON},
		{name: "seq twice", log: join(changed(t, `{"seq":1,`, `{"seq":1,"seq":1,`)), line: 1, want: problemTwice + "seq"},
		{name: "prev twice", log: join(changed(t, `"version"`, `"prev":"`+zeros+`","version"`)), line: 1, want: problemTwice + "prev"},
		{name: "seq in capitals", log: join(changed(t, `"seq"`, `"SEQ"`)), line: 1, want: problemCase + "seq"},
		{name: "SEQ next to seq", log: join(changed(t, `{"seq":1,`, `{"seq":1,"SEQ":2,`)), line: 1, want: problemCase + "seq"},
		{name: "Prev next to prev", log: join(changed(t, `"version"`, `"Prev":"`+strings.Repeat("1", 64)+`","version"`)),
			line: 1, want: problemCase + "prev"},
		{name: "EVENT next to event", log: join(changed(t, `"version"`, `"EVENT":"decision","version"`)), line: 1, want: problemCase + "event"},
		{name: "seq with a long s", log: join(changed(t, `{"seq":1,`, `{"seq":1,"ſeq":2,`)), line: 1, want: problemCase + "seq"},
		{name: "Torn_Length next to torn_length", line: 1, want: problemCase + "torn_length",
			log: join(changed(t, `"broker_started"`, `"log_recovered","torn_length":5,"Torn_Length":6,"torn_sha256":"`+zeros+`"`))},
		{name: "seq missing", log: join(changed(t, `"seq":1,`, ``)), line: 1, want: problemSeq},
		{name: "seq as text", log: join(changed(t, `"seq":1`, `"seq":"1"`)), line: 1, want: problemSeq},
		{name: "seq 1.0", log: join(changed(t, `"seq":1`, `"seq":1.0`)), line: 1, want: problemSeq},
		{name: "seq 1e0", log: join(changed(t, `"seq":1`, `"seq":1e0`)), line: 1, want: problemSeq},
		{name: "seq -1", log: join(changed(t, `"seq":1`, `"seq":-1`)), line: 1, want: problemSeq},
		{name: "seq 0", log: join(changed(t, `"seq":1`, `"seq":0`)), line: 1, want: problemSeq},
		{name: "seq too large", log: join(changed(t, `"seq":1`, `"seq":18446744073709551616`)), line: 1, want: problemSeq},
		{name: "time not UTC", log: join(changed(t, `00.000Z"`, `00.000+02:00"`)), line: 1, want: problemTime},
		{name: "time not a time", log: join(changed(t, `"2026-10-14T12:00:00.000Z"`, `"`+canary+`"`)), line: 1, want: problemTime},
		{name: "time missing", log: join(changed(t, `"time":"2026-10-14T12:00:00.000Z",`, ``)), line: 1, want: problemTime},
		{name: "event in capitals", log: join(changed(t, `"broker_started"`, `"Broker_started"`)), line: 1, want: problemEvent},
		{name: "event not text", log: join(changed(t, `"broker_started"`, `7`)), line: 1, want: problemEvent},
		{name: "event empty", log: join(changed(t, `"broker_started"`, `""`)), line: 1, want: problemEvent},
		{name: "prev in capitals", log: join(changed(t, zeros, strings.Repeat("A", 64))), line: 1, want: problemPrev},
		{name: "prev too short", log: join(changed(t, zeros, zeros[1:])), line: 1, want: problemPrev},
		{name: "prev missing", log: join(changed(t, `"prev":"`+zeros+`",`, ``)), line: 1, want: problemPrev},
		{name: "prev not zeros in the first entry", log: join(changed(t, zeros, strings.Repeat("1", 64))),
			line: 1, want: "has a prev that is not 64 zeros, which the first entry needs"},
		{name: "log_recovered with a torn_length that is not a number", log: join(tl[0], tl[1], torn, bytes.Replace(recovered, []byte(`"torn_length":`), []byte(`"torn_length":0`), 1)),
			line: 3, want: problemJSON},
		{name: "log_recovered without torn_length", line: 1, want: problemTornLength,
			log: join(changed(t, `"broker_started"`, `"log_recovered","torn_sha256":"`+zeros+`"`))},
		{name: "log_recovered with a torn_length that is too large", line: 1, want: problemTornLength,
			log: join(changed(t, `"broker_started"`, `"log_recovered","torn_length":65537,"torn_sha256":"`+zeros+`"`))},
		{name: "log_recovered without torn_sha256", line: 1, want: problemTornHash,
			log: join(changed(t, `"broker_started"`, `"log_recovered","torn_length":5`))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(bytes.NewReader(tt.log), tt.anchors...)
			var ve *VerifyError
			if !errors.As(err, &ve) {
				t.Fatalf("Verify: %v; want a *VerifyError", err)
			}
			if ve.Line != tt.line || ve.Problem != tt.want {
				t.Errorf("Verify: line %d, %q; want line %d, %q", ve.Line, ve.Problem, tt.line, tt.want)
			}
			if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "CANARY") {
				t.Errorf("the error shows text from the log: %v", err)
			}
		})
	}
}

// TestVerifyFindsEveryByteChange changes, removes or adds each byte of a
// log, one at a time. With the anchor of the last entry, Verify must find
// every change. The log has a torn line, which is outside the chain.
func TestVerifyFindsEveryByteChange(t *testing.T) {
	t.Parallel()
	c := newChain(t)
	c.add(BrokerStarted{Version: "dev"})
	c.add(Request{Subject: secretsSubject(), Message: "<b>text</b>"})
	c.tear(half(c.lines[1]))
	c.add(Decision{Subject: secretsSubject(), UserID: 7, Answer: AnswerApproveOnce})
	c.add(BrokerStopped{})
	log := c.bytes()
	if _, err := Verify(bytes.NewReader(log), c.last); err != nil {
		t.Fatalf("Verify of the good log: %v", err)
	}
	check := func(what string, i int, bad []byte) {
		t.Helper()
		if _, err := Verify(bytes.NewReader(bad), c.last); err == nil {
			t.Errorf("%s at byte %d: Verify found no problem", what, i)
		}
	}
	for i := range log {
		for _, b := range []byte{log[i] ^ 0x01, '\n'} {
			if b == log[i] {
				continue
			}
			bad := bytes.Clone(log)
			bad[i] = b
			check("changing a byte", i, bad)
		}
		check("removing a byte", i, slices.Delete(bytes.Clone(log), i, i+1))
		check("adding a byte", i, slices.Insert(bytes.Clone(log), i, ' '))
	}
	check("adding a byte", len(log), append(bytes.Clone(log), ' '))
}

// failingReader returns data, then an error.
type failingReader struct {
	data []byte
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, errors.New("read failed")
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestVerifyReadError(t *testing.T) {
	c := newChain(t).addAll()
	_, err := Verify(&failingReader{data: c.bytes()})
	var ve *VerifyError
	if err == nil || errors.As(err, &ve) {
		t.Fatalf("Verify = %v; want a read error, not a *VerifyError", err)
	}
	if want := "reading line 15: read failed"; !strings.Contains(err.Error(), want) {
		t.Errorf("Verify = %v; want %q", err, want)
	}
}

func TestParseAnchor(t *testing.T) {
	hash := sha256.Sum256([]byte("made-up line"))
	hexHash := hex.EncodeToString(hash[:])
	for _, s := range []string{"12:" + hexHash, "12:" + strings.ToUpper(hexHash), "012:" + hexHash} {
		a, err := ParseAnchor(s)
		if err != nil || a != (Anchor{Seq: 12, Hash: hash}) {
			t.Errorf("ParseAnchor(%q) = %v, %v; want 12 and the hash", s, a, err)
		}
	}
	a := Anchor{Seq: 12, Hash: hash}
	if got, err := ParseAnchor(a.String()); err != nil || got != a {
		t.Errorf("ParseAnchor(%q) = %v, %v; want %v", a.String(), got, err, a)
	}
	for _, s := range []string{
		"", "12", "12:", ":" + hexHash, "0:" + hexHash, "-1:" + hexHash, "+1:" + hexHash, " 1:" + hexHash,
		"1:" + hexHash[1:], "1:" + hexHash + "0", "1:" + hexHash[1:] + "g", "x:" + hexHash, "1:" + hexHash + ":1",
		"18446744073709551616:" + hexHash, "1:" + canary,
	} {
		_, err := ParseAnchor(s)
		if err == nil {
			t.Errorf("ParseAnchor(%q): no error", s)
			continue
		}
		if s != "" && strings.Contains(err.Error(), s) || strings.Contains(err.Error(), "CANARY") {
			t.Errorf("ParseAnchor(%q) = %v; the error repeats the text", s, err)
		}
	}
}

// problemTemplates are every problem that Verify can report, with each
// number written as N. FuzzVerify checks that every problem is one of
// them, so no problem can hold text from the log.
var problemTemplates = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range []string{
		problemJSON, problemNotObject, problemSeq, problemTime, problemEvent, problemPrev, problemTornLength, problemTornHash,
		problemDepth,
		"is longer than N bytes",
		"has no newline at the end: it is a torn line, and no log_recovered entry follows it",
		"is a log_recovered entry, but the line before it is not the torn line that it names",
		"has seq N, want N",
		"has a prev that is not N zeros, which the first entry needs",
		"has a prev that is not the hash of the entry before it, on line N",
		"is entry N, and its hash is not the hash in the anchor",
		"no entry N: the log ends at entry N",
		"the log is empty",
		"two anchors for entry N have different hashes: the log was cut or changed, and the entry was written again, " +
			"or the anchors come from two logs",
		"an anchor needs an entry number from N",
	} {
		m[numbers.ReplaceAllString(p, "N")] = true
	}
	for _, name := range entryFields {
		m[problemTwice+name] = true
		m[problemCase+numbers.ReplaceAllString(name, "N")] = true
	}
	return m
}()

var numbers = regexp.MustCompile(`[0-9]+`)

func FuzzVerify(f *testing.F) {
	c := newChain(f).addAll()
	f.Add(c.bytes())
	tc := newChain(f)
	tc.add(BrokerStarted{Version: "dev"})
	tc.tear(half(tc.lines[0]))
	tc.add(BrokerStopped{})
	f.Add(tc.bytes())
	f.Add([]byte(nil))
	f.Add([]byte("\n"))
	f.Add([]byte(firstLine + "\n"))
	f.Add(half(c.lines[0]))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := Verify(bytes.NewReader(data))
		if err != nil {
			var ve *VerifyError
			if !errors.As(err, &ve) {
				t.Fatalf("Verify: %v; want a *VerifyError", err)
			}
			if !problemTemplates[numbers.ReplaceAllString(ve.Problem, "N")] {
				t.Fatalf("Verify: the problem %q is not one of the fixed problems", ve.Problem)
			}
			lines := uint64(1)
			for _, b := range data {
				if b == '\n' {
					lines++
				}
			}
			if ve.Line > lines {
				t.Fatalf("Verify: line %d of a log with %d lines", ve.Line, lines)
			}
			return
		}
		if res.Entries == 0 || res.Last.Seq != res.Entries {
			t.Fatalf("Verify = %+v; want the last seq to be the number of entries", res)
		}
		if _, err := Verify(bytes.NewReader(data), res.Last); err != nil {
			t.Fatalf("Verify with the anchor of the last entry: %v", err)
		}
		// Open reads only the end of a log. It must find the same last
		// entry as Verify.
		tail, err := readTail(bytes.NewReader(data), int64(len(data)))
		if err != nil || tail.torn != nil || !tail.hasLast || sha256.Sum256(tail.last) != res.Last.Hash {
			t.Fatalf("readTail = %v, %v; want the last line of entry %d and no torn bytes", tail, err, res.Last.Seq)
		}
		if e, bad := parseEntry(tail.last); bad != "" || e.seq != res.Last.Seq {
			t.Fatalf("parseEntry of the last line = %+v, %q; want seq %d", e, bad, res.Last.Seq)
		}
	})
}

// TestReadTail checks how Open finds the end of a log, at the limits.
func TestReadTail(t *testing.T) {
	line := func(n int) []byte { return bytes.Repeat([]byte("x"), n) }
	tests := []struct {
		name     string
		log      []byte
		last     []byte // nil: no complete line
		torn     []byte
		wantErr  string
		hasFirst bool
	}{
		{name: "empty", log: nil},
		{name: "one line", log: join([]byte("a")), last: []byte("a")},
		{name: "two lines", log: join([]byte("a"), []byte("bc")), last: []byte("bc")},
		{name: "torn line", log: append(join([]byte("a")), "bc"...), last: []byte("a"), torn: []byte("bc")},
		{name: "only a torn line", log: []byte("bc"), torn: []byte("bc")},
		{name: "an empty last line", log: join([]byte("a"), nil), last: []byte{}},
		{name: "longest lines", log: append(join(line(5), line(MaxLineSize)), line(MaxLineSize)...),
			last: line(MaxLineSize), torn: line(MaxLineSize)},
		{name: "longest line at the start", log: join(line(MaxLineSize)), last: line(MaxLineSize)},
		{name: "longest torn line alone", log: line(MaxLineSize), torn: line(MaxLineSize)},
		{name: "torn line too long", log: append(join(line(5)), line(MaxLineSize+1)...), wantErr: "without a newline"},
		{name: "torn line alone too long", log: line(MaxLineSize + 1), wantErr: "without a newline"},
		{name: "torn line far too long", log: append(join(line(5)), line(3*MaxLineSize)...), wantErr: "without a newline"},
		{name: "last line too long", log: join(line(5), line(MaxLineSize+1)), wantErr: "longer than 65536"},
		{name: "last line at the start too long", log: join(line(MaxLineSize + 1)), wantErr: "longer than 65536"},
		{name: "last line too long before the longest torn line", log: append(join(line(5), line(MaxLineSize+1)), line(MaxLineSize)...),
			wantErr: "longer than 65536"},
		{name: "last line far too long", log: join(line(5), line(3*MaxLineSize)), wantErr: "longer than 65536"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readTail(bytes.NewReader(tt.log), int64(len(tt.log)))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("readTail: %v; want an error with %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readTail: %v", err)
			}
			if got.hasLast != (tt.last != nil) || !bytes.Equal(got.last, tt.last) || !bytes.Equal(got.torn, tt.torn) ||
				(got.torn == nil) != (tt.torn == nil) {
				t.Errorf("readTail = last %d bytes (%v), torn %d bytes; want last %d bytes, torn %d bytes",
					len(got.last), got.hasLast, len(got.torn), len(tt.last), len(tt.torn))
			}
		})
	}
}

// TestReadTailReadsOnlyTheEnd: Open must not read the whole log.
func TestReadTailReadsOnlyTheEnd(t *testing.T) {
	r := &countingReaderAt{size: 1 << 30}
	if _, err := readTail(r, r.size); err == nil {
		t.Fatal("readTail of a log of zeros: no error")
	}
	if r.read > 2*MaxLineSize+2 {
		t.Errorf("readTail read %d bytes; want at most %d", r.read, 2*MaxLineSize+2)
	}
}

// countingReaderAt is a log of zeros that counts the bytes read.
type countingReaderAt struct {
	size int64
	read int64
}

func (r *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > r.size {
		return 0, io.ErrUnexpectedEOF
	}
	clear(p)
	r.read += int64(len(p))
	return len(p), nil
}

// TestVerifyHostileLines: lines that a careless reader might read in two
// ways. Verify refuses them, or reads them in one clear way.
func TestVerifyHostileLines(t *testing.T) {
	base := `{"seq":1,"time":"2026-10-14T12:00:00.000Z","event":"broker_started","prev":"` + zeros + `","version":"dev"}`
	edit := func(old, new string) string {
		if !strings.Contains(base, old) {
			t.Fatalf("base has no %q", old)
		}
		return strings.Replace(base, old, new, 1)
	}
	nested := func(depth int) string {
		return edit(`"dev"`, `"dev","x":`+strings.Repeat("[", depth)+strings.Repeat("]", depth))
	}
	tests := []struct {
		name string
		line string
		want string // the problem; "" means the line passes
	}{
		{"seq 01", edit(`"seq":1`, `"seq":01`), problemJSON},
		{"seq -0", edit(`"seq":1`, `"seq":-0`), problemSeq},
		{"seq too large", edit(`"seq":1`, `"seq":99999999999999999999999`), problemSeq},
		{"seq as an escaped name", edit(`"seq":1`, `"seq":1`), ""},
		{"seq twice, once escaped", edit(`"seq":1`, `"seq":1,"seq":2`), problemTwice + "seq"},
		{"NUL in a string", edit(`"dev"`, "\"d\x00ev\""), problemJSON},
		{"NUL after the object", base + "\x00", problemJSON},
		{"invalid UTF-8 in an event field", edit(`"dev"`, "\"d\xffev\""), ""},
		{"invalid UTF-8 in a name", edit(`"version"`, "\"vers\xffion\""), ""},
		{"carriage return at the end", base + "\r", ""},
		{"spaces around", "  " + base + "  ", ""},
		{"byte order mark", "\xef\xbb\xbf" + base, problemJSON},
		{"time with a lower case z", edit(`000Z"`, `000z"`), problemTime},
		{"time 24:00", edit(`12:00:00.000Z`, `24:00:00.000Z`), problemTime},
		{"time with a leap second", edit(`12:00:00.000Z`, `23:59:60.000Z`), problemTime},
		{"time in the year 0", edit(`2026-10-14`, `0000-01-01`), ""},
		// Unicode case folding does not match "ı" (dotless i) or "İ" to
		// "i", and neither does encoding/json: these are other names.
		{"a name with a dotless i", edit(`"version"`, `"tıme":"2026-10-15T12:00:00.000Z","version"`), ""},
		{"a name with a capital dotted I", edit(`"version"`, `"TİME":"2026-10-15T12:00:00.000Z","version"`), ""},
		// At most maxDepth levels, counted by Verify itself, on every Go
		// version. The object of the entry is the first level.
		{"16 levels, the most", nested(maxDepth - 1), ""},
		{"17 levels", nested(maxDepth), problemDepth},
		{"10000 levels", nested(10000), problemDepth},
		{"17 levels of objects", edit(`"dev"`, `"dev","x":`+strings.Repeat(`{"a":`, maxDepth)+`1`+strings.Repeat("}", maxDepth)),
			problemDepth},
		{"brackets in a string", edit(`"dev"`, `"dev","x":"`+strings.Repeat("[{", 100)+`"`), ""},
		{"brackets after an escaped quote in a string", edit(`"dev"`, `"dev","x":"\"`+strings.Repeat("[", 100)+`"`), ""},
		{"deep arrays after an escaped backslash ends a string",
			edit(`"dev"`, `"dev","x":"\\","y":`+strings.Repeat("[", maxDepth)+strings.Repeat("]", maxDepth)), problemDepth},
		{"too deep and not valid JSON", base + strings.Repeat("[", maxDepth+1), problemDepth},
		// Verify does not read the fields of events other than
		// log_recovered.
		{"an event field twice", edit(`"dev"`, `"dev","answer":"deny","answer":"approve_once"`), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(strings.NewReader(tt.line + "\n"))
			if tt.want == "" {
				if err != nil {
					t.Errorf("Verify: %v; want it to pass", err)
				}
				return
			}
			var ve *VerifyError
			if !errors.As(err, &ve) || ve.Line != 1 || ve.Problem != tt.want {
				t.Errorf("Verify: %v; want line 1: %q", err, tt.want)
			}
			if err != nil && (strings.Contains(err.Error(), "dev") || strings.Contains(err.Error(), "\x00")) {
				t.Errorf("the error shows text from the line: %v", err)
			}
		})
	}
}

// TestProblemDepthNamesTheLimit: the text of problemDepth is a constant,
// so it must name maxDepth itself.
func TestProblemDepthNamesTheLimit(t *testing.T) {
	if want := " " + strconv.Itoa(maxDepth) + " "; !strings.Contains(problemDepth, want) {
		t.Errorf("problemDepth = %q; want it to name the limit %d", problemDepth, maxDepth)
	}
}

// TestVerifyHugeInputs: Verify stops at the first line that is too long,
// and it does not read a long line into memory.
func TestVerifyHugeInputs(t *testing.T) {
	good := newChain(t).addAll().bytes()
	tooLong := bytes.Repeat([]byte("x"), MaxLineSize+1)
	tests := []struct {
		name string
		log  []byte
		line uint64
		want string
	}{
		{"an 8 MiB line", bytes.Repeat([]byte("x"), 8<<20), 1, "is longer than 65536 bytes"},
		{"an 8 MiB line with a newline", append(bytes.Repeat([]byte("x"), 8<<20), '\n'), 1, "is longer than 65536 bytes"},
		{"a line one byte too long at the end", append(bytes.Clone(good), tooLong...), 15, "is longer than 65536 bytes"},
		{"a line one byte too long, with a newline", append(bytes.Clone(good), append(tooLong, '\n')...), 15,
			"is longer than 65536 bytes"},
		{"a million newlines", bytes.Repeat([]byte("\n"), 1<<20), 1, problemJSON},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(bytes.NewReader(tt.log))
			var ve *VerifyError
			if !errors.As(err, &ve) || ve.Line != tt.line || ve.Problem != tt.want {
				t.Errorf("Verify: %v; want line %d: %q", err, tt.line, tt.want)
			}
		})
	}
}
