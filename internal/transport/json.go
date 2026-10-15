package transport

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxRequestBody is the largest request body that ReadJSON reads, in
// bytes: 2 MiB. It fits the largest valid request (DESIGN.md section 10):
//
//   - The client sends a claimed text field, such as the reason, with at
//     most maxClaimedText bytes (64 KiB, as claim.MaxInput), and a command
//     line with at most maxArguments arguments and maxClaimedText bytes in
//     all. It replaces a longer field with "[hidden: too long]".
//   - In JSON, one byte of text takes at most jsonEscapeFactor bytes: a
//     control character becomes \u0001. Each argument adds 3 bytes: two
//     quotes and a comma. So a text field takes at most 2 + 6 × 65,536 =
//     393,218 bytes, and a command line at most 1 + 3 × 4096 + 6 × 65,536 =
//     405,505 bytes.
//   - The largest request is an SSH request: maxCommandLines command lines
//     (ssh and at most 3 of its parent processes) and the reason, so at
//     most 2,015,238 bytes. A request for secrets has one command line and
//     2 text fields (the working directory and the reason): at most
//     1,191,941 bytes. The other fields of a request, such as names, keys
//     and the data to sign, fit in maxOtherFields.
const MaxRequestBody = 2 << 20

// The parts of the largest valid request; see MaxRequestBody. A test
// checks that they fit.
const (
	maxClaimedText   = 64 << 10
	maxArguments     = 4096
	maxCommandLines  = 4
	maxOtherFields   = 64 << 10
	jsonEscapeFactor = 6
)

// Limits on the shape of a request body (checkJSONShape). They are far
// above any valid request: the largest has about 16,400 values (4 command
// lines of 4096 arguments), and no object in a request has 32 keys.
const (
	maxJSONDepth  = 16      // levels of objects and arrays
	maxJSONKeys   = 256     // keys in one object
	maxJSONValues = 1 << 16 // values in all
)

// requestError is an error of ReadJSON. Its text is fixed: it never holds
// anything from the request, so it is safe to log. The client gets only
// the HTTP status.
type requestError struct {
	status int
	text   string
}

func (e *requestError) Error() string { return "transport: " + e.text }

// The errors of ReadJSON.
var (
	errContentType = &requestError{http.StatusUnsupportedMediaType, "the request body is not application/json"}
	errTooLarge    = &requestError{http.StatusRequestEntityTooLarge,
		"the request body is larger than " + strconv.Itoa(MaxRequestBody>>20) + " MiB"}
	errRead      = &requestError{http.StatusBadRequest, "the request body could not be read"}
	errNotUTF8   = &requestError{http.StatusBadRequest, "the request body is not valid UTF-8"}
	errSyntax    = &requestError{http.StatusBadRequest, "the request body is not valid JSON"}
	errNotObject = &requestError{http.StatusBadRequest, "the request body is not a JSON object"}
	errTrailing  = &requestError{http.StatusBadRequest, "the request body has more after the JSON object"}
	errKeyName   = &requestError{http.StatusBadRequest, "a key in the request body is not a lower-case name"}
	errDuplicate = &requestError{http.StatusBadRequest, "a key appears twice in one object of the request body"}
	errTooDeep   = &requestError{http.StatusBadRequest,
		"the request body has more than " + strconv.Itoa(maxJSONDepth) + " levels of objects and arrays"}
	errTooManyKeys = &requestError{http.StatusBadRequest,
		"an object in the request body has more than " + strconv.Itoa(maxJSONKeys) + " keys"}
	errTooManyValues = &requestError{http.StatusBadRequest,
		"the request body has more than " + strconv.Itoa(maxJSONValues) + " values"}
	errNotRequest = &requestError{http.StatusBadRequest,
		"the request body does not fit the request: it has an unknown key, or a value of the wrong type"}
)

// ReadJSON reads the body of a request to the broker and decodes it into
// a new T. On any error it answers the request itself, with the HTTP
// status only, and returns the error and no value. The error never holds
// anything from the request, so it is safe to log.
//
// The request must have the content type application/json
// (charset=utf-8 is allowed), and the body must be:
//
//   - at most MaxRequestBody bytes;
//   - valid UTF-8;
//   - one JSON object, with nothing but whitespace after it;
//   - at most 16 levels of objects and arrays, at most 256 keys in one
//     object, and at most 65,536 values in all;
//   - in each object, each key at most once;
//   - each key a lower-case name: a letter, then letters, digits or "_",
//     at most 64 in all. So put data into values, not into keys; a map in
//     T accepts only keys of this form;
//   - only keys that T has (no unknown fields), with values of the right
//     type.
//
// ReadJSON reads the whole body. Then net/http lifts the read deadline
// (readTimeout) and watches the connection, so the request's context ends
// when the client hangs up. That fails in one case: when the client has
// already sent its next request on the same connection (HTTP pipelining),
// net/http stops watching, and the request runs until its own time limit.
// The handler may wait for the approver as long as it needs. It must
// answer with WriteJSON or WriteError, which set a new write deadline for
// the answer.
func ReadJSON[T any](w http.ResponseWriter, r *http.Request) (*T, error) {
	v, err := readJSON[T](w, r)
	if err != nil {
		status := http.StatusBadRequest
		var re *requestError
		if errors.As(err, &re) {
			status = re.status
		}
		WriteError(w, status)
		return nil, err
	}
	return v, nil
}

// readJSON is ReadJSON without the answer on errors.
func readJSON[T any](w http.ResponseWriter, r *http.Request) (*T, error) {
	if !isJSONContentType(r.Header.Values("Content-Type")) {
		return nil, errContentType
	}
	if r.ContentLength > MaxRequestBody {
		// Do not read the body, and close the connection after the
		// answer, so that the rest of the body is not read either.
		w.Header().Set("Connection", "close")
		return nil, errTooLarge
	}
	// MaxBytesReader also makes the server close the connection after
	// the answer, when the body is too long.
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBody))
	// The body may hold claimed text with a secret in it. Clearing it is
	// best effort: the decoded value, encoding/json and net/http's buffers
	// keep their own copies.
	defer clear(data)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, errTooLarge
		}
		return nil, errRead
	}
	return decodeJSON[T](data)
}

// isJSONContentType reports whether values, the Content-Type headers of a
// request, are exactly one header for JSON in UTF-8.
func isJSONContentType(values []string) bool {
	if len(values) != 1 {
		return false
	}
	media, params, err := mime.ParseMediaType(values[0])
	if err != nil || media != "application/json" {
		return false
	}
	for name, value := range params {
		if name != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

// decodeJSON decodes a request body with the rules of ReadJSON, except the
// content type. It returns a new T, or an error and no value: a value that
// failed may be decoded in part, and must not be used.
func decodeJSON[T any](data []byte) (*T, error) {
	if len(data) > MaxRequestBody {
		return nil, errTooLarge
	}
	if !utf8.Valid(data) {
		return nil, errNotUTF8
	}
	if err := checkJSONShape(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	v := new(T)
	// encoding/json's errors can repeat a key or a part of a value from
	// the request, so they are not passed on.
	if err := dec.Decode(v); err != nil {
		return nil, errNotRequest
	}
	// checkJSONShape already refused more data after the object; this
	// makes sure that the decoder took all of it, too.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errTrailing
	}
	return v, nil
}

// checkJSONShape checks, in one pass over the bytes, what encoding/json
// does not check in a request body, and it limits the work that the
// decoder does next:
//
//   - the body is valid JSON: one object, with nothing but whitespace after
//     it;
//   - at most maxJSONDepth levels of objects and arrays;
//   - at most maxJSONValues values in all (objects, arrays, strings,
//     numbers, true, false and null), and at most maxJSONKeys keys in one
//     object. json.Decoder.Decode does work for each value, also for a
//     value of the wrong type (it makes an error value for each), so these
//     limits bound its time and memory;
//   - in each object, each key at most once, and each key a lower-case
//     name: a letter, then letters, digits or "_", at most 64 in all. Keys
//     are compared after JSON unescaping ("\u0072eason" is "reason"), as
//     encoding/json compares them.
//
// encoding/json matches a key to a field without regard to case, and with
// Unicode case folding ("ſ" matches "s"). With keys of this form, and field
// names in lower case, a key matches a field only when it is the exact
// name. The data must be valid UTF-8.
func checkJSONShape(data []byte) error {
	s := jsonScanner{data: data}
	s.skipSpace()
	if s.peek() != '{' {
		return errNotObject
	}
	if err := s.value(0); err != nil {
		return err
	}
	s.skipSpace()
	if s.pos != len(s.data) {
		return errTrailing
	}
	return nil
}

// maxJSONKey is the longest key in a request body, in bytes.
const maxJSONKey = 64

// jsonScanner reads a request body for checkJSONShape. It calls itself for
// nested values, but never more than maxJSONDepth levels deep.
type jsonScanner struct {
	data   []byte
	pos    int
	values int // the values so far
	// keys holds the keys of the open object on each level. A level has at
	// most one open object at a time, so each map is used again.
	keys [maxJSONDepth]map[string]struct{}
	key  [maxJSONKey]byte // the last key, after unescaping
}

// peek returns the byte at the position, or 0 at the end.
func (s *jsonScanner) peek() byte {
	if s.pos < len(s.data) {
		return s.data[s.pos]
	}
	return 0
}

// skipSpace skips JSON whitespace.
func (s *jsonScanner) skipSpace() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

// value reads one value. depth is the number of objects and arrays that
// hold it.
func (s *jsonScanner) value(depth int) error {
	if s.values++; s.values > maxJSONValues {
		return errTooManyValues
	}
	s.skipSpace()
	switch c := s.peek(); {
	case c == '{':
		return s.object(depth + 1)
	case c == '[':
		return s.array(depth + 1)
	case c == '"':
		return s.str()
	case c == '-' || '0' <= c && c <= '9':
		return s.number()
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	}
	return errSyntax
}

// object reads an object; depth counts the object itself.
func (s *jsonScanner) object(depth int) error {
	if depth > maxJSONDepth {
		return errTooDeep
	}
	s.pos++ // the "{"
	keys := s.keys[depth-1]
	if keys == nil {
		keys = make(map[string]struct{})
		s.keys[depth-1] = keys
	}
	clear(keys)
	s.skipSpace()
	if s.peek() == '}' {
		s.pos++
		return nil
	}
	for {
		s.skipSpace()
		key, err := s.objectKey()
		if err != nil {
			return err
		}
		if _, dup := keys[string(key)]; dup {
			return errDuplicate
		}
		if len(keys) == maxJSONKeys {
			return errTooManyKeys
		}
		keys[string(key)] = struct{}{}
		s.skipSpace()
		if s.peek() != ':' {
			return errSyntax
		}
		s.pos++
		if err := s.value(depth); err != nil {
			return err
		}
		s.skipSpace()
		switch s.peek() {
		case ',':
			s.pos++
		case '}':
			s.pos++
			return nil
		default:
			return errSyntax
		}
	}
}

// array reads an array; depth counts the array itself.
func (s *jsonScanner) array(depth int) error {
	if depth > maxJSONDepth {
		return errTooDeep
	}
	s.pos++ // the "["
	s.skipSpace()
	if s.peek() == ']' {
		s.pos++
		return nil
	}
	for {
		if err := s.value(depth); err != nil {
			return err
		}
		s.skipSpace()
		switch s.peek() {
		case ',':
			s.pos++
		case ']':
			s.pos++
			return nil
		default:
			return errSyntax
		}
	}
}

// objectKey reads the key of an object member, and returns it after JSON
// unescaping. The result is valid until the next call. A key that is not
// a lower-case name is errKeyName, even before its end.
func (s *jsonScanner) objectKey() ([]byte, error) {
	if s.peek() != '"' {
		return nil, errSyntax
	}
	s.pos++
	n := 0
	for {
		if s.pos >= len(s.data) {
			return nil, errSyntax
		}
		c := s.data[s.pos]
		switch c {
		case '"':
			s.pos++
			if n == 0 || s.key[0] < 'a' || s.key[0] > 'z' {
				return nil, errKeyName
			}
			return s.key[:n], nil
		case '\\':
			r, ok := s.escape()
			if !ok {
				return nil, errSyntax
			}
			if r >= 0x80 {
				return nil, errKeyName
			}
			c = byte(r) //nolint:gosec // G115: r is below 0x80 here.
		default:
			s.pos++
		}
		if !isKeyByte(c) || n == maxJSONKey {
			return nil, errKeyName
		}
		s.key[n] = c
		n++
	}
}

// isKeyByte reports whether c may be in a key: a lower-case letter, a
// digit or "_".
func isKeyByte(c byte) bool {
	return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_'
}

// str reads a string value: valid escapes, and no control characters.
func (s *jsonScanner) str() error {
	s.pos++ // the opening quote
	for s.pos < len(s.data) {
		switch c := s.data[s.pos]; {
		case c == '"':
			s.pos++
			return nil
		case c == '\\':
			if _, ok := s.escape(); !ok {
				return errSyntax
			}
		case c < 0x20:
			return errSyntax
		default:
			s.pos++
		}
	}
	return errSyntax
}

// escape reads the escape at the position, which is at a backslash, and
// returns the character that it stands for. For \u, that is the UTF-16
// code unit. ok is false if the escape is not valid JSON.
func (s *jsonScanner) escape() (rune, bool) {
	if s.pos+1 >= len(s.data) {
		return 0, false
	}
	c := s.data[s.pos+1]
	s.pos += 2
	switch c {
	case '"', '\\', '/':
		return rune(c), true
	case 'b':
		return '\b', true
	case 'f':
		return '\f', true
	case 'n':
		return '\n', true
	case 'r':
		return '\r', true
	case 't':
		return '\t', true
	case 'u':
		if s.pos+4 > len(s.data) {
			return 0, false
		}
		var r rune
		for _, h := range s.data[s.pos : s.pos+4] {
			switch {
			case '0' <= h && h <= '9':
				r = r<<4 | rune(h-'0')
			case 'a' <= h && h <= 'f':
				r = r<<4 | rune(h-'a'+10)
			case 'A' <= h && h <= 'F':
				r = r<<4 | rune(h-'A'+10)
			default:
				return 0, false
			}
		}
		s.pos += 4
		return r, true
	}
	return 0, false
}

// number reads a number: -? (0 | [1-9][0-9]*) (\.[0-9]+)? ([eE][+-]?[0-9]+)?
func (s *jsonScanner) number() error {
	if s.peek() == '-' {
		s.pos++
	}
	switch c := s.peek(); {
	case c == '0':
		s.pos++
	case '1' <= c && c <= '9':
		s.digits()
	default:
		return errSyntax
	}
	if s.peek() == '.' {
		s.pos++
		if !s.digits() {
			return errSyntax
		}
	}
	if c := s.peek(); c == 'e' || c == 'E' {
		s.pos++
		if c := s.peek(); c == '+' || c == '-' {
			s.pos++
		}
		if !s.digits() {
			return errSyntax
		}
	}
	return nil
}

// digits skips digits, and reports whether there was at least one.
func (s *jsonScanner) digits() bool {
	start := s.pos
	for s.pos < len(s.data) && '0' <= s.data[s.pos] && s.data[s.pos] <= '9' {
		s.pos++
	}
	return s.pos > start
}

// literal reads the literal word: true, false or null.
func (s *jsonScanner) literal(word string) error {
	end := s.pos + len(word)
	if end > len(s.data) || string(s.data[s.pos:end]) != word {
		return errSyntax
	}
	s.pos = end
	return nil
}

// WriteJSON answers a request with status and v as JSON. It sets a new
// write deadline first (writeTimeout from now): the server's own deadline
// counts from when the request came, and may have passed while the handler
// waited for the approver. The answer is marked not to be stored
// (Cache-Control: no-store). The encoded copy is cleared after it is
// written, as best effort: net/http's write buffer keeps a copy, and so
// does a buffer in the pool of encoding/json. So an answer with secret
// values goes through WriteJSONBody instead. An error never holds anything
// from v.
func WriteJSON(w http.ResponseWriter, status int, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		WriteError(w, http.StatusInternalServerError)
		return errors.New("transport: the answer cannot be written as JSON")
	}
	defer clear(body)
	return writeBody(w, status, body)
}

// WriteJSONBody answers a request with status and body: one JSON value
// that the caller wrote itself, such as an answer with secret values that
// api.SecretsAnswer.Encode wrote, so that no other copy of the values is
// made. It does not change body; the caller clears it after the call.
// Otherwise it works as WriteJSON: a new write deadline, and
// Cache-Control: no-store. A body that is not valid JSON is not written;
// the client gets 500. An error never holds anything from body.
func WriteJSONBody(w http.ResponseWriter, status int, body []byte) error {
	if !json.Valid(body) {
		WriteError(w, http.StatusInternalServerError)
		return errors.New("transport: the answer is not valid JSON")
	}
	return writeBody(w, status, body)
}

// processingTimeout is the time a client has to take a 102 Processing
// answer (WriteProcessing). It is short: that answer is small, and the
// broker must not wait for a client that does not read while its request
// waits for the approver. It is a variable only so that a test can make it
// short.
var processingTimeout = 5 * time.Second

// WriteProcessing tells the client that its request is still being
// worked on: an informational answer, 102 Processing, with the headers in
// h, before the final answer. The broker sends it when a request starts to
// wait for the approver, with the short code that the client prints
// (DESIGN.md section 10). The final answer must still come, with WriteJSON
// or WriteError; it does not carry the headers in h. Call WriteProcessing
// only before the final answer.
//
// It first sets a short write deadline (processingTimeout), so a client
// that does not read cannot hold the caller for long. WriteJSON and
// WriteError set a new deadline for the final answer. net/http does not
// say whether the informational answer reached the client; a client that
// does not take it does not take the final answer either.
func WriteProcessing(w http.ResponseWriter, h http.Header) error {
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(processingTimeout))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	header := w.Header()
	for name, values := range h {
		header[http.CanonicalHeaderKey(name)] = values
	}
	w.WriteHeader(http.StatusProcessing)
	for name := range h {
		header.Del(name)
	}
	return nil
}

// WriteError answers a request with an error: the HTTP status and its
// standard text, such as {"error":"Forbidden"}, and nothing else. A status
// that is not an error becomes 500. WriteError says nothing about what was
// wrong: the client may be hostile, and the broker says little to it.
func WriteError(w http.ResponseWriter, status int) {
	text := http.StatusText(status)
	if status < 400 || text == "" {
		status, text = http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)
	}
	body, err := json.Marshal(struct {
		Error string `json:"error"`
	}{text})
	if err != nil {
		body = []byte(`{"error":"Internal Server Error"}`)
	}
	// The client is told by the status. If it cannot be told, there is
	// nobody to tell.
	_ = writeBody(w, status, body)
}

// writeBody writes a JSON answer.
func writeBody(w http.ResponseWriter, status int, body []byte) error {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Cache-Control", "no-store")
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(writeTimeout))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	w.WriteHeader(status)
	_, err = w.Write(body)
	return err
}
