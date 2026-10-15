package api

import (
	"encoding/json"
	"reflect"
	"testing"
)

// FuzzDecode decodes any bytes into each type of the protocol. Decoding
// never panics; a value that decodes passes its caps, and decodes to the
// same value again after it is written.
func FuzzDecode(f *testing.F) {
	for _, v := range fullValues() {
		data, err := json.Marshal(v)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	for _, s := range []string{
		`{"secrets":[{"var":"A","name":"b"}],"command":["x",null],"dir":"","reason":""}`,
		`{"public_key":"AQ==","data":"","flags":1,"binds":["AA==","AA==","AA=="],"commands":[[]],"reason":""}`,
		`{"key":"k","user":"u","hosts":["h"],"seconds":-1,"reason":"r","reason":"s"}`,
		`{"keys":[{"name":"n","public_key":[1]}]}`,
		`{"minutes":1e3}`,
		`{"error":"\u0000"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, v := range allTypes {
			typ := reflect.TypeOf(v)
			got := reflect.New(typ).Interface()
			if err := json.Unmarshal(data, got); err != nil {
				continue
			}
			if c, ok := got.(interface{ Check() error }); ok {
				if err := c.Check(); err != nil {
					t.Errorf("%s: a decoded value fails its caps: %v", typ, err)
				}
			}
			again, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("%s: Marshal: %v", typ, err)
			}
			back := reflect.New(typ).Interface()
			if err := json.Unmarshal(again, back); err != nil {
				t.Fatalf("%s: a written value does not decode: %v", typ, err)
			}
			if !reflect.DeepEqual(got, back) {
				t.Errorf("%s: the round trip changed the value", typ)
			}
		}
	})
}
