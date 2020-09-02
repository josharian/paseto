// +build gofuzz

package paseto

import (
	"bytes"
)

var (
	nonce = bytes.Repeat([]byte("-"), 24)
	key   = bytes.Repeat([]byte("*"), 32)
)

func Fuzz(data []byte) int {
	// Avoid pounding on the OSCSPRNG, and increase reproducibility.
	randRead = bytes.NewBuffer(nonce).Read
	payload := data
	var footer []byte
	if len(data) > 0 && data[0]%2 == 1 {
		footer = data
	}
	token, err := Encrypt(payload, key, footer)
	if err != nil {
		panic(err)
	}
	p, f, ok := Decrypt(token, key)
	if !ok {
		panic("round trip failed")
	}
	if !bytes.Equal(p, payload) {
		panic("round trip p failed")
	}
	if !bytes.Equal(f, footer) {
		panic("round trip f failed")
	}

	// TODO: test other things
	// TODO: test against an external implementation, e.g. o1egl
	// TODO: negative tests
	return 0
}
