package paseto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// These tests and benchmark were adapted from github.com/o1egl/paseto,
// with relatively minimal changes.
// The rationale behind borrowing them was to attempt to ensure compatibility,
// and to make benchmark apples-to-apples (as much as possible).

func TestPasetoV2_Encrypt_Compatibility(t *testing.T) {
	nullKey := bytes.Repeat([]byte{0}, 32)
	fullKey := bytes.Repeat([]byte{0xff}, 32)
	symmetricKey, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	nonce := bytes.Repeat([]byte{0}, 24)
	nonce2, _ := hex.DecodeString("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")
	footer := []byte("Cuon Alpinus")
	payload := []byte("Love is stronger than hate or fear")

	cases := map[string]struct {
		key     []byte
		token   string
		nonce   []byte
		payload []byte
		footer  []byte
	}{
		"Empty message, empty footer, empty nonce, null key": {
			key:   nullKey,
			token: "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ",
			nonce: nonce,
		},
		"Empty message, empty footer, empty nonce, full key": {
			key:   fullKey,
			token: "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg",
			nonce: nonce,
		},
		"Empty message, empty footer, empty nonce, symmetric key": {
			key:   symmetricKey,
			token: "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA",
			nonce: nonce,
		},
		"Empty message, non-empty footer, empty nonce, null key": {
			key:    nullKey,
			token:  "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz",
			nonce:  nonce,
			footer: footer,
		},
		"Empty message, non-empty footer, empty nonce, full key": {
			key:    fullKey,
			token:  "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz",
			nonce:  nonce,
			footer: footer,
		},
		"Empty message, non-empty footer, empty nonce, symmetric key": {
			key:    symmetricKey,
			token:  "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz",
			nonce:  nonce,
			footer: footer,
		},
		"Non-empty message, empty footer, empty nonce, null key": {
			key:     nullKey,
			token:   "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0",
			nonce:   nonce,
			payload: payload,
		},
		"Non-empty message, empty footer, empty nonce, full key": {
			key:     fullKey,
			token:   "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw",
			nonce:   nonce,
			payload: payload,
		},
		"Non-empty message, empty footer, empty nonce, symmetric key": {
			key:     symmetricKey,
			token:   "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U",
			nonce:   nonce,
			payload: payload,
		},
		"Non-empty message, non-empty footer, non-empty nonce, null key": {
			key:     nullKey,
			token:   "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz",
			nonce:   nonce2,
			payload: payload,
			footer:  footer,
		},
		"Non-empty message, non-empty footer, non-empty nonce, full key": {
			key:     fullKey,
			token:   "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz",
			nonce:   nonce2,
			payload: payload,
			footer:  footer,
		},
		"Non-empty message, non-empty footer, non-empty nonce, symmetric key": {
			key:     symmetricKey,
			token:   "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz",
			nonce:   nonce2,
			payload: payload,
			footer:  footer,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			randRead = bytes.NewBuffer(test.nonce).Read
			token, err := Encrypt(test.payload, test.key, test.footer)
			if err != nil {
				t.Fatal(err)
			}
			if test.token != string(token) {
				t.Fatalf("%q != %q", test.token, string(token))
			}
		})
	}
	randRead = rand.Read
}

func TestEncryptDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")

	testPayload := []byte("payload")
	testFooter := []byte("footer")

	token, err := Encrypt(testPayload, key, testFooter)
	if err != nil {
		t.Fatal(err)
	}
	obtainedPayload, obtainedFooter, ok := Decrypt(token, key)
	if !ok {
		t.Fatal("round trip failed")
	}
	if string(testPayload) != string(obtainedPayload) {
		t.Errorf("payload %q != %q", string(testPayload), string(obtainedPayload))
	}
	if string(testFooter) != string(obtainedFooter) {
		t.Errorf("footer %q != %q", string(testFooter), string(obtainedFooter))
	}
}

func Benchmark_V2_String_Encrypt(b *testing.B) {
	symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")

	var (
		payload = []byte("payload")
		footer  = []byte("footer")
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt(payload, symmetricKey, footer)
	}
}

func Benchmark_V2_String_Decrypt(b *testing.B) {
	symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	token := []byte("v2.local.VxvYfYL-KSCBaNC8toZUWgoqYHveHjypGx87pqUi0e69gKNAApe3sVkAog30zAc.Zm9vdGVy")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Decrypt(token, symmetricKey)
	}
}
