// Package paseto implements PASETO v2.local.
//
// See https://paseto.io/ for details.
//
// It has NOT been reviewed by a cryptographer.
// Use at your own risk.
package paseto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// TODO: accept a *[32]byte key instead of a slice?

var randRead = rand.Read // testing hook for nonce control

func Encrypt(message []byte, key []byte, footer []byte) ([]byte, error) {
	// https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#encrypt

	// Change variable names to match the docs.
	m := message
	k := key
	f := footer
	// Set up our aead object. We'll use it later.
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	// 1. Set header h to v2.local.
	h := v2local
	// nc is the concatenation of n and c (to be defined soon).
	// We allocate it up front to minimize allocation.
	// We also abuse it as a temporary buffer for nonce calculation.
	nc := make([]byte, 0, 24+len(m)+aead.Overhead())
	// 2. Generate 24 random bytes from the OS's CSPRNG.
	buf := nc[:24]
	if _, err := randRead(buf); err != nil {
		return nil, err
	}
	// 3. Calculate BLAKE2b of the message m with the output of step 2 as the key,
	// with an output length of 24. This will be our nonce, n.
	hash, err := blake2b.New(24, buf)
	if err != nil {
		return nil, err
	}
	hash.Write(m)
	// Place n at the beginning of nc.
	// At this point, n == nc.
	nc = hash.Sum(nc)

	// 4. Pack h, n, and f together (in that order) using PAE. We'll call this preAuth.
	preAuth := pae(h, nc, f)
	// 5. Encrypt the message using XChaCha20-Poly1305,
	// using an AEAD interface such as the one provided in libsodium.
	//   c = crypto_aead_xchacha20poly1305_encrypt(
	//   	message = m
	//   	aad = preAuth
	//   	nonce = n
	//   	key = k
	//   );
	nc = aead.Seal(nc, nc, m, preAuth) // append the result (c) to nc; now nc == concat(n, c)
	// 6. If f is:
	//      Empty: return h || b64(n || c)
	//      Non-empty: return h || b64(n || c) || . || base64url(f)
	//      ...where || means "concatenate"
	outlen := len(h) + base64.RawURLEncoding.EncodedLen(len(nc))
	if len(f) > 0 {
		outlen += 1 + base64.RawURLEncoding.EncodedLen(len(f)) // 1 for '.'
	}
	out := make([]byte, outlen)
	off := copy(out, h)
	base64.RawURLEncoding.Encode(out[off:], nc)
	off += base64.RawURLEncoding.EncodedLen(len(nc))
	if len(f) > 0 {
		out[off] = '.'
		off++
		base64.RawURLEncoding.Encode(out[off:], f)
	}
	return out, nil
}

func Decrypt(token []byte, key []byte) (payload, footer []byte, ok bool) {
	// https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Version2.md#decrypt

	// Change variable names to match the docs.
	m := token
	k := key

	// 1. If f is not empty, implementations MAY verify that the value
	// appended to the token matches some expected string f,
	// provided they do so using a constant-time string compare function.

	// We don't verify f.

	// 2. Verify that the message begins with v2.local., otherwise throw an exception.
	// This constant will be referred to as h.
	h := v2local
	if !bytes.HasPrefix(m, h) {
		return nil, nil, false
	}
	m = m[len(h):]

	// 3. Decode the payload (m sans h, f, and the optional trailing period between m and f)
	// from base64url to raw binary. Set:
	//   n to the leftmost 24 bytes
	//   c to the middle remainder of the payload, excluding n.

	// There should be at most one "." in m, separating the payload and the footer.
	// Both payload and footer are base64-encoded, and "." is not a part of that encoding.
	// So here we simply decide where to split, and let base64 decoding detect any extraneous ".".
	if i := bytes.IndexByte(m, '.'); i >= 0 {
		// Footer is present. Decode it. And adjust m.
		footer, ok = decodeBase64(m[i+1:])
		if !ok {
			return nil, nil, false
		}
		m = m[:i]
	}
	raw, ok := decodeBase64(m)
	if !ok {
		return nil, nil, false
	}
	n := raw[:24]
	c := raw[24:]

	// 4. Pack h, n, and f together (in that order) using PAE. We'll call this preAuth
	preAuth := pae(h, n, footer)

	// 5. Decrypt c using XChaCha20-Poly1305, store the result in p.
	//       p = crypto_aead_xchacha20poly1305_decrypt(
	//          ciphertext = c
	//          aad = preAuth
	//          nonce = n
	//          key = k
	//       );
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, nil, false
	}

	// It is tempting to optimize by passing in a buffer here.
	// But we have to take care: We return payload and footer to the caller,
	// so we don't want either of them to pin a lot of extra memory, or leak anything.
	// For now, be conservative and start from scratch.
	payload, err = aead.Open(nil, n, c, preAuth)
	if err != nil {
		return nil, nil, false
	}

	// 6. If decryption failed, throw an exception. Otherwise, return p.
	return payload, footer, true
}

func decodeBase64(src []byte) ([]byte, bool) {
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(src)))
	n, err := base64.RawURLEncoding.Decode(dst, src)
	if err != nil {
		return nil, false
	}
	dst = dst[:n]
	return dst, true
}

func pae(bb ...[]byte) []byte {
	// https://github.com/paragonie/paseto/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition

	// Size required is 8 bytes for len(bb),
	// plus 8 bytes for each element of bb,
	// plus whatever is required for the elements of bb.
	n := 8 + 8*len(bb)
	for _, b := range bb {
		n += len(b)
	}
	buf := make([]byte, n)
	le64(len(bb), buf[:8])
	off := 8
	for _, b := range bb {
		le64(len(b), buf[off:off+8])
		off += 8
		copy(buf[off:], b)
		off += len(b)
	}
	return buf
}

func le64(n int, b []byte) {
	u := uint64(n) << 1 >> 1 // clear MSB
	binary.LittleEndian.PutUint64(b, u)
}

var v2local = []byte("v2.local.")
