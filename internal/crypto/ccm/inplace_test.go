package ccm

import (
	"bytes"
	"crypto/aes"
	"math/rand/v2"
	"testing"
)

// cipher.AEAD allows plaintext[:0] as dst. Seal used to take the tag after
// encrypting, so sealing in place authenticated the ciphertext instead.
func TestSealInPlace(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 8))
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := NewCCMWithNonceAndTagSizes(c, 11, 16)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 1000; i++ {
		nonce := make([]byte, aead.NonceSize())
		data := make([]byte, r.IntN(64))
		plaintext := make([]byte, 1+r.IntN(300)) // Open rejects a bare tag
		for _, b := range [][]byte{nonce, data, plaintext} {
			for j := range b {
				b[j] = byte(r.Uint32())
			}
		}

		want := aead.Seal(nil, nonce, plaintext, data)

		buf := make([]byte, len(plaintext), len(plaintext)+aead.Overhead())
		copy(buf, plaintext)
		got := aead.Seal(buf[:0], nonce, buf, data)

		if !bytes.Equal(got, want) {
			t.Fatalf("iteration %d: in-place Seal differs", i)
		}
		if _, err := aead.Open(nil, nonce, got, data); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}
