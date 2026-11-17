package ccm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/rand/v2"
	"testing"
)

// byteWiseWrite is the byte-at-a-time Write that the block-wise one replaced.
func byteWiseWrite(m *mac, p []byte) {
	for _, c := range p {
		if m.p >= len(m.ci) {
			m.c.Encrypt(m.ci, m.ci)
			m.p = 0
		}
		m.ci[m.p] ^= c
		m.p++
	}
}

// Write must give the byte-wise result for any split of the input.
func TestMACWriteMatchesByteWise(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	key := make([]byte, 16)
	for i := 0; i < 20000; i++ {
		for j := range key {
			key[j] = byte(r.Uint32())
		}
		c, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		want, got := newMAC(c), newMAC(c)
		for parts := 1 + r.IntN(4); parts > 0; parts-- {
			msg := make([]byte, r.IntN(100))
			for j := range msg {
				msg[j] = byte(r.Uint32())
			}
			byteWiseWrite(want, msg)
			for rest := msg; len(rest) > 0; {
				k := 1 + r.IntN(len(rest))
				_, _ = got.Write(rest[:k])
				rest = rest[k:]
			}
			if r.IntN(2) == 0 {
				want.PadZero()
				got.PadZero()
			}
		}
		if !bytes.Equal(want.Sum(nil), got.Sum(nil)) {
			t.Fatalf("iteration %d: MAC differs from the byte-wise one", i)
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	ccm, err := NewCCMWithNonceAndTagSizes(c, 11, 16)
	if err != nil {
		b.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(c, 12)
	if err != nil {
		b.Fatal(err)
	}
	for _, a := range []struct {
		name string
		aead cipher.AEAD
	}{{"CCM", ccm}, {"GCM", gcm}} {
		for _, n := range []int{64 << 10, 1 << 20} {
			b.Run(fmt.Sprintf("%s/%dKiB", a.name, n>>10), func(b *testing.B) {
				pt := make([]byte, n)
				dst := make([]byte, 0, n+16)
				nonce := make([]byte, a.aead.NonceSize())
				ad := make([]byte, 32)
				b.SetBytes(int64(n))
				b.ReportAllocs()
				for b.Loop() {
					a.aead.Seal(dst[:0], nonce, pt, ad)
				}
			})
		}
	}
}
