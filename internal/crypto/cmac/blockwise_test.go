package cmac

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"math/rand/v2"
	"testing"
)

// byteWiseWrite is the byte-at-a-time Write that the block-wise one replaced.
func byteWiseWrite(d *cmac, p []byte) {
	for _, c := range p {
		if d.p >= len(d.ci) {
			d.c.Encrypt(d.ci, d.ci)
			d.p = 0
		}
		d.ci[d.p] ^= c
		d.p++
	}
}

// Write must give the byte-wise result for any split of the input, including
// input that ends on a block boundary, where Sum uses the other subkey.
func TestWriteMatchesByteWise(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	key := make([]byte, 16)
	for i := 0; i < 20000; i++ {
		for j := range key {
			key[j] = byte(r.Uint32())
		}
		c, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		want, got := New(c).(*cmac), New(c).(*cmac)
		for parts := 1 + r.IntN(4); parts > 0; parts-- {
			msg := make([]byte, 16*r.IntN(5)+r.IntN(2)*r.IntN(16))
			for j := range msg {
				msg[j] = byte(r.Uint32())
			}
			byteWiseWrite(want, msg)
			for rest := msg; len(rest) > 0; {
				k := 1 + r.IntN(len(rest))
				_, _ = got.Write(rest[:k])
				rest = rest[k:]
			}
		}
		if !bytes.Equal(want.Sum(nil), got.Sum(nil)) {
			t.Fatalf("iteration %d: CMAC differs from the byte-wise one", i)
		}
	}
}

func BenchmarkCMAC(b *testing.B) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatal(err)
	}
	h := New(c)
	for _, n := range []int{64 << 10, 1 << 20} {
		b.Run(fmt.Sprintf("%dKiB", n>>10), func(b *testing.B) {
			msg := make([]byte, n)
			sum := make([]byte, 0, h.Size())
			b.SetBytes(int64(n))
			b.ReportAllocs()
			for b.Loop() {
				h.Reset()
				_, _ = h.Write(msg)
				sum = h.Sum(sum[:0])
			}
		})
	}
}
