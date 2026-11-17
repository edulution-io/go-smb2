package smb2_test

import (
	"bytes"
	"io"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"
)

// Reads and writes larger than one chunk keep several requests in flight; the
// data must still land where it belongs, and a read past the end of the file
// must stop exactly at it.
func TestPipelinedReadWrite(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	const size = 10<<20 + 12345 // several chunks and a partial one
	want := make([]byte, size)
	r := rand.New(rand.NewPCG(9, 10))
	for i := range want {
		want[i] = byte(r.Uint32())
	}

	name := "pipelined-" + strconv.Itoa(os.Getpid())
	f, err := fs.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fs.Remove(name) }()
	defer func() { _ = f.Close() }()

	if n, err := f.WriteAt(want, 0); err != nil || n != size {
		t.Fatalf("WriteAt: %d, %v", n, err)
	}

	got := make([]byte, size+3<<20) // reaches past the end of the file
	n, err := f.ReadAt(got, 0)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if n != size || !bytes.Equal(got[:n], want) {
		t.Fatalf("ReadAt returned %d bytes, want %d, equal=%v", n, size, bytes.Equal(got[:min(n, size)], want[:min(n, size)]))
	}

	// From an unaligned offset into the middle of the file.
	const off = 1<<20 + 7
	part := make([]byte, 5<<20)
	if n, err := f.ReadAt(part, off); err != nil || n != len(part) || !bytes.Equal(part, want[off:off+len(part)]) {
		t.Fatalf("ReadAt at %d: %d, %v", off, n, err)
	}

	// Sequential Read through the whole file.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(f)
	if err != nil || !bytes.Equal(all, want) {
		t.Fatalf("ReadAll: %d bytes, %v", len(all), err)
	}
}

// BenchmarkTransfer reads and writes 16 MiB through ReadAt and WriteAt; run
// it against a server with latency to see the effect of pipelining.
func BenchmarkTransfer(b *testing.B) {
	if fs == nil {
		b.Skip()
	}

	const size = 16 << 20
	buf := make([]byte, size)
	name := "transfer-" + strconv.Itoa(os.Getpid())
	f, err := fs.Create(name)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = fs.Remove(name) }()
	defer func() { _ = f.Close() }()

	b.Run("WriteAt", func(b *testing.B) {
		b.SetBytes(size)
		for b.Loop() {
			if _, err := f.WriteAt(buf, 0); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ReadAt", func(b *testing.B) {
		b.SetBytes(size)
		for b.Loop() {
			if _, err := f.ReadAt(buf, 0); err != nil && err != io.EOF {
				b.Fatal(err)
			}
		}
	})
}
