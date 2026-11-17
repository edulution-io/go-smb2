package smb2

import (
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// A pipelined read used to keep every response until the whole transfer had
// finished, holding about the size of the read again in buffers. Chunks are
// now copied as they arrive, so only those in flight stay alive.
func TestPipelinedReadReleasesResponses(t *testing.T) {
	const size = 32 << 20 // 512 chunks of 64 KiB

	files := &fakeFiles{data: make([]byte, size)}
	for i := range files.data {
		files.data[i] = byte(i)
	}
	sess, err := dialFake(t, &fakeServer{files: files})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.s.t.Close() }()

	share, err := sess.Mount("share")
	if err != nil {
		t.Fatal(err)
	}
	f, err := share.OpenFile("file", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	b := make([]byte, size)

	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc

	// Sample the live heap while the read runs.
	var peak atomic.Uint64
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
			runtime.GC()
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak.Load() {
				peak.Store(ms.HeapAlloc)
			}
		}
	}()

	n, err := f.ReadAt(b, 0)
	close(stop)
	<-sampled
	if err != nil || n != size {
		t.Fatalf("ReadAt: %d, %v", n, err)
	}

	if extra := int64(peak.Load()) - int64(base); extra > size/4 {
		t.Errorf("the read held %d MiB of responses alive, for a %d MiB read", extra>>20, size>>20)
	}
}
