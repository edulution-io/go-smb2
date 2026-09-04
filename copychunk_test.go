package smb2

import (
	"encoding/binary"
	"testing"

	. "github.com/edulution-io/go-smb2/internal/smb2"
)

// copyPlan drives copychunkPlanner the way copyTo does -- plan a request,
// report that the server wrote all of it, plan the next -- and returns every
// chunk in the order they were sent. It goes through the planner rather than
// reproducing its arithmetic, so a planner that stops advancing fails here.
func copyPlan(t *testing.T, srcOff, dstOff, size int64, l copychunkLimits) []*SrvCopychunk {
	t.Helper()

	plan := newCopychunkPlanner(srcOff, dstOff, size)
	plan.narrow(l)

	var (
		all      []*SrvCopychunk
		requests int
	)
	for !plan.done() {
		chunks, planned := plan.next()
		if planned <= 0 {
			t.Fatalf("request %d planned %d bytes with %d left of %d", requests, planned, plan.remains, size)
		}
		all = append(all, chunks...)

		if err := plan.advance(planned, planned); err != nil {
			t.Fatalf("request %d: %v", requests, err)
		}

		requests++
		if requests > 1000 {
			t.Fatalf("still going after %d requests, %d of %d bytes copied", requests, plan.copied, size)
		}
	}

	if plan.copied != size {
		t.Fatalf("planner copied %d bytes, want %d", plan.copied, size)
	}
	return all
}

// assertCovers checks that the chunks copy [srcOff, srcOff+size) to
// [dstOff, dstOff+size) exactly once, contiguously and in order.
//
// The whole point: a plan that restarts at the beginning of the file on its
// second request still adds up to the right number of bytes, and only the
// offsets say so.
func assertCovers(t *testing.T, chunks []*SrvCopychunk, srcOff, dstOff, size int64) {
	t.Helper()

	var at int64
	for i, c := range chunks {
		if c.Length == 0 {
			t.Fatalf("chunk %d is empty", i)
		}
		if c.SourceOffset != srcOff+at {
			t.Fatalf("chunk %d reads at %d, want %d", i, c.SourceOffset, srcOff+at)
		}
		if c.TargetOffset != dstOff+at {
			t.Fatalf("chunk %d writes at %d, want %d", i, c.TargetOffset, dstOff+at)
		}
		at += int64(c.Length)
	}
	if at != size {
		t.Fatalf("chunks cover %d bytes, want %d", at, size)
	}
}

func TestPlanCopychunksCoversTheWholeFile(t *testing.T) {
	l := defaultCopychunkLimits
	oneRequest := int64(l.totalSize)

	sizes := []int64{
		1,
		int64(l.chunkSize) - 1,
		int64(l.chunkSize),
		int64(l.chunkSize) + 1,
		oneRequest - 1,
		oneRequest,
		// The sizes that a plan restarting from the top of the file gets wrong:
		// everything past the first request's worth.
		oneRequest + 1,
		oneRequest + int64(l.chunkSize),
		3*oneRequest + 12345,
		50 * 1024 * 1024, // the handout from #100
	}

	for _, size := range sizes {
		t.Run(byteCount(size), func(t *testing.T) {
			assertCovers(t, copyPlan(t, 0, 0, size, l), 0, 0, size)
		})
	}
}

// TestPlanCopychunksFromNonZeroOffsets covers a partially read source and a
// destination being appended to: the two offsets move independently, and only
// the distance each has travelled from its own start is shared.
func TestPlanCopychunksFromNonZeroOffsets(t *testing.T) {
	const (
		srcOff = 4096
		dstOff = 7
		size   = 40 * 1024 * 1024
	)

	assertCovers(t, copyPlan(t, srcOff, dstOff, size, defaultCopychunkLimits), srcOff, dstOff, size)
}

// TestPlanCopychunksRespectsLimits checks the three bounds a server can narrow.
func TestPlanCopychunksRespectsLimits(t *testing.T) {
	l := copychunkLimits{chunks: 3, chunkSize: 100, totalSize: 1000}

	chunks, planned := planCopychunks(0, 0, 10000, l)
	if len(chunks) != 3 {
		t.Fatalf("planned %d chunks, want the 3 the server allows", len(chunks))
	}
	if planned != 300 {
		t.Fatalf("planned %d bytes, want 300 (3 chunks of 100)", planned)
	}
	for i, c := range chunks {
		if c.Length != 100 {
			t.Fatalf("chunk %d is %d bytes, want the 100 the server allows", i, c.Length)
		}
	}

	// totalSize binding before the chunk count does.
	l = copychunkLimits{chunks: 16, chunkSize: 100, totalSize: 250}
	chunks, planned = planCopychunks(0, 0, 10000, l)
	if planned != 250 {
		t.Fatalf("planned %d bytes, want the 250 the server allows in one request", planned)
	}
	if len(chunks) != 3 || chunks[2].Length != 50 {
		t.Fatalf("planned %d chunks ending in %d bytes, want 3 ending in 50", len(chunks), chunks[len(chunks)-1].Length)
	}

	// A remainder shorter than the limits is not padded up to them.
	chunks, planned = planCopychunks(0, 0, 30, l)
	if planned != 30 || len(chunks) != 1 || chunks[0].Length != 30 {
		t.Fatalf("planned %d bytes in %d chunks, want 30 in 1", planned, len(chunks))
	}
}

// TestPlanCopychunksPlansNothingForNothing pins the case copyTo must never send:
// a request carrying no chunks is a limits probe, and Samba answers it
// STATUS_INVALID_PARAMETER.
func TestPlanCopychunksPlansNothingForNothing(t *testing.T) {
	for _, remains := range []int64{0, -1} {
		chunks, planned := planCopychunks(0, 0, remains, defaultCopychunkLimits)
		if len(chunks) != 0 || planned != 0 {
			t.Fatalf("remains=%d planned %d chunks covering %d bytes, want none", remains, len(chunks), planned)
		}
	}
}

// TestCopychunkPlannerRejectsImpossibleProgress pins what a copy cannot survive
// believing: a server reporting no progress would leave the loop re-sending the
// same request forever, and one reporting more than was asked for would skip
// bytes nothing has copied.
func TestCopychunkPlannerRejectsImpossibleProgress(t *testing.T) {
	cases := []struct {
		name             string
		written, planned int64
		wantErr          bool
	}{
		{"the whole request", 1000, 1000, false},
		{"a short write the server is allowed", 400, 1000, false},
		{"no progress", 0, 1000, true},
		{"a negative count", -1, 1000, true},
		{"more than was asked for", 1001, 1000, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := newCopychunkPlanner(0, 0, 4000)
			err := plan.advance(c.written, c.planned)

			if c.wantErr {
				if err == nil {
					t.Fatalf("advance(%d, %d) was accepted", c.written, c.planned)
				}
				if plan.copied != 0 {
					t.Fatalf("a rejected report still advanced the copy to %d", plan.copied)
				}
				return
			}

			if err != nil {
				t.Fatalf("advance(%d, %d): %v", c.written, c.planned, err)
			}
			if plan.copied != c.written {
				t.Fatalf("copied %d, want %d", plan.copied, c.written)
			}
		})
	}
}

// TestCopychunkPlannerNarrowsWithoutLosingProgress covers the renegotiation
// path: a server rejects the first request with smaller limits, and the copy
// has to resume from where it was rather than from the top of the file.
func TestCopychunkPlannerNarrowsWithoutLosingProgress(t *testing.T) {
	const size = 40 * 1024 * 1024

	plan := newCopychunkPlanner(0, 0, size)

	// One request at the assumed limits lands.
	chunks, planned := plan.next()
	if err := plan.advance(planned, planned); err != nil {
		t.Fatal(err)
	}
	all := chunks

	// Then the server asks for less, and the rest goes out re-chunked.
	plan.narrow(copychunkLimits{chunks: 2, chunkSize: 512 * 1024, totalSize: 1024 * 1024})

	for requests := 0; !plan.done(); requests++ {
		if requests > 1000 {
			t.Fatalf("still going after %d requests", requests)
		}
		chunks, planned := plan.next()
		if planned > 1024*1024 {
			t.Fatalf("request %d covers %d bytes, more than the server now allows", requests, planned)
		}
		all = append(all, chunks...)
		if err := plan.advance(planned, planned); err != nil {
			t.Fatal(err)
		}
	}

	assertCovers(t, all, 0, 0, size)
}

func TestCopychunkLimitsFrom(t *testing.T) {
	response := func(chunks, chunkSize, total uint32) []byte {
		b := make([]byte, 12)
		binary.LittleEndian.PutUint32(b[0:4], chunks)
		binary.LittleEndian.PutUint32(b[4:8], chunkSize)
		binary.LittleEndian.PutUint32(b[8:12], total)
		return b
	}

	t.Run("limits the server sent", func(t *testing.T) {
		l, ok := copychunkLimitsFrom(response(4, 512, 2048))
		if !ok {
			t.Fatal("rejected a well-formed response")
		}
		if l != (copychunkLimits{chunks: 4, chunkSize: 512, totalSize: 2048}) {
			t.Fatalf("read %+v", l)
		}
	})

	t.Run("short buffer", func(t *testing.T) {
		if _, ok := copychunkLimitsFrom(make([]byte, 11)); ok {
			t.Fatal("accepted a response too short to decode")
		}
	})

	// A zero in any field would plan requests that copy nothing, forever.
	t.Run("a zero limit is not usable", func(t *testing.T) {
		for i, r := range [][]byte{
			response(0, 512, 2048),
			response(4, 0, 2048),
			response(4, 512, 0),
		} {
			if _, ok := copychunkLimitsFrom(r); ok {
				t.Fatalf("case %d: accepted limits that allow no progress", i)
			}
		}
	})
}

func byteCount(n int64) string {
	switch {
	case n%(1024*1024) == 0:
		return itoa(n/(1024*1024)) + "MiB"
	case n%1024 == 0:
		return itoa(n/1024) + "KiB"
	default:
		return itoa(n) + "B"
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
