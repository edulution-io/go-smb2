package smb2

import (
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/edulution-io/go-smb2/internal/msrpc"
)

// shareEnumFragment builds a response fragment of length n with a valid RPC
// header; level 1 and count go into the first fragment's stub.
func shareEnumFragment(n int, callId, count uint32) []byte {
	b := make([]byte, n)
	b[0] = msrpc.RPC_VERSION
	b[1] = msrpc.RPC_VERSION_MINOR
	b[2] = msrpc.RPC_TYPE_RESPONSE
	binary.LittleEndian.PutUint32(b[12:16], callId)
	if n >= 40 {
		binary.LittleEndian.PutUint32(b[24:28], 1)
		binary.LittleEndian.PutUint32(b[36:40], count)
	}
	return b
}

func TestReadShareEnum(t *testing.T) {
	const callId = 3

	t.Run("complete", func(t *testing.T) {
		read := func(b []byte) (int, error) { return 0, nil }
		r, err := readShareEnum(shareEnumFragment(48, callId, 0), callId, read)
		if err != nil {
			t.Fatal(err)
		}
		if names := r.ShareNameList(); len(names) != 0 {
			t.Errorf("names %q, want none", names)
		}
	})

	// The ioctl output is not bounded by MaxOutputResponse, so an output longer
	// than a fragment made the read buffer slice negative and panicked.
	t.Run("output longer than a fragment", func(t *testing.T) {
		read := func(b []byte) (int, error) { return 0, nil }
		if _, err := readShareEnum(shareEnumFragment(shareEnumFragmentSize+1, callId, 0), callId, read); err == nil {
			t.Fatal("oversized output accepted")
		}
	})

	// A server declaring more entries than it ever sends kept the client reading
	// without end: growing the buffer, or spinning on header-only fragments.
	for _, size := range []int{shareEnumFragmentSize, 24} {
		t.Run("never complete/"+strconv.Itoa(size), func(t *testing.T) {
			reads := 0
			read := func(b []byte) (int, error) {
				reads++
				if reads > maxShareEnumFragments+1 {
					t.Fatal("still reading past the fragment limit")
				}
				return copy(b, shareEnumFragment(min(size, len(b)), callId, 0)), nil
			}
			if _, err := readShareEnum(shareEnumFragment(48, callId, 0xFFFFFFFF), callId, read); err == nil {
				t.Fatal("endless response accepted")
			}
		})
	}

	t.Run("wrong call id", func(t *testing.T) {
		read := func(b []byte) (int, error) { return 0, nil }
		if _, err := readShareEnum(shareEnumFragment(48, callId+1, 0), callId, read); err == nil {
			t.Fatal("foreign call id accepted")
		}
	})
}

func FuzzReadShareEnum(f *testing.F) {
	f.Add(shareEnumFragment(48, 1, 0), shareEnumFragment(64, 1, 0))
	f.Add(shareEnumFragment(48, 1, 2), shareEnumFragment(200, 1, 0))

	f.Fuzz(func(t *testing.T, output, fragment []byte) {
		read := func(b []byte) (int, error) { return copy(b, fragment), nil }
		r, err := readShareEnum(output, 1, read)
		if err == nil {
			_ = r.ShareNameList()
		}
	})
}
