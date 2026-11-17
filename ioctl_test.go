package smb2

import (
	"encoding/binary"
	"testing"

	. "github.com/edulution-io/go-smb2/internal/smb2"
)

func ioctlResponse(outputLen int) IoctlResponseDecoder {
	b := make([]byte, 48+outputLen)
	binary.LittleEndian.PutUint16(b[0:2], 49)                  // StructureSize
	binary.LittleEndian.PutUint32(b[32:36], 64+48)             // OutputOffset
	binary.LittleEndian.PutUint32(b[36:40], uint32(outputLen)) // OutputCount
	return IoctlResponseDecoder(b)
}

// The server must not return more output than MaxOutputResponse; callers that
// size buffers on it used to get whatever length the server sent.
func TestIoctlOutputBoundedByMaxOutputResponse(t *testing.T) {
	r := ioctlResponse(16)
	if r.IsInvalid() {
		t.Fatal("test response is invalid")
	}

	if out, err := ioctlOutput(r, 16, nil); err != nil || len(out) != 16 {
		t.Errorf("output within the limit: got %d bytes, %v", len(out), err)
	}
	if _, err := ioctlOutput(r, 15, nil); err == nil {
		t.Error("output past the limit accepted")
	}
}
