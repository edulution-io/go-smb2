package smb2

import "testing"

// MS-FSCC 2.4.11 defines FILE_DISPOSITION_INFORMATION as a single BOOLEAN.
// Size feeds InputBufferLength (request.go:1275), so reporting 4 declared
// three padding bytes as payload on every SMB2 SET_INFO that deletes a file.
// Samba tolerates it; stricter servers answer STATUS_INFO_LENGTH_MISMATCH.
func TestFileDispositionInformationEncoderSize(t *testing.T) {
	e := &FileDispositionInformationEncoder{DeletePending: 1}

	if got := e.Size(); got != 1 {
		t.Errorf("Size() = %d, want 1", got)
	}

	p := make([]byte, e.Size())
	e.Encode(p)
	if p[0] != 1 {
		t.Errorf("Encode wrote DeletePending = %d, want 1", p[0])
	}
}
