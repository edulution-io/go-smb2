package smb2

import "testing"

// TestPacketCodec_IsInvalid_GuardsShortPackets locks in the precondition that
// session.recv relies on: a short or zero-length packet (as produced by a dead
// connection) is reported invalid, so the caller rejects it structurally
// before comparing header fields such as SessionId against session state that
// may itself still be at its zero value (before a session is established).
func TestPacketCodec_IsInvalid_GuardsShortPackets(t *testing.T) {
	for _, n := range []int{0, 1, 47, 63} {
		if !PacketCodec(make([]byte, n)).IsInvalid() {
			t.Errorf("IsInvalid() = false for a %d-byte packet; want true", n)
		}
	}

	// A well-formed 64-byte SMB2 header must still be accepted.
	hdr := make([]byte, 64)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0xFE, 'S', 'M', 'B' // ProtocolId
	hdr[4] = 64                                          // StructureSize = 64 (LE)
	if PacketCodec(hdr).IsInvalid() {
		t.Error("IsInvalid() = true for a valid 64-byte SMB2 header; want false")
	}
}
