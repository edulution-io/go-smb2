package smb2

import "testing"

// TestPacketCodec_IsInvalid_GuardsShortPackets locks in the precondition that
// session.recv relies on: a short or zero-length packet (as produced by a dead
// connection) is reported invalid, so callers reject it before reading header
// fields. Without that gate, fixed-offset accessors such as SessionId
// (pkt[40:48]) slice past the buffer and panic with "slice bounds out of range",
// crashing any goroutine that lacks a recover.
func TestPacketCodec_IsInvalid_GuardsShortPackets(t *testing.T) {
	// These are exactly the buffers that previously panicked SessionId().
	for _, n := range []int{0, 1, 47, 63} {
		if !PacketCodec(make([]byte, n)).IsInvalid() {
			t.Errorf("IsInvalid() = false for a %d-byte packet; want true (SessionId would panic on it)", n)
		}
	}

	// A well-formed 64-byte SMB2 header must still be accepted.
	hdr := make([]byte, 64)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0xFE, 'S', 'M', 'B' // ProtocolId
	hdr[4] = 64                                          // StructureSize = 64 (LE)
	if PacketCodec(hdr).IsInvalid() {
		t.Error("IsInvalid() = true for a valid 64-byte SMB2 header; want false")
	}
	// And the accessor it guards must not panic on a valid header.
	_ = PacketCodec(hdr).SessionId()
}
