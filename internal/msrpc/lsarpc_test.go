package msrpc

import "testing"

// buildLookupSidsResponse builds an RPC response PDU carrying stub bytes, with the
// header fields ReturnValue reads.
func buildLookupSidsResponse(stub []byte, fragLength, authLength uint16) []byte {
	b := make([]byte, 24+len(stub))
	b[0] = RPC_VERSION
	b[1] = RPC_VERSION_MINOR
	b[2] = RPC_TYPE_RESPONSE
	le.PutUint16(b[8:10], fragLength)
	le.PutUint16(b[10:12], authLength)
	le.PutUint32(b[12:16], 42) // call id
	copy(b[24:], stub)
	return b
}

func TestLsarLookupSidsResponseDecoderReturnValue(t *testing.T) {
	// Minimal well-formed stub: no referenced domains, no translated names, then
	// MappedCount and the NTSTATUS.
	stub := []byte{
		0x00, 0x00, 0x00, 0x00, // ReferencedDomains pointer (null)
		0x00, 0x00, 0x00, 0x00, // TranslatedNames.Entries
		0x00, 0x00, 0x00, 0x00, // TranslatedNames pointer (null)
		0x02, 0x00, 0x00, 0x00, // MappedCount
		0x07, 0x01, 0x00, 0x00, // STATUS_SOME_NOT_MAPPED
	}

	tests := []struct {
		name string
		pdu  []byte
		want uint32
	}{
		{
			name: "frag length covers the whole pdu",
			pdu:  buildLookupSidsResponse(stub, uint16(24+len(stub)), 0),
			want: 0x00000107,
		},
		{
			name: "trailing bytes past frag length are ignored",
			pdu:  buildLookupSidsResponse(append(stub, 0xde, 0xad, 0xbe, 0xef), uint16(24+len(stub)), 0),
			want: 0x00000107,
		},
		{
			name: "implausible frag length falls back to the buffer end",
			pdu:  buildLookupSidsResponse(stub, 0xffff, 0),
			want: 0x00000107,
		},
		{
			// An auth verifier is 8 header bytes plus AuthLength trailer bytes, all
			// of which sit behind the status.
			name: "auth verifier is skipped",
			pdu: buildLookupSidsResponse(
				append(append([]byte{}, stub...), make([]byte, 8+16)...),
				uint16(24+len(stub)+8+16), 16),
			want: 0x00000107,
		},
		{
			name: "pdu too short to carry a status",
			pdu:  buildLookupSidsResponse(stub[:len(stub)-4], uint16(24+len(stub)-4), 0),
			want: 0xFFFFFFFF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := LsarLookupSidsResponseDecoder(tt.pdu)
			if d.IsInvalid() {
				t.Fatalf("IsInvalid() = true, want a decodable response")
			}
			if got := d.ReturnValue(); got != tt.want {
				t.Errorf("ReturnValue() = 0x%08X, want 0x%08X", got, tt.want)
			}
		})
	}
}
