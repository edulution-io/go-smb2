package msrpc

import (
	"runtime"
	"testing"
)

// buildLookupSidsResponse builds an RPC response PDU carrying stub bytes, with the
// header fields ReturnValue reads. The PDU is a complete response in one fragment,
// which is what a server sends for a reply that fits.
func buildLookupSidsResponse(stub []byte, fragLength, authLength uint16) []byte {
	b := make([]byte, 24+len(stub))
	b[0] = RPC_VERSION
	b[1] = RPC_VERSION_MINOR
	b[2] = RPC_TYPE_RESPONSE
	b[3] = RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST
	le.PutUint16(b[8:10], fragLength)
	le.PutUint16(b[10:12], authLength)
	le.PutUint32(b[12:16], 42) // call id
	copy(b[24:], stub)
	return b
}

// buildAuthenticatedResponse builds a response PDU whose stub is followed by
// padLength padding bytes, an 8-byte sec_trailer and an authLength-byte token.
func buildAuthenticatedResponse(stub []byte, padLength, authLength int) []byte {
	verifier := make([]byte, padLength+8+authLength)
	verifier[padLength+2] = byte(padLength) // sec_trailer.auth_pad_length
	body := append(append([]byte{}, stub...), verifier...)
	return buildLookupSidsResponse(body, uint16(24+len(body)), uint16(authLength))
}

// withoutLastFragFlag turns a PDU into the first fragment of a fragmented reply.
func withoutLastFragFlag(pdu []byte) []byte {
	pdu[3] &^= RPC_PACKET_FLAG_LAST
	return pdu
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
			// The server declared more bytes than arrived. Reading the buffer end
			// anyway lands wherever the truncation left off -- on a zero-padded stub
			// that reads as STATUS_SUCCESS, which is the one thing this must never do.
			name: "frag length longer than the pdu is truncation",
			pdu:  buildLookupSidsResponse(stub, 0xffff, 0),
			want: NoReturnValue,
		},
		{
			// The status is the last field of the last fragment, and this client does
			// not read the rest of a fragmented reply.
			name: "non-final fragment carries no status",
			pdu:  withoutLastFragFlag(buildLookupSidsResponse(stub, uint16(24+len(stub)), 0)),
			want: NoReturnValue,
		},
		{
			// An auth verifier is an 8-byte sec_trailer plus AuthLength token bytes,
			// all of which sit behind the status.
			name: "auth verifier is skipped",
			pdu:  buildAuthenticatedResponse(stub, 0, 16),
			want: 0x00000107,
		},
		{
			// auth_pad_length bytes sit between the stub and the sec_trailer and are
			// not counted by AuthLength; missing them reads padding as the status.
			name: "auth padding is skipped",
			pdu:  buildAuthenticatedResponse(stub, 12, 16),
			want: 0x00000107,
		},
		{
			name: "auth verifier larger than the pdu",
			pdu:  buildLookupSidsResponse(stub, uint16(24+len(stub)), 0xffff),
			want: NoReturnValue,
		},
		{
			name: "pdu too short to carry a status",
			pdu:  buildLookupSidsResponse(stub[:len(stub)-4], uint16(24+len(stub)-4), 0),
			want: NoReturnValue,
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

// ReturnValue is exported on an exported type, so it has to hold up on a buffer
// that never passed IsInvalid: every length below the minimum must report
// NoReturnValue instead of panicking on a header read.
func TestLsarLookupSidsResponseDecoderReturnValueShortBuffer(t *testing.T) {
	full := buildLookupSidsResponse(make([]byte, 20), 44, 0)

	for n := 0; n < len(full); n++ {
		if got := LsarLookupSidsResponseDecoder(full[:n]).ReturnValue(); got != NoReturnValue {
			t.Errorf("ReturnValue() on %d bytes = 0x%08X, want NoReturnValue", n, got)
		}
	}
}

// Results must not read past the declared stub end: the STATUS_BUFFER_OVERFLOW
// re-read appends a whole transact's worth of buffer behind the PDU, and
// ReturnValue already excludes it.
func TestResultsStopsAtDeclaredStubEnd(t *testing.T) {
	stub := []byte{
		0x00, 0x00, 0x00, 0x00, // ReferencedDomains pointer (null)
		0x00, 0x00, 0x00, 0x00, // TranslatedNames.Entries
		0x00, 0x00, 0x00, 0x00, // TranslatedNames pointer (null)
		0x00, 0x00, 0x00, 0x00, // MappedCount
		0x00, 0x00, 0x00, 0x00, // STATUS_SUCCESS
	}
	fragLen := uint16(24 + len(stub))

	// A second PDU's worth of bytes behind the first, as a short re-read leaves.
	trailing := make([]byte, 64)
	for i := range trailing {
		trailing[i] = 0xAA
	}
	pdu := buildLookupSidsResponse(append(append([]byte{}, stub...), trailing...), fragLen, 0)

	results, err := LsarLookupSidsResponseDecoder(pdu).Results()
	if err != nil {
		t.Fatalf("Results() = %v, want the trailing bytes ignored", err)
	}
	if len(results) != 0 {
		t.Errorf("Results() = %d entries, want 0", len(results))
	}
	if got := LsarLookupSidsResponseDecoder(pdu).ReturnValue(); got != 0 {
		t.Errorf("ReturnValue() = 0x%08X, want STATUS_SUCCESS from the same extent", got)
	}
}

// buildCountOnlyResponse builds a response whose ReferencedDomains list declares
// domainCount entries but carries no array behind them.
func buildCountOnlyResponse(domainCount uint32) []byte {
	stub := make([]byte, 0, 20)
	put := func(v uint32) {
		b := make([]byte, 4)
		le.PutUint32(b, v)
		stub = append(stub, b...)
	}
	put(0x20000)     // ReferencedDomains pointer (non-null)
	put(domainCount) // Entries
	put(0x20004)     // Domains pointer (non-null)
	put(domainCount) // MaxEntries
	put(domainCount) // conformant MaxCount
	return buildLookupSidsResponse(stub, uint16(24+len(stub)), 0)
}

// buildNamesCountOnlyResponse builds a response whose TranslatedNames declares
// nameCount entries with no array behind them.
func buildNamesCountOnlyResponse(nameCount uint32, namesPtr uint32) []byte {
	stub := make([]byte, 0, 16)
	put := func(v uint32) {
		b := make([]byte, 4)
		le.PutUint32(b, v)
		stub = append(stub, b...)
	}
	put(0)         // ReferencedDomains pointer (null)
	put(nameCount) // TranslatedNames.Entries
	put(namesPtr)  // TranslatedNames pointer
	put(nameCount) // conformant MaxCount
	return buildLookupSidsResponse(stub, uint16(24+len(stub)), 0)
}

// Every count in a response is a server-declared uint32 that the payload does
// not have to back. Results must reject a count the buffer cannot cover before
// it sizes anything from it -- otherwise a tiny PDU declaring four billion
// entries has the decoder reserve tens of gigabytes and die on the way to
// discovering the response is truncated.
//
// TotalAlloc is process-wide, so this measures the package's allocations, not
// this call's: it must stay sequential, and nothing here may allocate in the
// background. The budget is three orders of magnitude below a regression.
func TestResultsRejectsUnbackedCountsWithoutAllocating(t *testing.T) {
	// Large enough that a regression allocates hundreds of megabytes and trips
	// the budget below, small enough not to kill the test host outright.
	const declared = 20_000_000

	tests := []struct {
		name string
		pdu  []byte
	}{
		{"referenced domain entries", buildCountOnlyResponse(declared)},
		{"translated name entries", buildNamesCountOnlyResponse(declared, 0x30000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.pdu) > 128 {
				t.Fatalf("fixture grew to %d bytes; it must stay tiny for this test to mean anything", len(tt.pdu))
			}

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			results, err := LsarLookupSidsResponseDecoder(tt.pdu).Results()
			runtime.ReadMemStats(&after)

			if err == nil && len(results) != 0 {
				t.Errorf("Results() = %d entries, want an error or nothing from a %d-byte response", len(results), len(tt.pdu))
			}

			const budget = 1 << 20
			if grew := after.TotalAlloc - before.TotalAlloc; grew > budget {
				t.Errorf("Results() allocated %d bytes from a %d-byte response, want under %d", grew, len(tt.pdu), budget)
			}
		})
	}
}

// A count that overflows int when multiplied by its element size must not slip
// past the bounds check. On a 32-bit build the product wraps; the check is done
// in 64-bit arithmetic so that it fails there too.
func TestResultsRejectsOverflowingCounts(t *testing.T) {
	for _, count := range []uint32{0xFFFFFFFF, 0x80000000, 0x40000000, 0x20000000} {
		for _, pdu := range [][]byte{
			buildCountOnlyResponse(count),
			buildNamesCountOnlyResponse(count, 0x30000),
		} {
			results, err := LsarLookupSidsResponseDecoder(pdu).Results()
			if err == nil && len(results) != 0 {
				t.Errorf("count 0x%08X: Results() = %d entries, want an error or nothing", count, len(results))
			}
		}
	}
}

// A declared count with a null array pointer is not an array of empty results.
func TestResultsNullNamesPointer(t *testing.T) {
	results, err := LsarLookupSidsResponseDecoder(buildNamesCountOnlyResponse(0xFFFFFFFF, 0)).Results()
	if err != nil {
		t.Fatalf("Results() = %v, want no error", err)
	}
	if len(results) != 0 {
		t.Errorf("Results() = %d entries, want 0 for a null names pointer", len(results))
	}
}

// Results and ReturnValue decode a PDU that a server controls end to end, so
// neither may panic on any input. Both are bounded by the length of the buffer
// they are given, which is what makes this target runnable at all: before the
// counts were checked against the payload, a seed declaring four billion entries
// exhausted memory rather than failing.
func FuzzResults(f *testing.F) {
	f.Add(buildCountOnlyResponse(3))
	f.Add(buildNamesCountOnlyResponse(2, 0x30000))
	f.Add(buildNamesCountOnlyResponse(2, 0))
	f.Add(buildLookupSidsResponse(make([]byte, 40), 64, 0))
	f.Add(buildAuthenticatedResponse(make([]byte, 20), 12, 16))

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = LsarLookupSidsResponseDecoder(b).Results()
		_ = LsarLookupSidsResponseDecoder(b).ReturnValue()
	})
}
