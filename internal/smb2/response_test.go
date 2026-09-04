package smb2

import "testing"

// Offsets in an SMB2 response are counted from the start of the 64-byte packet
// header, but the decoders are handed the body alone -- so a buffer of n bytes
// backs offsets up to n+64. The helpers below take the body length and the
// offset/length fields separately, since the defect under test is exactly a
// guard that trusts fields the buffer does not back.

func negotiateResponse(n int, secOff, secLen uint16) NegotiateResponseDecoder {
	b := make([]byte, n)
	if n >= 64 {
		le.PutUint16(b[0:2], 65)     // StructureSize
		le.PutUint16(b[4:6], SMB210) // DialectRevision
		le.PutUint16(b[56:58], secOff)
		le.PutUint16(b[58:60], secLen)
	}
	return NegotiateResponseDecoder(b)
}

func negotiate311Response(n int, ctxOff uint32) NegotiateResponseDecoder {
	b := negotiateResponse(n, 0, 0)
	if n >= 64 {
		le.PutUint16(b[4:6], SMB311)
		le.PutUint32(b[60:64], ctxOff)
	}
	return b
}

// The guard summed SecurityBufferOffset+SecurityBufferLength in uint16, so a
// pair that wraps -- 0xFF00 + 0x0200 = 0x0100 -- validated as a 256-byte total
// while SecurityBuffer slices from 0xFF00-64. Reachable by an on-path attacker:
// the negotiate response is decoded before signing is established.
func TestNegotiateResponseDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     NegotiateResponseDecoder
		invalid bool
	}{
		{"empty", NegotiateResponseDecoder(nil), true},
		{"one byte short of the fixed fields", negotiateResponse(63, 0, 0), true},
		{"fixed fields only, no security buffer", negotiateResponse(64, 0, 0), false},
		{"security buffer fully present", negotiateResponse(192, 128, 128), false},
		{"security buffer one byte short", negotiateResponse(191, 128, 128), true},
		{"offset and length wrap the sum to 256", negotiateResponse(256, 0xFF00, 0x0200), true},
		{"length alone wraps the sum to 0", negotiateResponse(256, 0x0100, 0xFF00), true},
		{"SMB311 context offset in range", negotiate311Response(192, 128), false},
		{"SMB311 context offset past the end", negotiate311Response(192, 512), true},
		{"SMB311 context offset unaligned", negotiate311Response(192, 132), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

// The invariant the guard exists for: clearing IsInvalid has to mean the
// accessors can slice. SecurityBuffer recomputes off+len in uint16 of its own,
// so widening only the guard would leave it panicking.
func TestNegotiateResponseDecoderSliceableWhenValid(t *testing.T) {
	cases := []NegotiateResponseDecoder{
		negotiateResponse(64, 0, 0),
		negotiateResponse(192, 128, 128),
		negotiateResponse(256, 0xFF00, 0x0200),
		negotiateResponse(256, 0x0100, 0xFF00),
		negotiateResponse(63, 0, 0),
		negotiate311Response(192, 128),
		negotiate311Response(192, 512),
	}

	for _, c := range cases {
		if c.IsInvalid() {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("accessor panicked on a buffer IsInvalid cleared (len=%d, off=%d, len=%d): %v",
						len(c), c.SecurityBufferOffset(), c.SecurityBufferLength(), r)
				}
			}()
			_ = c.SecurityBuffer()
			if c.DialectRevision() == SMB311 {
				_ = c.NegotiateContextList()
			}
		}()
	}
}

func sessionSetupResponse(n int, secOff, secLen uint16) SessionSetupResponseDecoder {
	b := make([]byte, n)
	if n >= 8 {
		le.PutUint16(b[0:2], 9) // StructureSize
		le.PutUint16(b[4:6], secOff)
		le.PutUint16(b[6:8], secLen)
	}
	return SessionSetupResponseDecoder(b)
}

// Same wrapping sum as the negotiate case, and equally pre-auth: session.go
// hands SecurityBuffer() straight to the SPNEGO acceptor.
func TestSessionSetupResponseDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     SessionSetupResponseDecoder
		invalid bool
	}{
		{"empty", SessionSetupResponseDecoder(nil), true},
		{"one byte short of the fixed fields", sessionSetupResponse(7, 0, 0), true},
		{"fixed fields only, no security buffer", sessionSetupResponse(8, 0, 0), false},
		{"security buffer fully present", sessionSetupResponse(72, 72, 64), false},
		{"security buffer one byte short", sessionSetupResponse(71, 72, 64), true},
		{"offset and length wrap the sum to 256", sessionSetupResponse(256, 0xFF00, 0x0200), true},
		{"length alone wraps the sum to 0", sessionSetupResponse(256, 0x0100, 0xFF00), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

func TestSessionSetupResponseDecoderSliceableWhenValid(t *testing.T) {
	cases := []SessionSetupResponseDecoder{
		sessionSetupResponse(8, 0, 0),
		sessionSetupResponse(72, 72, 64),
		sessionSetupResponse(256, 0xFF00, 0x0200),
		sessionSetupResponse(256, 0x0100, 0xFF00),
		sessionSetupResponse(7, 0, 0),
	}

	for _, c := range cases {
		if c.IsInvalid() {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("SecurityBuffer() panicked on a buffer IsInvalid cleared (len=%d, off=%d, len=%d): %v",
						len(c), c.SecurityBufferOffset(), c.SecurityBufferLength(), r)
				}
			}()
			_ = c.SecurityBuffer()
		}()
	}
}
