package smb2

import (
	"bytes"
	"testing"
)

// These decoders run before signing or encryption is established, so their
// input is whatever the wire delivers. Each helper builds a body of total
// length n with the length fields set independently of n, which is what lets
// a case describe a buffer the fields do not back.

func negotiateResponse(n int, dialect uint16, secOff, secLen uint16, ctxOff uint32) NegotiateResponseDecoder {
	b := make([]byte, n)
	if n >= 64 {
		le.PutUint16(b[0:2], 65)
		le.PutUint16(b[4:6], dialect)
		le.PutUint16(b[56:58], secOff)
		le.PutUint16(b[58:60], secLen)
		le.PutUint32(b[60:64], ctxOff)
	}
	return NegotiateResponseDecoder(b)
}

// The guard added SecurityBufferOffset and SecurityBufferLength in uint16, so
// 0xFF00+0x0200 wrapped to 0x0100 and a 256-byte body passed a check that
// SecurityBuffer then sliced as r[65216:192].
func TestNegotiateResponseDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     NegotiateResponseDecoder
		invalid bool
	}{
		{"empty", NegotiateResponseDecoder(nil), true},
		{"shorter than the fixed fields", negotiateResponse(63, SMB210, 0, 0, 0), true},
		{"fixed fields only, no buffer", negotiateResponse(64, SMB210, 128, 0, 0), false},
		{"buffer fully present", negotiateResponse(80, SMB210, 128, 16, 0), false},
		{"buffer one byte short", negotiateResponse(79, SMB210, 128, 16, 0), true},
		{"offset and length wrap in uint16", negotiateResponse(256, SMB210, 0xFF00, 0x0200, 0), true},
		{"length alone past the end", negotiateResponse(256, SMB210, 128, 0xFFFF, 0), true},
		{"311 context offset at the end", negotiateResponse(80, SMB311, 128, 16, 144), false},
		{"311 context offset past the end", negotiateResponse(80, SMB311, 128, 16, 152), true},
		{"311 context offset misaligned", negotiateResponse(80, SMB311, 128, 16, 145), true},
		{"311 context offset near uint32 max", negotiateResponse(80, SMB311, 128, 16, 0xFFFFFFF8), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

// Clearing IsInvalid has to mean the accessors can slice. The accessor used
// to recompute the sum in uint16 on its own, so a widened guard alone would
// still have left it panicking.
func TestNegotiateResponseDecoderAccessorsSliceableWhenValid(t *testing.T) {
	cases := []NegotiateResponseDecoder{
		negotiateResponse(64, SMB210, 128, 0, 0),
		negotiateResponse(80, SMB210, 128, 16, 0),
		negotiateResponse(256, SMB210, 0xFF00, 0x0200, 0),
		negotiateResponse(256, SMB210, 128, 0xFFFF, 0),
		negotiateResponse(80, SMB311, 128, 16, 144),
		negotiateResponse(80, SMB311, 128, 16, 0xFFFFFFF8),
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
			// The context offset is only validated for SMB 3.1.1; on older
			// dialects the field is reserved and conn.go never reads it.
			if c.DialectRevision() == SMB311 {
				_ = c.NegotiateContextList()
			}
		}()
	}
}

func sessionSetupResponse(n int, secOff, secLen uint16) SessionSetupResponseDecoder {
	b := make([]byte, n)
	if n >= 8 {
		le.PutUint16(b[0:2], 9)
		le.PutUint16(b[4:6], secOff)
		le.PutUint16(b[6:8], secLen)
	}
	return SessionSetupResponseDecoder(b)
}

// Same defect as the negotiate response: the uint16 sum wrapped and the
// accessor sliced past the end.
func TestSessionSetupResponseDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     SessionSetupResponseDecoder
		invalid bool
	}{
		{"empty", SessionSetupResponseDecoder(nil), true},
		{"shorter than the fixed fields", sessionSetupResponse(7, 0, 0), true},
		{"fixed fields only, no buffer", sessionSetupResponse(8, 72, 0), false},
		{"buffer fully present", sessionSetupResponse(24, 72, 16), false},
		{"buffer one byte short", sessionSetupResponse(23, 72, 16), true},
		{"offset and length wrap in uint16", sessionSetupResponse(256, 0xFF00, 0x0200), true},
		{"length alone past the end", sessionSetupResponse(256, 72, 0xFFFF), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

func TestSessionSetupResponseDecoderSecurityBufferSliceableWhenValid(t *testing.T) {
	cases := []SessionSetupResponseDecoder{
		sessionSetupResponse(8, 72, 0),
		sessionSetupResponse(24, 72, 16),
		sessionSetupResponse(256, 0xFF00, 0x0200),
		sessionSetupResponse(256, 72, 0xFFFF),
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

func negotiateContext(n int, dataLen uint16) NegotiateContextDecoder {
	b := make([]byte, n)
	if n >= 4 {
		le.PutUint16(b[2:4], dataLen)
	}
	return NegotiateContextDecoder(b)
}

// The guard was already computed in int, but Data() added 8 to the uint16
// length, so a DataLength of 0xFFF8 in a buffer large enough to hold it
// produced ctx[8:0].
func TestNegotiateContextDecoderDataSliceableWhenValid(t *testing.T) {
	cases := []NegotiateContextDecoder{
		negotiateContext(8, 0),
		negotiateContext(24, 16),
		negotiateContext(23, 16),
		negotiateContext(65536, 0xFFF8),
		negotiateContext(65543, 0xFFFF),
	}

	for _, c := range cases {
		if c.IsInvalid() {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Data() panicked on a buffer IsInvalid cleared (len=%d, DataLength=%d): %v",
						len(c), c.DataLength(), r)
				}
			}()
			if got := len(c.Data()); got != int(c.DataLength()) {
				t.Errorf("len(Data()) = %d, want %d", got, c.DataLength())
			}
		}()
	}
}

func hashContextData(algCount, saltLen uint16) HashContextDataDecoder {
	b := make([]byte, 4+int(algCount)*2+int(saltLen))
	le.PutUint16(b[0:2], algCount)
	le.PutUint16(b[2:4], saltLen)
	return HashContextDataDecoder(b)
}

// Salt() computed its offset in uint16, so an algorithm count of 0x7FFE put
// the offset at 0 and returned the head of the buffer as the salt.
func TestHashContextDataDecoderSalt(t *testing.T) {
	cases := []HashContextDataDecoder{
		hashContextData(1, 32),
		hashContextData(0x7FFE, 16),
		hashContextData(0xFFFF, 0xFFFF),
	}

	for _, c := range cases {
		if c.IsInvalid() {
			t.Errorf("IsInvalid() = true for a buffer sized to its fields (len=%d)", len(c))
			continue
		}
		want := c[len(c)-int(c.SaltLength()):]
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Salt() panicked (len=%d, count=%d, salt=%d): %v",
						len(c), c.HashAlgorithmCount(), c.SaltLength(), r)
				}
			}()
			if got := c.Salt(); !bytes.Equal(got, want) {
				t.Errorf("Salt() returned %d bytes at the wrong offset (count=%d, salt=%d)",
					len(got), c.HashAlgorithmCount(), c.SaltLength())
			}
		}()
	}
}
