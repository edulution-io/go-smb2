package smb2

import "testing"

// negotiateContext builds an SMB2_NEGOTIATE_CONTEXT of total length n whose
// DataLength field carries dataLen.
func negotiateContext(n int, dataLen uint16) NegotiateContextDecoder {
	b := make([]byte, n)
	if n >= 8 {
		le.PutUint16(b[2:4], dataLen)
	}
	return NegotiateContextDecoder(b)
}

// The guard widens DataLength to int and is sound, but Data recomputed 8+len
// in uint16: a context declaring 65529 bytes of data, in a negotiate response
// large enough to back it, wrapped the upper bound to 1 and panicked with
// ctx[8:1]. The transport accepts frames up to 16 MiB, and the negotiate
// response is decoded before signing is established.
func TestNegotiateContextDecoderDataSliceableWhenValid(t *testing.T) {
	tests := []struct {
		name    string
		buf     NegotiateContextDecoder
		invalid bool
	}{
		{"empty", NegotiateContextDecoder(nil), true},
		{"one byte short of the fixed fields", negotiateContext(7, 0), true},
		{"fixed fields only, no data", negotiateContext(8, 0), false},
		{"data fully present", negotiateContext(16, 8), false},
		{"data one byte short", negotiateContext(15, 8), true},
		{"DataLength wraps the upper bound to 1", negotiateContext(65537, 65529), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Fatalf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
			if tt.invalid {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Data() panicked on a context IsInvalid cleared: %v", r)
				}
			}()
			if got := len(tt.buf.Data()); got != int(tt.buf.DataLength()) {
				t.Errorf("len(Data()) = %d, want %d", got, tt.buf.DataLength())
			}
		})
	}
}
