package spnego

import "testing"

// Both tokens come from the server during session setup.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x60, 0x00})
	f.Add([]byte{0xa1, 0x00})

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeNegTokenInit2(b)
		_, _ = DecodeNegTokenInit(b)
		_, _ = DecodeNegTokenResp(b)
	})
}
