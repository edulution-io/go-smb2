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

// mustNotPanic asserts the invariant every one of these guards exists for:
// once IsInvalid clears, the variable-length accessors behind it must be
// sliceable. Checking the boolean alone would still pass if the guard and the
// accessor disagreed on the width they compute the total in.
func mustNotPanic(t *testing.T, what string, access func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked on a buffer IsInvalid cleared: %v", what, r)
		}
	}()
	access()
}

func errorResponse(n int, byteCount uint32) ErrorResponseDecoder {
	b := make([]byte, n)
	if n >= 8 {
		le.PutUint16(b[0:2], 9) // StructureSize
		le.PutUint32(b[4:8], byteCount)
	}
	return ErrorResponseDecoder(b)
}

// acceptError decodes this on every non-success status the server returns, so
// it is the broadest-reach member of the class. 8+ByteCount() wraps in uint32:
// 0xFFFFFFFF turned the guard into len(r) < 7 and ErrorData into r[8:7].
func TestErrorResponseDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     ErrorResponseDecoder
		invalid bool
	}{
		{"empty", ErrorResponseDecoder(nil), true},
		{"one byte short of the fixed fields", errorResponse(7, 0), true},
		{"fixed fields only, no error data", errorResponse(8, 0), false},
		{"error data fully present", errorResponse(12, 4), false},
		{"error data one byte short", errorResponse(11, 4), true},
		{"ByteCount wraps the sum to 7", errorResponse(64, 0xFFFFFFFF), true},
		{"ByteCount wraps the sum to 0", errorResponse(64, 0xFFFFFFF8), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

func errorContext(n int, dataLen uint32) ErrorContextResponseDecoder {
	b := make([]byte, n)
	if n >= 8 {
		le.PutUint32(b[0:4], dataLen)
	}
	return ErrorContextResponseDecoder(b)
}

// Same wrap, one level down: acceptError walks the context list whenever the
// error response reports a non-zero ErrorContextCount.
func TestErrorContextResponseDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     ErrorContextResponseDecoder
		invalid bool
	}{
		{"empty", ErrorContextResponseDecoder(nil), true},
		{"one byte short of the fixed fields", errorContext(7, 0), true},
		{"fixed fields only, no context data", errorContext(8, 0), false},
		{"context data fully present", errorContext(16, 8), false},
		{"context data one byte short", errorContext(15, 8), true},
		{"ErrorDataLength wraps the sum to 7", errorContext(64, 0xFFFFFFFF), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

func readResponse(n int, dataOff uint8, dataLen uint32) ReadResponseDecoder {
	b := make([]byte, n)
	if n >= 16 {
		le.PutUint16(b[0:2], 17) // StructureSize
		b[2] = dataOff
		le.PutUint32(b[4:8], dataLen)
	}
	return ReadResponseDecoder(b)
}

// DataOffset is a uint8 but DataLength is a uint32, and the sum was taken in
// uint32: DataLength 0xFFFFFFFF turned the guard into len(r) < 15.
func TestReadResponseDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     ReadResponseDecoder
		invalid bool
	}{
		{"empty", ReadResponseDecoder(nil), true},
		{"one byte short of the fixed fields", readResponse(15, 0, 0), true},
		{"fixed fields only, no data", readResponse(16, 0, 0), false},
		{"data fully present", readResponse(256, 80, 240), false},
		{"data one byte short", readResponse(255, 80, 240), true},
		{"DataLength wraps the sum to 15", readResponse(256, 80, 0xFFFFFFFF), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

func createResponse(n int, ctxOff, ctxLen uint32) CreateResponseDecoder {
	b := make([]byte, n)
	if n >= 88 {
		le.PutUint16(b[0:2], 89) // StructureSize
		le.PutUint32(b[80:84], ctxOff)
		le.PutUint32(b[84:88], ctxLen)
	}
	return CreateResponseDecoder(b)
}

// CreateContextsOffset+CreateContextsLength are both uint32, so a length that
// carries the sum to exactly 0 mod 2^32 made the guard len(r) < -64.
func TestCreateResponseDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     CreateResponseDecoder
		invalid bool
	}{
		{"empty", CreateResponseDecoder(nil), true},
		{"one byte short of the fixed fields", createResponse(87, 0, 0), true},
		{"fixed fields only, no contexts", createResponse(88, 0, 0), false},
		{"contexts fully present", createResponse(256, 152, 168), false},
		{"contexts one byte short", createResponse(255, 152, 168), true},
		{"unaligned context offset", createResponse(256, 156, 164), true},
		{"length wraps the sum to 0", createResponse(256, 152, 0xFFFFFF68), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

func ioctlResponse(n int, inOff, inCnt, outOff, outCnt uint32) IoctlResponseDecoder {
	b := make([]byte, n)
	if n >= 48 {
		le.PutUint16(b[0:2], 49) // StructureSize
		le.PutUint32(b[24:28], inOff)
		le.PutUint32(b[28:32], inCnt)
		le.PutUint32(b[32:36], outOff)
		le.PutUint32(b[36:40], outCnt)
	}
	return IoctlResponseDecoder(b)
}

// Two wrapping sums in one guard, and Output() is what File.copyTo and
// File.Statfs read their payload out of.
func TestIoctlResponseDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     IoctlResponseDecoder
		invalid bool
	}{
		{"empty", IoctlResponseDecoder(nil), true},
		{"one byte short of the fixed fields", ioctlResponse(47, 0, 0, 0, 0), true},
		{"fixed fields only, no buffers", ioctlResponse(48, 0, 0, 0, 0), false},
		{"buffers fully present", ioctlResponse(240, 112, 192, 112, 192), false},
		{"buffers one byte short", ioctlResponse(239, 112, 192, 112, 192), true},
		{"InputCount wraps the sum to 48", ioctlResponse(256, 112, 0xFFFFFFC0, 0, 0), true},
		{"OutputCount wraps the sum to 48", ioctlResponse(256, 0, 0, 112, 0xFFFFFFC0), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

// QUERY_DIRECTORY and QUERY_INFO share a wire layout: StructureSize, a uint16
// OutputBufferOffset and a uint32 OutputBufferLength.
func outputBufferResponse(n int, off uint16, length uint32) []byte {
	b := make([]byte, n)
	if n >= 8 {
		le.PutUint16(b[0:2], 9) // StructureSize
		le.PutUint16(b[2:4], off)
		le.PutUint32(b[4:8], length)
	}
	return b
}

// The offset is uint16 and the length uint32, and the sum was taken in uint32
// after widening the offset -- so the length alone carries the wrap.
func TestOutputBufferResponseDecodersIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		n       int
		off     uint16
		length  uint32
		invalid bool
	}{
		{"empty", 0, 0, 0, true},
		{"one byte short of the fixed fields", 7, 0, 0, true},
		{"fixed fields only, no output buffer", 8, 0, 0, false},
		{"output buffer fully present", 256, 72, 248, false},
		{"output buffer one byte short", 255, 72, 248, true},
		{"length wraps the sum to 0", 256, 72, 0xFFFFFFB8, true},
		{"length wraps the sum to 64", 256, 72, 0xFFFFFFF8, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := outputBufferResponse(tt.n, tt.off, tt.length)
			if got := QueryDirectoryResponseDecoder(b).IsInvalid(); got != tt.invalid {
				t.Errorf("QueryDirectoryResponseDecoder.IsInvalid() = %v, want %v", got, tt.invalid)
			}
			if got := QueryInfoResponseDecoder(b).IsInvalid(); got != tt.invalid {
				t.Errorf("QueryInfoResponseDecoder.IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

func TestResponseDecodersSliceableWhenValid(t *testing.T) {
	cases := []struct {
		name      string
		isInvalid func() bool
		access    func()
	}{}

	for _, r := range []ErrorResponseDecoder{
		errorResponse(8, 0), errorResponse(12, 4), errorResponse(64, 0xFFFFFFFF), errorResponse(64, 0xFFFFFFF8),
	} {
		cases = append(cases, struct {
			name      string
			isInvalid func() bool
			access    func()
		}{"ErrorResponseDecoder.ErrorData", r.IsInvalid, func() { _ = r.ErrorData() }})
	}

	for _, r := range []ErrorContextResponseDecoder{
		errorContext(8, 0), errorContext(16, 8), errorContext(64, 0xFFFFFFFF),
	} {
		cases = append(cases, struct {
			name      string
			isInvalid func() bool
			access    func()
		}{"ErrorContextResponseDecoder.ErrorContextData", r.IsInvalid, func() { _ = r.ErrorContextData() }})
	}

	for _, r := range []ReadResponseDecoder{
		readResponse(16, 0, 0), readResponse(256, 80, 240), readResponse(256, 80, 0xFFFFFFFF),
	} {
		cases = append(cases, struct {
			name      string
			isInvalid func() bool
			access    func()
		}{"ReadResponseDecoder.Data", r.IsInvalid, func() { _ = r.Data() }})
	}

	for _, r := range []CreateResponseDecoder{
		createResponse(88, 0, 0), createResponse(256, 152, 168), createResponse(256, 152, 0xFFFFFF68),
	} {
		cases = append(cases, struct {
			name      string
			isInvalid func() bool
			access    func()
		}{"CreateResponseDecoder.CreateContexts", r.IsInvalid, func() { _ = r.CreateContexts() }})
	}

	for _, r := range []IoctlResponseDecoder{
		ioctlResponse(48, 0, 0, 0, 0), ioctlResponse(240, 112, 192, 112, 192),
		ioctlResponse(256, 112, 0xFFFFFFC0, 0, 0), ioctlResponse(256, 0, 0, 112, 0xFFFFFFC0),
	} {
		cases = append(cases, struct {
			name      string
			isInvalid func() bool
			access    func()
		}{"IoctlResponseDecoder.Input/Output", r.IsInvalid, func() { _, _ = r.Input(), r.Output() }})
	}

	for _, b := range [][]byte{
		outputBufferResponse(8, 0, 0), outputBufferResponse(256, 72, 248),
		outputBufferResponse(256, 72, 0xFFFFFFB8), outputBufferResponse(256, 72, 0xFFFFFFF8),
	} {
		qd := QueryDirectoryResponseDecoder(b)
		qi := QueryInfoResponseDecoder(b)
		cases = append(cases, struct {
			name      string
			isInvalid func() bool
			access    func()
		}{"QueryDirectoryResponseDecoder.OutputBuffer", qd.IsInvalid, func() { _ = qd.OutputBuffer() }})
		cases = append(cases, struct {
			name      string
			isInvalid func() bool
			access    func()
		}{"QueryInfoResponseDecoder.OutputBuffer", qi.IsInvalid, func() { _ = qi.OutputBuffer() }})
	}

	for _, c := range cases {
		if c.isInvalid() {
			continue
		}
		mustNotPanic(t, c.name, c.access)
	}
}
