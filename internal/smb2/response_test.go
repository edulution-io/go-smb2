package smb2

import "testing"

// A bounds case pairs a buffer with the accessor its guard protects. The
// runner checks the verdict and, whenever the guard clears the buffer, that
// the accessor can slice it without panicking -- asserting the boolean alone
// would still pass if the guard and the slice disagreed on the length.
type boundsCase struct {
	name    string
	invalid bool
	dec     interface{ IsInvalid() bool }
	access  func()
}

func runBoundsCases(t *testing.T, cases []boundsCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.dec.IsInvalid(); got != tt.invalid {
				t.Fatalf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
			if tt.invalid {
				return
			}
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("accessor panicked on a buffer IsInvalid cleared: %v", r)
				}
			}()
			tt.access()
		})
	}
}

// Every helper builds a body of total length n with the length fields set
// independently of n, so a case can describe a buffer the fields do not back.
// Offsets are relative to the packet header, 64 bytes before the body.

func errorResponse(n int, byteCount uint32) ErrorResponseDecoder {
	b := make([]byte, n)
	if n >= 8 {
		le.PutUint16(b[0:2], 9)
		le.PutUint32(b[4:8], byteCount)
	}
	return ErrorResponseDecoder(b)
}

// The guard compared uint32(len(r)) < 8+ByteCount() in uint32, so a
// ByteCount of 0xFFFFFFFF wrapped the right side to 7 and ErrorData sliced
// r[8:7]. This runs on every non-success status the server returns.
func TestErrorResponseDecoderBounds(t *testing.T) {
	mk := func(name string, invalid bool, d ErrorResponseDecoder) boundsCase {
		return boundsCase{name, invalid, d, func() { _ = d.ErrorData() }}
	}
	runBoundsCases(t, []boundsCase{
		mk("empty", true, ErrorResponseDecoder(nil)),
		mk("shorter than the fixed fields", true, errorResponse(7, 0)),
		mk("fixed fields only", false, errorResponse(8, 0)),
		mk("one byte of padding", false, errorResponse(9, 0)),
		mk("data fully present", false, errorResponse(24, 16)),
		mk("data one byte short", true, errorResponse(23, 16)),
		mk("ByteCount wraps the sum to 7", true, errorResponse(64, 0xFFFFFFFF)),
		mk("ByteCount wraps the sum to 0", true, errorResponse(64, 0xFFFFFFF8)),
	})
}

func errorContext(n int, dataLen uint32) ErrorContextResponseDecoder {
	b := make([]byte, n)
	if n >= 4 {
		le.PutUint32(b[0:4], dataLen)
	}
	return ErrorContextResponseDecoder(b)
}

func TestErrorContextResponseDecoderBounds(t *testing.T) {
	mk := func(name string, invalid bool, d ErrorContextResponseDecoder) boundsCase {
		return boundsCase{name, invalid, d, func() { _ = d.ErrorContextData() }}
	}
	runBoundsCases(t, []boundsCase{
		mk("empty", true, ErrorContextResponseDecoder(nil)),
		mk("shorter than the fixed fields", true, errorContext(7, 0)),
		mk("fixed fields only", false, errorContext(8, 0)),
		mk("data fully present", false, errorContext(24, 16)),
		mk("data one byte short", true, errorContext(23, 16)),
		mk("ErrorDataLength wraps the sum to 7", true, errorContext(64, 0xFFFFFFFF)),
	})
}

func readResponse(n int, dataOff uint8, dataLen uint32) ReadResponseDecoder {
	b := make([]byte, n)
	if n >= 16 {
		le.PutUint16(b[0:2], 17)
		b[2] = dataOff
		le.PutUint32(b[4:8], dataLen)
	}
	return ReadResponseDecoder(b)
}

// DataOffset is a uint8 and was widened to uint32 before the addition, but
// DataLength is itself a uint32, so 80+0xFFFFFFFF still wrapped to 79 and
// the int() conversion saw a value smaller than the 16-byte header.
func TestReadResponseDecoderBounds(t *testing.T) {
	mk := func(name string, invalid bool, d ReadResponseDecoder) boundsCase {
		return boundsCase{name, invalid, d, func() { _ = d.Data() }}
	}
	runBoundsCases(t, []boundsCase{
		mk("empty", true, ReadResponseDecoder(nil)),
		mk("shorter than the fixed fields", true, readResponse(15, 80, 0)),
		mk("fixed fields only", false, readResponse(16, 80, 0)),
		mk("data fully present", false, readResponse(80, 80, 64)),
		mk("data one byte short", true, readResponse(79, 80, 64)),
		mk("DataLength wraps the sum to 79", true, readResponse(256, 80, 0xFFFFFFFF)),
		mk("DataLength wraps the sum to 0", true, readResponse(256, 80, 0xFFFFFFB0)),
	})
}

func createResponse(n int, coff, clen uint32) CreateResponseDecoder {
	b := make([]byte, n)
	if n >= 88 {
		le.PutUint16(b[0:2], 89)
		le.PutUint32(b[80:84], coff)
		le.PutUint32(b[84:88], clen)
	}
	return CreateResponseDecoder(b)
}

// The guard added CreateContextsOffset and CreateContextsLength in uint32,
// so 152+0xFFFFFF68 summed to exactly 0 and CreateContexts sliced
// r[88:4294967232].
func TestCreateResponseDecoderBounds(t *testing.T) {
	mk := func(name string, invalid bool, d CreateResponseDecoder) boundsCase {
		return boundsCase{name, invalid, d, func() { _ = d.CreateContexts() }}
	}
	runBoundsCases(t, []boundsCase{
		mk("empty", true, CreateResponseDecoder(nil)),
		mk("shorter than the fixed fields", true, createResponse(87, 0, 0)),
		mk("fixed fields only", false, createResponse(88, 0, 0)),
		mk("contexts fully present", false, createResponse(120, 152, 32)),
		mk("contexts one byte short", true, createResponse(119, 152, 32)),
		mk("offset misaligned", true, createResponse(120, 156, 32)),
		mk("length wraps the sum to 0", true, createResponse(120, 152, 0xFFFFFF68)),
		mk("length wraps the sum below the offset", true, createResponse(120, 152, 0xFFFFFFFF)),
	})
}

func ioctlResponse(n int, inOff, inCnt, outOff, outCnt uint32) IoctlResponseDecoder {
	b := make([]byte, n)
	if n >= 48 {
		le.PutUint16(b[0:2], 49)
		le.PutUint32(b[24:28], inOff)
		le.PutUint32(b[28:32], inCnt)
		le.PutUint32(b[32:36], outOff)
		le.PutUint32(b[36:40], outCnt)
	}
	return IoctlResponseDecoder(b)
}

func TestIoctlResponseDecoderBounds(t *testing.T) {
	mk := func(name string, invalid bool, d IoctlResponseDecoder) boundsCase {
		return boundsCase{name, invalid, d, func() { _ = d.Input(); _ = d.Output() }}
	}
	runBoundsCases(t, []boundsCase{
		mk("empty", true, IoctlResponseDecoder(nil)),
		mk("shorter than the fixed fields", true, ioctlResponse(47, 0, 0, 0, 0)),
		mk("fixed fields only", false, ioctlResponse(48, 0, 0, 0, 0)),
		mk("output fully present", false, ioctlResponse(80, 0, 0, 112, 32)),
		mk("output one byte short", true, ioctlResponse(79, 0, 0, 112, 32)),
		mk("input fully present", false, ioctlResponse(80, 112, 32, 0, 0)),
		mk("input one byte short", true, ioctlResponse(79, 112, 32, 0, 0)),
		mk("OutputCount wraps the sum to 47", true, ioctlResponse(80, 0, 0, 112, 0xFFFFFFFF)),
		mk("InputCount wraps the sum to 47", true, ioctlResponse(80, 112, 0xFFFFFFFF, 0, 0)),
	})
}

func queryDirectoryResponse(n int, off uint16, length uint32) QueryDirectoryResponseDecoder {
	b := make([]byte, n)
	if n >= 8 {
		le.PutUint16(b[0:2], 9)
		le.PutUint16(b[2:4], off)
		le.PutUint32(b[4:8], length)
	}
	return QueryDirectoryResponseDecoder(b)
}

func TestQueryDirectoryResponseDecoderBounds(t *testing.T) {
	mk := func(name string, invalid bool, d QueryDirectoryResponseDecoder) boundsCase {
		return boundsCase{name, invalid, d, func() { _ = d.OutputBuffer() }}
	}
	runBoundsCases(t, []boundsCase{
		mk("empty", true, QueryDirectoryResponseDecoder(nil)),
		mk("shorter than the fixed fields", true, queryDirectoryResponse(7, 0, 0)),
		mk("fixed fields only", false, queryDirectoryResponse(8, 72, 0)),
		mk("output fully present", false, queryDirectoryResponse(72, 72, 64)),
		mk("output one byte short", true, queryDirectoryResponse(71, 72, 64)),
		mk("OutputBufferLength wraps the sum to 71", true, queryDirectoryResponse(72, 72, 0xFFFFFFFF)),
	})
}

func queryInfoResponse(n int, off uint16, length uint32) QueryInfoResponseDecoder {
	return QueryInfoResponseDecoder(queryDirectoryResponse(n, off, length))
}

func TestQueryInfoResponseDecoderBounds(t *testing.T) {
	mk := func(name string, invalid bool, d QueryInfoResponseDecoder) boundsCase {
		return boundsCase{name, invalid, d, func() { _ = d.OutputBuffer() }}
	}
	runBoundsCases(t, []boundsCase{
		mk("empty", true, QueryInfoResponseDecoder(nil)),
		mk("shorter than the fixed fields", true, queryInfoResponse(7, 0, 0)),
		mk("fixed fields only", false, queryInfoResponse(8, 72, 0)),
		mk("output fully present", false, queryInfoResponse(72, 72, 64)),
		mk("output one byte short", true, queryInfoResponse(71, 72, 64)),
		mk("OutputBufferLength wraps the sum to 71", true, queryInfoResponse(72, 72, 0xFFFFFFFF)),
	})
}
