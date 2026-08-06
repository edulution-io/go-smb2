package smb2

import "testing"

// quotaEntry builds a FileQuotaInformation buffer of total length n whose
// SidLength field carries sidLen, so a case can set the two independently --
// which is the whole point, since the defect is the guard trusting a SidLength
// the buffer does not back.
func quotaEntry(n int, sidLen uint32) FileQuotaInformationDecoder {
	b := make([]byte, n)
	if n >= 8 {
		le.PutUint32(b[4:8], sidLen)
	}
	return FileQuotaInformationDecoder(b)
}

// The guard computed 40+SidLength() in uint32, which wraps before the int()
// widening, so it validated a smaller number than Sid slices with: SidLength
// 0xFFFFFFFF turned the check into len(c) < 39 and the slice into c[40:39].
func TestFileQuotaInformationDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     FileQuotaInformationDecoder
		invalid bool
	}{
		{"empty", FileQuotaInformationDecoder(nil), true},
		{"shorter than the fixed fields", quotaEntry(39, 0), true},
		{"too short to hold SidLength", quotaEntry(4, 0), true},
		{"fixed fields only, no SID", quotaEntry(40, 0), false},
		{"SID fully present", quotaEntry(48, 8), false},
		{"SID one byte short", quotaEntry(47, 8), true},
		{"SidLength wraps the sum to 39", quotaEntry(48, 0xFFFFFFFF), true},
		{"SidLength wraps the sum to 24", quotaEntry(48, 0xFFFFFFF0), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

// The invariant the guard exists for: clearing IsInvalid has to mean Sid can be
// sliced. Asserting the boolean alone would still pass if the guard and the
// slice disagreed on the length in some other way.
func TestFileQuotaInformationDecoderSidSliceableWhenValid(t *testing.T) {
	cases := []FileQuotaInformationDecoder{
		quotaEntry(40, 0),
		quotaEntry(48, 8),
		quotaEntry(48, 0xFFFFFFFF),
		quotaEntry(48, 0xFFFFFFF0),
		quotaEntry(39, 0),
	}

	for _, c := range cases {
		if c.IsInvalid() {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Sid() panicked on a buffer IsInvalid cleared (len=%d, SidLength=%d): %v",
						len(c), c.SidLength(), r)
				}
			}()
			_ = c.Sid()
		}()
	}
}

// resumeKeyResponse builds an SRV_REQUEST_RESUME_KEY response of total length n
// whose ContextLength field carries ctxLen, so the two can be set apart.
func resumeKeyResponse(n int, ctxLen uint32) SrvRequestResumeKeyResponseDecoder {
	b := make([]byte, n)
	if n >= 28 {
		le.PutUint32(b[24:28], ctxLen)
	}
	return SrvRequestResumeKeyResponseDecoder(b)
}

// Unlike the quota decoder this one is reachable: File.copyTo decodes it, and
// copyTo is what File.ReadFrom and File.WriteTo dispatch to, so a short or
// hostile ioctl response reaches it through any io.Copy between two SMB files.
func TestSrvRequestResumeKeyResponseDecoderIsInvalid(t *testing.T) {
	tests := []struct {
		name    string
		buf     SrvRequestResumeKeyResponseDecoder
		invalid bool
	}{
		{"empty", SrvRequestResumeKeyResponseDecoder(nil), true},
		{"resume key only, no ContextLength", resumeKeyResponse(24, 0), true},
		{"one byte short of the fixed fields", resumeKeyResponse(27, 0), true},
		{"fixed fields only, empty context", resumeKeyResponse(28, 0), false},
		{"context fully present", resumeKeyResponse(32, 4), false},
		{"context one byte short", resumeKeyResponse(31, 4), true},
		{"ContextLength wraps the sum to 27", resumeKeyResponse(28, 0xFFFFFFFF), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.buf.IsInvalid(); got != tt.invalid {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.invalid)
			}
		})
	}
}

// What copyTo does once IsInvalid clears: it copies ResumeKey into the
// copychunk request. Context is covered too, since the wrap defect is what
// would let it slice past the end.
func TestSrvRequestResumeKeyResponseDecoderSliceableWhenValid(t *testing.T) {
	cases := []SrvRequestResumeKeyResponseDecoder{
		resumeKeyResponse(28, 0),
		resumeKeyResponse(32, 4),
		resumeKeyResponse(28, 0xFFFFFFFF),
		resumeKeyResponse(27, 0),
	}

	for _, c := range cases {
		if c.IsInvalid() {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("slicing panicked on a buffer IsInvalid cleared (len=%d): %v", len(c), r)
				}
			}()
			_ = c.ResumeKey()
			_ = c.Context()
		}()
	}
}

// MS-FSCC 2.4.11 defines FILE_DISPOSITION_INFORMATION as a single BOOLEAN.
// Size feeds InputBufferLength, so reporting 4 declared three padding bytes as
// payload on every SMB2 SET_INFO that deletes a file.
func TestFileDispositionInformationEncoderSize(t *testing.T) {
	e := &FileDispositionInformationEncoder{DeletePending: 1}

	if got := e.Size(); got != 1 {
		t.Errorf("Size() = %d, want 1", got)
	}

	p := make([]byte, e.Size())
	e.Encode(p)
	if p[0] != 1 {
		t.Errorf("Encode wrote DeletePending = %d, want 1", p[0])
	}
}
