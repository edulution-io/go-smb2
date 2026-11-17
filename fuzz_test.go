package smb2

import (
	"testing"

	. "github.com/edulution-io/go-smb2/internal/smb2"
)

// The parsers below take bytes straight from a server response. They may
// return an error on any input, but never panic or loop.

func FuzzParseSecurityDescriptor(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 20))
	system := buildSID(1, 5, 18)
	f.Add(buildSecurityDescriptor(0x0004, system, nil, nil, buildACL(2, buildACE(0, 0, 0x001F01FF, system))))

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseSecurityDescriptor(b)
		_, _ = parseACL(b)
	})
}

func FuzzParseDirectoryEntries(f *testing.F) {
	f.Add([]byte{})
	f.Add(dirInfoEntry("a.txt", 0))

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseDirectoryEntries(b)
	})
}

func FuzzEvalSymlinkError(f *testing.F) {
	f.Add("dir\\link\\file", []byte{})
	f.Add("link", make([]byte, 64))

	f.Fuzz(func(t *testing.T, name string, b []byte) {
		_, _ = evalSymlinkError(name, b)
	})
}

func FuzzCopychunkLimitsFrom(f *testing.F) {
	f.Add(copychunkResponse(4, 512, 2048))

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = copychunkLimitsFrom(b)
	})
}

func FuzzAccept(f *testing.F) {
	f.Add(uint16(SMB2_CREATE), make([]byte, 64+9))

	f.Fuzz(func(t *testing.T, cmd uint16, b []byte) {
		if PacketCodec(b).IsInvalid() {
			return // the receiver drops these before accept sees them
		}
		_, _ = accept(cmd, b)
	})
}
