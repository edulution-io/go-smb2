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
	f.Add([]byte{1, 0, 4, 0x80, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0})

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseSecurityDescriptor(b)
		_, _ = parseACL(b)
	})
}

func FuzzParseDirectoryEntries(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 104))

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
	f.Add(make([]byte, 12))

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
