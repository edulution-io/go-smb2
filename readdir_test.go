package smb2

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// dirInfoEntry builds one FILE_DIRECTORY_INFORMATION entry: 64 fixed bytes
// followed by the UTF-16LE name, with the given NextEntryOffset.
func dirInfoEntry(name string, next uint32) []byte {
	ws := utf16.Encode([]rune(name))
	b := make([]byte, 64+2*len(ws))
	binary.LittleEndian.PutUint32(b[0:4], next)
	binary.LittleEndian.PutUint32(b[60:64], uint32(2*len(ws)))
	for i, w := range ws {
		binary.LittleEndian.PutUint16(b[64+2*i:66+2*i], w)
	}
	return b
}

func TestParseDirectoryEntries(t *testing.T) {
	first := dirInfoEntry("a.txt", 0)
	second := dirInfoEntry("b.txt", 0)
	binary.LittleEndian.PutUint32(first[0:4], uint32(len(first))) // NextEntryOffset

	fi, err := parseDirectoryEntries(append(append([]byte{}, first...), second...))
	if err != nil {
		t.Fatalf("parseDirectoryEntries() = %v", err)
	}
	if len(fi) != 2 || fi[0].Name() != "a.txt" || fi[1].Name() != "b.txt" {
		t.Fatalf("got %d entries %v, want a.txt and b.txt", len(fi), fi)
	}
}

func TestParseDirectoryEntriesSkipsDotEntries(t *testing.T) {
	dot := dirInfoEntry(".", 0)
	dotdot := dirInfoEntry("..", 0)
	name := dirInfoEntry("a.txt", 0)
	binary.LittleEndian.PutUint32(dot[0:4], uint32(len(dot)))
	binary.LittleEndian.PutUint32(dotdot[0:4], uint32(len(dotdot)))

	output := append(append(append([]byte{}, dot...), dotdot...), name...)

	fi, err := parseDirectoryEntries(output)
	if err != nil {
		t.Fatalf("parseDirectoryEntries() = %v", err)
	}
	if len(fi) != 1 || fi[0].Name() != "a.txt" {
		t.Fatalf("got %d entries %v, want a.txt alone", len(fi), fi)
	}
}

// A NextEntryOffset past the end of the output buffer must be rejected
// rather than sliced, which panicked.
func TestParseDirectoryEntriesRejectsOutOfRangeNextEntryOffset(t *testing.T) {
	for _, next := range []uint32{0xFFFFFFFF, 1 << 20, 75} {
		entry := dirInfoEntry("a.txt", next)

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parseDirectoryEntries() panicked on NextEntryOffset %d: %v", next, r)
				}
			}()
			if _, err := parseDirectoryEntries(entry); err == nil {
				t.Errorf("parseDirectoryEntries() = nil error for NextEntryOffset %d past a %d-byte buffer, want an error",
					next, len(entry))
			}
		}()
	}
}

// NextEntryOffset must also advance past the entry just decoded, not merely
// stay inside the buffer, or the walk re-reads overlapping bytes as entry
// after entry and makes no progress.
func TestParseDirectoryEntriesRejectsNonAdvancingNextEntryOffset(t *testing.T) {
	output := make([]byte, 256)
	for off := 0; off+64 <= len(output); off += 8 {
		binary.LittleEndian.PutUint32(output[off:off+4], 8) // NextEntryOffset
	}
	binary.LittleEndian.PutUint32(output[192:196], 0) // terminate the chain

	fi, err := parseDirectoryEntries(output)
	if err == nil {
		t.Errorf("parseDirectoryEntries() = %d entries, nil error for a chain stepping 8 bytes through 64-byte entries, want an error", len(fi))
	}
}
