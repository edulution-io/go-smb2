package smb2

import (
	"context"
	"errors"
	"io"
	"testing"
)

// newDeadFile returns a File on a connection that fails every request, as a
// dropped connection does.
func newDeadFile(t *testing.T) *File {
	t.Helper()
	conn := newTestConn(16)
	conn.err = errors.New("connection is dead")
	conn.maxReadSize = creditPayload
	conn.maxWriteSize = creditPayload
	fs := &Share{
		treeConn: &treeConn{session: &session{conn: conn}},
		ctx:      context.Background(),
	}
	return &File{fs: fs, name: "f", offset: 10}
}

// io.Reader, io.Writer and io.ReaderAt forbid a negative count even on error;
// bufio panics on one, and Write used to move the offset back by it.
func TestFileErrorsReportNoNegativeCounts(t *testing.T) {
	buf := make([]byte, 8)
	ops := []struct {
		name  string
		seeks bool
		do    func(f *File) (int64, error)
	}{
		{"Read", false, func(f *File) (int64, error) { n, err := f.Read(buf); return int64(n), err }},
		{"ReadAt", false, func(f *File) (int64, error) { n, err := f.ReadAt(buf, 0); return int64(n), err }},
		{"ReadAt negative offset", false, func(f *File) (int64, error) { n, err := f.ReadAt(buf, -1); return int64(n), err }},
		{"Write", false, func(f *File) (int64, error) { n, err := f.Write(buf); return int64(n), err }},
		{"WriteAt", false, func(f *File) (int64, error) { n, err := f.WriteAt(buf, 0); return int64(n), err }},
		{"WriteAt negative offset", false, func(f *File) (int64, error) { n, err := f.WriteAt(buf, -1); return int64(n), err }},
		{"Seek from end", true, func(f *File) (int64, error) { return f.Seek(0, io.SeekEnd) }},
		{"Seek bad whence", true, func(f *File) (int64, error) { return f.Seek(0, 7) }},
		{"server-side copy", false, func(f *File) (int64, error) {
			dst := &File{fs: f.fs, name: "g", id: f.id + 1}
			return dst.ReadFrom(f)
		}},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			f := newDeadFile(t)
			n, err := op.do(f)
			if err == nil {
				t.Fatal("err = nil, want the failure")
			}
			if n != 0 {
				t.Errorf("n = %d, want 0", n)
			}
			if !op.seeks && f.offset != 10 {
				t.Errorf("offset = %d, want 10 unchanged", f.offset)
			}
		})
	}
}
