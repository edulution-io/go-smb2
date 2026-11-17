package smb2

import (
	"bytes"
	"os"
	"testing"
)

// On an append-only handle the server appends each WRITE where the file ends,
// so chunks sent in parallel could land out of order. A large Write to an
// O_APPEND file must go out one chunk at a time.
func TestAppendWritesStaySerial(t *testing.T) {
	for _, tt := range []struct {
		name       string
		flag       int
		appendOnly bool
		overlap    bool
	}{
		{"append", os.O_WRONLY | os.O_APPEND, true, false},
		// The control case shows the fake does see pipelined writes.
		{"plain", os.O_WRONLY, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := &fakeFiles{appendOnly: tt.appendOnly}
			sess, err := dialFake(t, &fakeServer{files: files})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = sess.s.t.Close() }()

			share, err := sess.Mount("share")
			if err != nil {
				t.Fatal(err)
			}
			f, err := share.OpenFile("file", tt.flag, 0644)
			if err != nil {
				t.Fatal(err)
			}

			data := make([]byte, 8<<16+123) // nine chunks of at most 64 KiB
			for i := range data {
				data[i] = byte(i / 1000)
			}
			if n, err := f.Write(data); err != nil || n != len(data) {
				t.Fatalf("Write: %d, %v", n, err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}

			if files.overlapped != tt.overlap {
				t.Errorf("a request arrived while a WRITE was unanswered: %v, want %v", files.overlapped, tt.overlap)
			}
			if !bytes.Equal(files.data, data) {
				t.Error("file content out of order")
			}
		})
	}
}
