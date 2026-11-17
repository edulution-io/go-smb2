package smb2

import (
	"encoding/binary"
	"net"
	"time"

	. "github.com/edulution-io/go-smb2/internal/erref"
	. "github.com/edulution-io/go-smb2/internal/smb2"
)

// fakeFiles serves one file on a disk share after a fakeServer login, for
// reads and writes. Like a
// server enforcing an append-only handle, it appends every WRITE to the file
// whatever its offset when appendOnly is set. It grants enough credits for
// pipelining and records whether a request arrived while a WRITE was still
// unanswered.
type fakeFiles struct {
	appendOnly bool

	data       []byte
	overlapped bool
}

func (f *fakeFiles) serve(conn net.Conn, key []byte) {
	frames := make(chan []byte)
	go func() {
		defer close(frames)
		for {
			req, err := readFrame(conn)
			if err != nil {
				return
			}
			frames <- req
		}
	}()

	var pending [][]byte
	for {
		var req []byte
		if len(pending) > 0 {
			req, pending = pending[0], pending[1:]
		} else {
			var ok bool
			if req, ok = <-frames; !ok {
				return
			}
		}

		if PacketCodec(req).Command() == SMB2_WRITE {
			// A serial client sends nothing else until this WRITE is answered.
			select {
			case next, ok := <-frames:
				if ok {
					f.overlapped = true
					pending = append(pending, next)
				}
			case <-time.After(50 * time.Millisecond):
			}
		}

		resp := f.answer(req)
		p := PacketCodec(resp)
		p.SetSessionId(fakeSession)
		p.SetTreeId(1)
		p.SetCreditResponse(64)
		if writeFrame(conn, signSMB21(resp, key)) != nil {
			return
		}
	}
}

func (f *fakeFiles) answer(req []byte) []byte {
	le := binary.LittleEndian
	switch PacketCodec(req).Command() {
	case SMB2_TREE_CONNECT:
		body := make([]byte, 16)
		le.PutUint16(body[0:], 16)
		body[2] = SMB2_SHARE_TYPE_DISK
		return response(req, STATUS_SUCCESS, body)
	case SMB2_CREATE:
		body := make([]byte, 88)
		le.PutUint16(body[0:], 89)
		le.PutUint64(body[48:], uint64(len(f.data))) // EndofFile
		body[64] = 1                                 // FileId
		return response(req, STATUS_SUCCESS, body)
	case SMB2_QUERY_INFO:
		body := make([]byte, 8+24) // FileStandardInformation
		le.PutUint16(body[0:], 9)
		le.PutUint16(body[2:], 64+8)
		le.PutUint32(body[4:], 24)
		le.PutUint64(body[8+8:], uint64(len(f.data)))
		return response(req, STATUS_SUCCESS, body)
	case SMB2_WRITE:
		w := WriteRequestDecoder(req[64:])
		data := req[w.DataOffset() : uint32(w.DataOffset())+w.Length()]
		off := int(w.Offset())
		if f.appendOnly {
			off = len(f.data)
		}
		if end := off + len(data); end > len(f.data) {
			f.data = append(f.data, make([]byte, end-len(f.data))...)
		}
		copy(f.data[off:], data)
		body := make([]byte, 16)
		le.PutUint16(body[0:], 17)
		le.PutUint32(body[4:], uint32(len(data)))
		return response(req, STATUS_SUCCESS, body)
	case SMB2_READ:
		r := ReadRequestDecoder(req[64:])
		off := int(r.Offset())
		if off >= len(f.data) {
			body := make([]byte, 9)
			le.PutUint16(body[0:], 9)
			return response(req, STATUS_END_OF_FILE, body)
		}
		data := f.data[off:min(off+int(r.Length()), len(f.data))]
		body := make([]byte, 16+len(data))
		le.PutUint16(body[0:], 17)
		body[2] = 64 + 16 // DataOffset
		le.PutUint32(body[4:], uint32(len(data)))
		copy(body[16:], data)
		return response(req, STATUS_SUCCESS, body)
	case SMB2_CLOSE:
		body := make([]byte, 60)
		le.PutUint16(body[0:], 60)
		return response(req, STATUS_SUCCESS, body)
	default:
		body := make([]byte, 9)
		le.PutUint16(body[0:], 9)
		return response(req, STATUS_NOT_SUPPORTED, body)
	}
}
