package smb2

import (
	"errors"
	"io"
	"net"
)

const (
	maxDirectTCPSize = 0xffffff // 16777215
	// maxNetBTSize     = 0x1ffff  // 131071
)

type transport interface {
	Write(p []byte) (n int, err error)
	ReadSize() (size int, err error)
	Read(p []byte) (n int, err error)
	Close() error
}

type directTCP struct {
	sb [4]byte
	rb [4]byte
	// Sharing one iovec across writes makes Write single-writer: it is reached only
	// from (*conn).runSender, and a second writer would interleave into this vector.
	wv   [2][]byte
	bufs net.Buffers
	conn net.Conn
	// vec is conn when it is a bare TCP socket. net.Buffers.WriteTo reaches the
	// writeBuffers promoted from an embedded *net.TCPConn, so a caller's wrapper
	// that overrides Write would be written straight past; only the concrete type
	// can take the vector.
	vec *net.TCPConn
}

func direct(tcpConn net.Conn) transport {
	t := &directTCP{conn: tcpConn}
	t.vec, _ = tcpConn.(*net.TCPConn)

	return t
}

func (t *directTCP) Write(p []byte) (n int, err error) {
	if len(p) > maxDirectTCPSize {
		return -1, errors.New("max transport size exceeds")
	}

	bs := t.sb[:]

	be.PutUint32(bs, uint32(len(p)))

	if t.vec == nil {
		_, err = t.conn.Write(bs)
		if err != nil {
			return -1, err
		}

		return t.conn.Write(p)
	}

	// WriteTo consumes the vector, so rebuild it from wv on every write.
	t.bufs = append(net.Buffers(t.wv[:0]), bs, p)

	written, err := t.bufs.WriteTo(t.vec)
	if err != nil {
		return -1, err
	}

	// The prefix is framing, not payload; report what the caller handed us.
	return int(written) - len(bs), nil
}

func (t *directTCP) ReadSize() (size int, err error) {
	bs := t.rb[:]

	_, err = io.ReadFull(t.conn, bs)
	if err != nil {
		return -1, err
	}

	if bs[0] != 0 {
		return -1, errors.New("invalid transport format")
	}

	return int(be.Uint32(bs)), nil
}

func (t *directTCP) Read(p []byte) (n int, err error) {
	n, err = io.ReadFull(t.conn, p)
	if err != nil {
		return -1, err
	}

	return n, err
}

func (t *directTCP) Close() error {
	return t.conn.Close()
}
