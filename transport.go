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
	// wv backs bufs, and bufs is a field rather than a local so that taking its
	// address for WriteTo does not escape a fresh slice header per write.
	//
	// Holding the iovec on the struct makes Write single-writer: it is reached
	// only from (*conn).runSender, which serializes every packet through one
	// goroutine. A second concurrent writer would interleave into this vector.
	wv   [2][]byte
	bufs net.Buffers
	conn net.Conn
}

func direct(tcpConn net.Conn) transport {
	return &directTCP{conn: tcpConn}
}

func (t *directTCP) Write(p []byte) (n int, err error) {
	if len(p) > maxDirectTCPSize {
		return -1, errors.New("max transport size exceeds")
	}

	bs := t.sb[:]

	be.PutUint32(bs, uint32(len(p)))

	// The length prefix and the packet go out as one writev, so a request costs
	// one syscall rather than two and the prefix never leaves as its own tiny
	// segment. On a transport that is not a TCP socket, WriteTo falls back to
	// writing each buffer in turn.
	// WriteTo consumes the vector, so rebuild it from wv on every write.
	t.bufs = append(net.Buffers(t.wv[:0]), bs, p)

	written, err := t.bufs.WriteTo(t.conn)
	if err != nil {
		return -1, err
	}

	return int(written), nil
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
