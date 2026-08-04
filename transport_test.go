package smb2

import (
	"io"
	"net"
	"testing"
)

// decoratedConn is the shape a caller hands to Dialer.Dial to wrap the socket:
// it embeds *net.TCPConn and overrides Write. Embedding also promotes the
// writeBuffers that net.Buffers.WriteTo looks for, which is the trap this guards.
type decoratedConn struct {
	*net.TCPConn
	writes int
}

func (c *decoratedConn) Write(p []byte) (int, error) {
	c.writes++

	return c.TCPConn.Write(p)
}

// dialLoopback returns the client side of a TCP pair whose peer drains writes.
func dialLoopback(t *testing.T) *net.TCPConn {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	done := make(chan struct{})

	go func() {
		defer close(done)

		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		io.Copy(io.Discard, c)
	}()

	t.Cleanup(func() { <-done })

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	return c.(*net.TCPConn)
}

func TestWriteKeepsDecoratedConn(t *testing.T) {
	c := &decoratedConn{TCPConn: dialLoopback(t)}
	pkt := make([]byte, 512)

	n, err := direct(c).Write(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if c.writes == 0 {
		t.Error("the wrapper's Write was bypassed; the vector reached the embedded socket")
	}

	if n != len(pkt) {
		t.Errorf("Write returned %d, want %d", n, len(pkt))
	}
}

func TestWriteReportsPayloadLength(t *testing.T) {
	// A bare *net.TCPConn takes the writev path, where the length prefix is
	// framing and must not be counted into what the caller is told went out.
	pkt := make([]byte, 512)

	n, err := direct(dialLoopback(t)).Write(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if n != len(pkt) {
		t.Errorf("Write returned %d, want %d", n, len(pkt))
	}
}
