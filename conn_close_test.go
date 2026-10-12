package smb2

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	. "github.com/edulution-io/go-smb2/internal/smb2"
)

// fakeTransport reads nothing until it is closed and hands every write to
// onWrite.
type fakeTransport struct {
	closed  chan struct{}
	once    sync.Once
	onWrite func(p []byte) error
}

func newFakeTransport(onWrite func(p []byte) error) *fakeTransport {
	return &fakeTransport{closed: make(chan struct{}), onWrite: onWrite}
}

func (t *fakeTransport) Write(p []byte) (int, error) {
	if err := t.onWrite(p); err != nil {
		return -1, err
	}
	return len(p), nil
}

func (t *fakeTransport) ReadSize() (int, error) {
	<-t.closed
	return -1, net.ErrClosed
}

func (t *fakeTransport) Read(p []byte) (int, error) {
	<-t.closed
	return -1, net.ErrClosed
}

func (t *fakeTransport) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

// newFakeConn starts a conn's sender and receiver over t, as negotiate does.
func newFakeConn(t *testing.T, tr *fakeTransport) *conn {
	t.Helper()
	c := &conn{
		t:                   tr,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(64),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		write:               make(chan *outgoing, 1),
	}
	go c.runSender()
	go c.runReciever()
	t.Cleanup(func() { _ = tr.Close() })
	return c
}

func newRequest() Packet {
	req := new(LogoffRequest)
	req.CreditCharge = 1
	return req
}

// logoffClose does to the conn what session.logoff does once the server has
// answered, and waits for the receiver to finish.
func logoffClose(t *testing.T, c *conn, tr *fakeTransport) {
	t.Helper()
	c.rdone <- struct{}{}
	_ = tr.Close()
	select {
	case <-c.wdone:
	case <-time.After(5 * time.Second):
		t.Fatal("the receiver did not stop after the transport closed")
	}
}

// A request on a connection a logoff closed used to wait forever for a sender
// that had already stopped.
func TestSendAfterLogoffFails(t *testing.T) {
	tr := newFakeTransport(func([]byte) error { return nil })
	c := newFakeConn(t, tr)
	logoffClose(t, c, tr)

	errc := make(chan error, 1)
	go func() {
		_, err := c.send(newRequest(), context.Background())
		errc <- err
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("send after logoff: err = %v, want one wrapping net.ErrClosed", err)
		}
		var te *TransportError
		if !errors.As(err, &te) {
			t.Errorf("send after logoff: err = %T, want *TransportError", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("send on a connection a logoff closed did not return")
	}
}

// A request still waiting for its response when a logoff closes the connection
// used to get neither a response nor an error.
func TestPendingRequestFailsOnLogoff(t *testing.T) {
	tr := newFakeTransport(func([]byte) error { return nil })
	c := newFakeConn(t, tr)

	rr, err := c.send(newRequest(), context.Background())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	logoffClose(t, c, tr)

	pkt, err := c.recv(rr)
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("recv after logoff: pkt = %v, err = %v, want an error wrapping net.ErrClosed", pkt, err)
	}
}

// A request that stops waiting for its write used to leave the write's result
// in a channel the next request read as its own.
func TestWriteResultBelongsToItsRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	errWrite := errors.New("first write failed")
	var writes int
	var mu sync.Mutex
	tr := newFakeTransport(func([]byte) error {
		mu.Lock()
		writes++
		first := writes == 1
		mu.Unlock()
		if !first {
			return nil
		}
		close(started)
		<-release
		return errWrite
	})
	c := newFakeConn(t, tr)

	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := c.send(newRequest(), ctx)
		firstDone <- err
	}()
	<-started
	cancel()
	if err := <-firstDone; !errors.As(err, new(*ContextError)) {
		t.Fatalf("first send: err = %v, want a *ContextError", err)
	}
	close(release)

	if _, err := c.send(newRequest(), context.Background()); err != nil {
		t.Errorf("second send: err = %v, want nil: the failed write was the first request's", err)
	}
}
