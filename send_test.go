package smb2

import (
	"bytes"
	"context"
	"crypto/aes"
	"hash"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/edulution-io/go-smb2/internal/crypto/cmac"

	. "github.com/edulution-io/go-smb2/internal/smb2"
)

// sendingConn returns a conn whose transport accepts every write and answers
// nothing, with a session that signs or, with encrypt, encrypts (GCM).
func sendingConn(tb testing.TB, encrypt bool) *conn {
	tb.Helper()
	c := encryptingConn(tb, 0)
	c.requireEncryption = encrypt
	ciph, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		tb.Fatal(err)
	}
	c.session.newSigner = func() hash.Hash { return cmac.New(ciph) }
	c.session.verifier = cmac.New(ciph)
	c.t = newFakeTransport(func([]byte) error { return nil })
	c.rdone = make(chan struct{}, 1)
	c.wdone = make(chan struct{}, 1)
	c.write = make(chan *outgoing)
	go c.runSender()
	tb.Cleanup(func() { close(c.wdone) })
	return c
}

// Goroutines sharing a connection, as the fileproxy's do, each send 1 MiB
// writes. Preparing a request used to happen under the connection lock.
func BenchmarkParallelSend(b *testing.B) {
	for _, mode := range []struct {
		name    string
		encrypt bool
	}{{"signed", false}, {"encrypted", true}} {
		b.Run(mode.name, func(b *testing.B) {
			c := sendingConn(b, mode.encrypt)
			b.SetBytes(1 << 20)
			b.RunParallel(func(pb *testing.PB) {
				req := writeRequest(1 << 20)
				for pb.Next() {
					rr, err := c.sendWith(req, nil, context.Background())
					if err != nil {
						b.Error(err)
						return
					}
					c.outstandingRequests.pop(rr.msgId)
				}
			})
		})
	}
}

// Requests prepared in parallel must each come out intact, with their own
// message id: signing and CCM keep state that used to be safe only because
// the connection lock serialized them.
func TestParallelSendsAreIntact(t *testing.T) {
	for _, mode := range []struct {
		name     string
		cipherId uint16
		encrypt  bool
	}{{"signed", 0, false}, {"ccm", AES128CCM, true}, {"gcm", AES128GCM, true}} {
		t.Run(mode.name, func(t *testing.T) {
			c := sendingConn(t, mode.encrypt)
			if mode.encrypt {
				c.session = encryptingConn(t, mode.cipherId).session
				c.session.conn = c
			}
			var mu sync.Mutex
			var sent [][]byte
			c.t.(*fakeTransport).onWrite = func(p []byte) error {
				mu.Lock()
				sent = append(sent, append([]byte(nil), p...))
				mu.Unlock()
				return nil
			}

			const senders, perSender = 8, 25
			var wg sync.WaitGroup
			for g := 0; g < senders; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < perSender; i++ {
						rr, err := c.sendWith(writeRequest(1000+g), nil, context.Background())
						if err != nil {
							t.Error(err)
							return
						}
						c.outstandingRequests.pop(rr.msgId)
					}
				}()
			}
			wg.Wait()

			ids := map[uint64]bool{}
			for _, pkt := range sent {
				if mode.encrypt {
					var err error
					if pkt, err = c.session.decrypt(pkt); err != nil {
						t.Fatal(err)
					}
				} else if !c.session.verify(append([]byte(nil), pkt...)) {
					t.Fatal("bad signature")
				}
				id := PacketCodec(pkt).MessageId()
				if ids[id] {
					t.Fatalf("message id %d sent twice", id)
				}
				ids[id] = true
			}
			if len(ids) != senders*perSender {
				t.Fatalf("%d requests sent, want %d", len(ids), senders*perSender)
			}
		})
	}
}

// The signers sign pools are made by a closure; it must sign with the same key
// the verifier checks, for every dialect.
func TestDerivedSignerMatchesVerifier(t *testing.T) {
	for _, dialect := range []uint16{SMB202, SMB210, SMB300, SMB302, SMB311} {
		s := &session{conn: &conn{dialect: dialect, preauthIntegrityHashId: SHA512, cipherId: AES128GCM}}
		if err := s.deriveKeys(bytes.Repeat([]byte{7}, 16), make([]byte, 64)); err != nil {
			t.Fatal(err)
		}
		pkt := s.sign(newResponse(t, 1))
		if !s.verify(pkt) {
			t.Errorf("dialect %#x: the verifier rejects what the signer signed", dialect)
		}
	}
}

// A request is visible to the receiver as soon as it is registered, before it
// is encoded. If it only learned then that it is encrypted, a plaintext
// response injected in between passed the encrypted-response check.
func TestRequestRegisteredWithItsEncryption(t *testing.T) {
	c := encryptingConn(t, AES128GCM)

	rr := c.registerRequest(writeRequest(16), nil, context.Background())
	if !rr.encrypted {
		t.Fatal("request registered without its encryption requirement")
	}

	if err := c.tryHandle(newResponse(t, rr.msgId), nil, false); err != nil {
		t.Fatal(err)
	}
	<-rr.recv
	if rr.err == nil {
		t.Fatal("plaintext response accepted while the request was being encoded")
	}
}

// encodeBlocker holds a request in Encode until release is closed.
type encodeBlocker struct {
	*LogoffRequest
	encoding, release chan struct{}
}

func (r encodeBlocker) Encode(pkt []byte) {
	close(r.encoding)
	<-r.release
	r.LogoffRequest.Encode(pkt)
}

// The receiver can stop while a request is being encoded, and the sender with
// it. With conn.write buffered, handing the request over still succeeded and
// sendWith then waited for a write result that never came.
func TestSendFailsOnceTheSenderStopped(t *testing.T) {
	for i := 0; i < 50; i++ {
		c := newConn(newFakeTransport(func([]byte) error { return nil }), openAccount(64))
		c.sequenceWindow = 1

		req := encodeBlocker{newRequest().(*LogoffRequest), make(chan struct{}), make(chan struct{})}

		done := make(chan error, 1)
		go func() {
			_, err := c.sendWith(req, nil, context.Background())
			done <- err
		}()

		<-req.encoding

		// What the receiver does when it stops; the sender stops with it.
		c.m.Lock()
		c.err = &TransportError{net.ErrClosed}
		close(c.wdone)
		c.m.Unlock()

		close(req.release)

		select {
		case err := <-done:
			if err == nil {
				t.Fatal("request sent without a sender")
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("run %d: sendWith hangs after the sender stopped", i)
		}
	}
}
