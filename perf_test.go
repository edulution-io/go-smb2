package smb2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net"
	"testing"

	. "github.com/edulution-io/go-smb2/internal/smb2"
)

// Sizes that bracket real SMB traffic: a small metadata response, a
// single-credit payload, and the 1 MiB cap readAtChunk/writeAtChunk work in.
var payloadSizes = []struct {
	name string
	size int
}{
	{"4KiB", 4 * 1024},
	{"64KiB", 64 * 1024},
	{"1MiB", 1024 * 1024},
}

func benchSession(tb testing.TB) *session {
	tb.Helper()

	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}

	ciph, err := aes.NewCipher(key)
	if err != nil {
		tb.Fatal(err)
	}

	enc, err := cipher.NewGCMWithNonceSize(ciph, 12)
	if err != nil {
		tb.Fatal(err)
	}

	dec, err := cipher.NewGCMWithNonceSize(ciph, 12)
	if err != nil {
		tb.Fatal(err)
	}

	return &session{
		sessionId: 0x1122334455667788,
		signer:    hmac.New(sha256.New, key),
		verifier:  hmac.New(sha256.New, key),
		encrypter: enc,
		decrypter: dec,
	}
}

// benchPacket builds a well-formed SMB2 packet header followed by size bytes of
// payload, matching what sign/verify/encrypt see on the wire.
func benchPacket(size int) []byte {
	pkt := make([]byte, 64+size)

	p := PacketCodec(pkt)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(SMB2_READ)
	p.SetMessageId(42)
	p.SetSessionId(0x1122334455667788)

	for i := 64; i < len(pkt); i++ {
		pkt[i] = byte(i)
	}

	return pkt
}

func BenchmarkSessionDecrypt(b *testing.B) {
	for _, sz := range payloadSizes {
		b.Run(sz.name, func(b *testing.B) {
			s := benchSession(b)

			wire, err := s.encrypt(benchPacket(sz.size))
			if err != nil {
				b.Fatal(err)
			}

			b.SetBytes(int64(len(wire)))
			b.ReportAllocs()

			for b.Loop() {
				// Mirror runReciever: a fresh buffer per packet, filled from
				// the socket, then decrypted in place.
				pkt := newRecvBuffer(len(wire))
				copy(pkt, wire)

				if _, err := s.decrypt(pkt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSessionEncrypt(b *testing.B) {
	for _, sz := range payloadSizes {
		b.Run(sz.name, func(b *testing.B) {
			s := benchSession(b)
			pkt := benchPacket(sz.size)

			b.SetBytes(int64(len(pkt)))
			b.ReportAllocs()

			for b.Loop() {
				if _, err := s.encrypt(pkt); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSessionSign(b *testing.B) {
	for _, sz := range payloadSizes {
		b.Run(sz.name, func(b *testing.B) {
			s := benchSession(b)
			pkt := benchPacket(sz.size)

			b.SetBytes(int64(len(pkt)))
			b.ReportAllocs()

			for b.Loop() {
				s.sign(pkt)
			}
		})
	}
}

func BenchmarkSessionVerify(b *testing.B) {
	for _, sz := range payloadSizes {
		b.Run(sz.name, func(b *testing.B) {
			s := benchSession(b)
			pkt := s.sign(benchPacket(sz.size))

			b.SetBytes(int64(len(pkt)))
			b.ReportAllocs()

			for b.Loop() {
				if !s.verify(pkt) {
					b.Fatal("signature did not verify")
				}
			}
		})
	}
}

// countingConn is a net.Conn that discards writes and counts the calls, so a
// benchmark can observe how many Write calls one SMB packet costs.
type countingConn struct {
	net.Conn
	writes int
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes++
	return len(p), nil
}

// BenchmarkTransportWriteCalls reports Write calls per packet on a transport
// that is not a TCP socket, which is the writev fallback path.
func BenchmarkTransportWriteCalls(b *testing.B) {
	c := &countingConn{}
	t := direct(c)
	pkt := benchPacket(4 * 1024)

	b.ReportAllocs()

	var iters int
	for b.Loop() {
		if _, err := t.Write(pkt); err != nil {
			b.Fatal(err)
		}
		iters++
	}

	b.ReportMetric(float64(c.writes)/float64(iters), "writes/op")
}

// BenchmarkTransportWriteTCP measures a packet write over a real loopback TCP
// connection, where the syscall count per packet is what actually shows up.
func BenchmarkTransportWriteTCP(b *testing.B) {
	for _, sz := range payloadSizes {
		b.Run(sz.name, func(b *testing.B) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer ln.Close()

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

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				b.Fatal(err)
			}

			t := direct(c)
			pkt := benchPacket(sz.size)

			b.SetBytes(int64(len(pkt)) + 4)
			b.ReportAllocs()

			for b.Loop() {
				if _, err := t.Write(pkt); err != nil {
					b.Fatal(err)
				}
			}

			b.StopTimer()
			c.Close()
			<-done
		})
	}
}
