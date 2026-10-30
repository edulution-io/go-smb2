package smb2

import (
	"crypto/aes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/edulution-io/go-smb2/internal/crypto/ccm"
	. "github.com/edulution-io/go-smb2/internal/smb2"
)

// TestReceiver_FailsTheConnectionOnAMalformedFrame pins that a frame the
// receiver cannot parse fails the request instead of panicking in the receiver
// goroutine, which would take the whole process down. These arrive before any
// session exists, so neither signing nor encryption can stop them.
func TestReceiver_FailsTheConnectionOnAMalformedFrame(t *testing.T) {
	withNextCommand := func(next uint32) func([]byte) []byte {
		return func(req []byte) []byte {
			pkt := negotiateResponse(req, SMB210)
			binary.LittleEndian.PutUint32(pkt[20:24], next)
			return pkt
		}
	}
	tests := []struct {
		name      string
		negotiate func([]byte) []byte
		want      string
	}{
		{"four zero bytes", func([]byte) []byte { return make([]byte, 4) }, "malformed response"},
		{"header cut short", func(req []byte) []byte { return negotiateResponse(req, SMB210)[:40] }, "malformed response"},
		{"next command beyond the frame", withNextCommand(0x1000), "malformed response"},
		{"next command inside the header", withNextCommand(8), "malformed response"},
		// The head is delivered before the tail is parsed, so the dial fails on
		// the cut-short NEGOTIATE body; what matters is that the tail does not panic.
		{"next command leaving a short tail", withNextCommand(64 + 64 - 8), "negotiate response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := dialFake(t, &fakeServer{negotiate: tt.negotiate})
			wantInvalid(t, sess, err, tt.want)
		})
	}
}

// TestReceiver_RejectsAnUnexpectedDialect pins that a dialect the client did
// not offer fails the dial: no signer or cipher exists for it, and the login
// that follows would verify with none.
func TestReceiver_RejectsAnUnexpectedDialect(t *testing.T) {
	for _, dialect := range []uint16{0x0201, 0x0399} {
		sess, err := dialFake(t, &fakeServer{dialect: dialect})
		wantInvalid(t, sess, err, "unexpected dialect")
	}
}

// TestReceiver_FailsTheConnectionOnAShortDecryptedPacket pins that a transform
// frame whose plaintext is shorter than a header ends the connection instead
// of panicking when the receiver reads its session id.
func TestReceiver_FailsTheConnectionOnAShortDecryptedPacket(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	c := &conn{
		t:                   direct(client),
		outstandingRequests: newOutstandingRequests(),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
	}
	c.session = &session{
		conn:      c,
		sessionId: fakeSession,
		encrypter: newTestAEAD(t, AES128GCM),
		decrypter: newTestAEAD(t, AES128GCM),
	}
	c.enableSession()
	done := make(chan struct{})
	go func() {
		c.runReciever()
		close(done)
	}()

	frame, err := c.session.encrypt(make([]byte, 20))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(server, frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the receiver kept running after a short decrypted packet")
	}
	c.m.Lock()
	defer c.m.Unlock()
	if c.err != malformedFrame {
		t.Errorf("conn.err = %v, want %v", c.err, malformedFrame)
	}
}

// TestReceiver_GivesUpOnARepeatedWildcardDialect pins that a server answering
// every NEGOTIATE with the SMB 2.??? wildcard cannot keep the client looping.
func TestReceiver_GivesUpOnARepeatedWildcardDialect(t *testing.T) {
	sess, err := dialFake(t, &fakeServer{negotiate: func(req []byte) []byte {
		return negotiateResponse(req, SMB2)
	}})
	wantInvalid(t, sess, err, "unexpected dialect")
}

func TestCCMOpen_RejectsCiphertextNoLongerThanTheTag(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := ccm.NewCCMWithNonceAndTagSizes(block, 11, 16)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 15, 16} {
		if _, err := aead.Open(nil, make([]byte, 11), make([]byte, n), nil); err == nil {
			t.Errorf("Open of %d bytes = nil error, want a rejection", n)
		}
	}
}

// TestTryDecrypt_RejectsATransformFrameWithoutACipher pins that a transform
// frame on a session that set up no cipher (SMB 2.x, guest, or 3.x without
// encryption) is refused rather than handed to a nil AEAD.
func TestTryDecrypt_RejectsATransformFrameWithoutACipher(t *testing.T) {
	c := &conn{}
	c.session = &session{conn: c, sessionId: fakeSession}
	pkt := make([]byte, 52+64)
	tc := TransformCodec(pkt)
	tc.SetProtocolId()
	tc.SetFlags(Encrypted)
	tc.SetSessionId(fakeSession)

	if _, err, _ := c.tryDecrypt(pkt); err == nil {
		t.Error("tryDecrypt = nil error, want a rejection")
	}
}

// TestTryVerify_RejectsASignedFrameWithoutAVerifier pins the same for a frame
// flagged as signed on a session with no signing key.
func TestTryVerify_RejectsASignedFrameWithoutAVerifier(t *testing.T) {
	c := &conn{outstandingRequests: newOutstandingRequests()}
	c.session = &session{conn: c, sessionId: fakeSession}
	pkt := make([]byte, 64)
	p := PacketCodec(pkt)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_SIGNED)
	p.SetSessionId(fakeSession)
	p.SetMessageId(1)

	if err := c.tryVerify(pkt, false); err == nil {
		t.Error("tryVerify = nil error, want a rejection")
	}
}
