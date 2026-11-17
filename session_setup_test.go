package smb2

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/asn1"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/edulution-io/go-smb2/internal/crypto/cmac"
	"github.com/edulution-io/go-smb2/internal/spnego"

	. "github.com/edulution-io/go-smb2/internal/erref"
	. "github.com/edulution-io/go-smb2/internal/smb2"
)

func newSigningSession(t *testing.T, dialect uint16) *session {
	t.Helper()
	ciph, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	return &session{
		conn:     &conn{dialect: dialect},
		signer:   cmac.New(ciph),
		verifier: cmac.New(ciph),
	}
}

func newResponse(t *testing.T, msgId uint64) []byte {
	t.Helper()
	req := new(LogoffRequest)
	req.MessageId = msgId
	pkt := make([]byte, req.Size())
	req.Encode(pkt)
	p := PacketCodec(pkt)
	p.SetFlags(p.Flags() | SMB2_FLAGS_SERVER_TO_REDIR)
	return pkt
}

// The final SESSION_SETUP response used to be accepted without looking at its
// signature, so SMB 3.1.1 preauth integrity never caught an altered negotiation.
func TestVerifySessionSetup(t *testing.T) {
	const guest = SMB2_SESSION_FLAG_IS_GUEST

	tests := []struct {
		name           string
		dialect        uint16
		requireSigning bool
		requireEncrypt bool
		flags          uint16
		signed         bool
		tamper         bool
		ok             bool
	}{
		{name: "signed", dialect: SMB311, signed: true, ok: true},
		{name: "tampered", dialect: SMB311, signed: true, tamper: true},
		{name: "unsigned 3.1.1", dialect: SMB311},
		{name: "unsigned 3.0 with signing required", dialect: SMB300, requireSigning: true},
		{name: "unsigned 3.0", dialect: SMB300, ok: true},
		{name: "tampered 3.0", dialect: SMB300, signed: true, tamper: true},
		{name: "guest", dialect: SMB311, flags: guest, ok: true},
		{name: "guest with signing required", dialect: SMB311, flags: guest, requireSigning: true},
		{name: "guest with encryption required", dialect: SMB311, flags: guest, requireEncrypt: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSigningSession(t, tt.dialect)
			s.requireSigning = tt.requireSigning
			s.requireEncryption = tt.requireEncrypt
			s.sessionFlags = tt.flags

			pkt := newResponse(t, 2)
			if tt.signed {
				pkt = s.sign(pkt)
			}
			if tt.tamper {
				pkt[len(pkt)-1] ^= 0xff
			}

			err := s.verifySessionSetup(pkt)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("response accepted")
			}
		})
	}
}

// scriptedTransport answers every written request with what reply returns.
type scriptedTransport struct {
	reply  func(req []byte) []byte
	in     chan []byte
	next   []byte
	closed chan struct{}
	once   sync.Once
}

func newScriptedTransport(reply func(req []byte) []byte) *scriptedTransport {
	return &scriptedTransport{reply: reply, in: make(chan []byte, 4), closed: make(chan struct{})}
}

func (t *scriptedTransport) Write(p []byte) (int, error) {
	t.in <- t.reply(p)
	return len(p), nil
}

func (t *scriptedTransport) ReadSize() (int, error) {
	select {
	case t.next = <-t.in:
		return len(t.next), nil
	case <-t.closed:
		return -1, net.ErrClosed
	}
}

func (t *scriptedTransport) Read(p []byte) (int, error) {
	return copy(p, t.next), nil
}

func (t *scriptedTransport) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

type fakeInitiator struct{ key []byte }

func (i *fakeInitiator) oid() asn1.ObjectIdentifier      { return spnego.NlmpOid }
func (i *fakeInitiator) initSecContext() ([]byte, error) { return []byte("negotiate"), nil }
func (i *fakeInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	return []byte("authenticate"), nil
}
func (i *fakeInitiator) sum(bs []byte) []byte { return nil }
func (i *fakeInitiator) sessionKey() []byte   { return i.key }

// The flags of the intermediate SESSION_SETUP response used to decide whether
// keys were derived, so a guest flag there followed by a signed final response
// left the verifier nil and panicked.
func TestSessionSetupIgnoresIntermediateFlags(t *testing.T) {
	sessionKey := bytes.Repeat([]byte{0x11}, 16)

	for _, tt := range []struct {
		name    string
		signKey []byte
		ok      bool
	}{
		{name: "signed with the session key", signKey: sessionKey, ok: true},
		{name: "signed with another key", signKey: bytes.Repeat([]byte{0x22}, 16)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server := &session{conn: &conn{dialect: SMB210}, signer: hmac.New(sha256.New, tt.signKey)}

			tr := newScriptedTransport(func(req []byte) []byte {
				res := &SessionSetupResponse{}
				res.Flags = SMB2_FLAGS_SERVER_TO_REDIR
				res.MessageId = PacketCodec(req).MessageId()
				res.SessionId = 1
				res.CreditRequestResponse = 1

				if res.MessageId == 0 {
					token, err := spnego.EncodeNegTokenResp(1, spnego.NlmpOid, []byte("challenge"), nil)
					if err != nil {
						panic(err)
					}
					res.Status = uint32(STATUS_MORE_PROCESSING_REQUIRED)
					res.SessionFlags = SMB2_SESSION_FLAG_IS_GUEST
					res.SecurityBuffer = token
				}

				pkt := make([]byte, res.Size())
				res.Encode(pkt)
				if res.MessageId != 0 {
					pkt = server.sign(pkt)
				}
				return pkt
			})

			c := &conn{
				t:                   tr,
				outstandingRequests: newOutstandingRequests(),
				account:             openAccount(64),
				rdone:               make(chan struct{}, 1),
				wdone:               make(chan struct{}, 1),
				write:               make(chan *outgoing, 1),
				dialect:             SMB210,
				requireSigning:      true,
			}
			go c.runSender()
			go c.runReciever()
			t.Cleanup(func() { _ = tr.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, err := sessionSetup(c, &fakeInitiator{key: sessionKey}, ctx)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("session accepted")
			}
		})
	}
}

// A response to an encrypted request must be encrypted too; a plaintext one can
// come from anyone on the path.
func TestUnencryptedResponseToEncryptedRequest(t *testing.T) {
	for _, isEncrypted := range []bool{false, true} {
		c := &conn{outstandingRequests: newOutstandingRequests(), account: openAccount(64)}
		rr := &requestResponse{msgId: 7, recv: make(chan []byte, 1), encrypted: true}
		c.outstandingRequests.set(rr.msgId, rr)

		if err := c.tryHandle(newResponse(t, rr.msgId), nil, isEncrypted); err != nil {
			t.Fatal(err)
		}

		<-rr.recv
		if isEncrypted && rr.err != nil {
			t.Errorf("encrypted response rejected: %v", rr.err)
		}
		if !isEncrypted && rr.err == nil {
			t.Error("unencrypted response accepted")
		}
	}
}

func TestNegotiateRequestDialects(t *testing.T) {
	tests := []struct {
		name string
		n    Negotiator
		want []uint16
	}{
		{name: "default", want: clientDialects},
		{name: "min 3.0", n: Negotiator{MinDialect: Dialect300}, want: []uint16{SMB311, SMB302, SMB300}},
		{name: "min 3.1.1", n: Negotiator{MinDialect: Dialect311}, want: []uint16{SMB311}},
		{name: "encryption", n: Negotiator{RequireEncryption: true}, want: []uint16{SMB311, SMB302, SMB300}},
		{name: "specified", n: Negotiator{SpecifiedDialect: Dialect302, MinDialect: Dialect300}, want: []uint16{SMB302}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := tt.n.makeRequest()
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(req.Dialects, tt.want) {
				t.Errorf("dialects %#x, want %#x", req.Dialects, tt.want)
			}
		})
	}

	for _, n := range []Negotiator{
		{SpecifiedDialect: Dialect210, MinDialect: Dialect300},
		{SpecifiedDialect: Dialect210, RequireEncryption: true},
		{MinDialect: 0x0400},
	} {
		if _, err := n.makeRequest(); err == nil {
			t.Errorf("%+v: request built", n)
		}
	}
}

// TestSessionSetup_AcceptsASignedFinalResponse is the control for the tests
// below: an honest server's login completes.
func TestSessionSetup_AcceptsASignedFinalResponse(t *testing.T) {
	sess, err := dialFake(t, &fakeServer{})
	if err != nil {
		t.Fatalf("login against an honest server failed: %v", err)
	}
	_ = sess.s.t.Close()
}

// TestSessionSetup_RejectsATamperedFinalResponse pins that the final
// SESSION_SETUP response, which arrives before the receiver verifies anything,
// is verified by sessionSetup itself when signing is required.
func TestSessionSetup_RejectsATamperedFinalResponse(t *testing.T) {
	tests := []struct {
		name  string
		want  string
		final func(pkt, key []byte) []byte
	}{
		{"guest flag set by a man in the middle", "guest or anonymous session", func(pkt, _ []byte) []byte {
			pkt[64+2] = byte(SMB2_SESSION_FLAG_IS_GUEST)
			return pkt
		}},
		{"null flag set by a man in the middle", "guest or anonymous session", func(pkt, _ []byte) []byte {
			pkt[64+2] = byte(SMB2_SESSION_FLAG_IS_NULL)
			return pkt
		}},
		{"guest flag on an unsigned response", "guest or anonymous session", func(pkt, _ []byte) []byte {
			p := PacketCodec(pkt)
			p.SetFlags(p.Flags() &^ SMB2_FLAGS_SIGNED)
			p.SetSignature(make([]byte, 16))
			pkt[64+2] = byte(SMB2_SESSION_FLAG_IS_GUEST)
			return pkt
		}},
		{"signature stripped", "unsigned session setup response", func(pkt, _ []byte) []byte {
			p := PacketCodec(pkt)
			p.SetFlags(p.Flags() &^ SMB2_FLAGS_SIGNED)
			p.SetSignature(make([]byte, 16))
			return pkt
		}},
		{"signature forged", "unverified session setup response", func(pkt, _ []byte) []byte {
			sig := PacketCodec(pkt).Signature()
			for i := range sig {
				sig[i] ^= 0xff
			}
			return pkt
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := dialFake(t, &fakeServer{final: tt.final})
			wantInvalid(t, sess, err, tt.want)
		})
	}
}

// TestSessionSetup_VerifiesASignedFinalResponseWhenSigningIsOptional pins that
// a final response carrying a signature is checked even when neither side
// requires signing, so its flags cannot be rewritten under a forged one.
func TestSessionSetup_VerifiesASignedFinalResponseWhenSigningIsOptional(t *testing.T) {
	sess, err := dialFake(t, &fakeServer{signingOptional: true})
	if err != nil {
		t.Fatalf("login against an honest server failed: %v", err)
	}
	_ = sess.s.t.Close()

	sess, err = dialFake(t, &fakeServer{signingOptional: true, final: func(pkt, _ []byte) []byte {
		pkt[64+2] = byte(SMB2_SESSION_FLAG_ENCRYPT_DATA)
		return pkt
	}})
	wantInvalid(t, sess, err, "unverified session setup response")
}
