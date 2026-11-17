package smb2

import (
	"crypto/aes"
	"slices"
	"testing"

	"github.com/edulution-io/go-smb2/internal/crypto/cmac"

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
