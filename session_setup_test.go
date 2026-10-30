package smb2

import (
	"testing"

	. "github.com/edulution-io/go-smb2/internal/smb2"
)

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
		{"guest flag set by a man in the middle", "guest account", func(pkt, _ []byte) []byte {
			pkt[64+2] = byte(SMB2_SESSION_FLAG_IS_GUEST)
			return pkt
		}},
		{"null flag set by a man in the middle", "anonymous account", func(pkt, _ []byte) []byte {
			pkt[64+2] = byte(SMB2_SESSION_FLAG_IS_NULL)
			return pkt
		}},
		{"guest flag on an unsigned response", "guest account", func(pkt, _ []byte) []byte {
			p := PacketCodec(pkt)
			p.SetFlags(p.Flags() &^ SMB2_FLAGS_SIGNED)
			p.SetSignature(make([]byte, 16))
			pkt[64+2] = byte(SMB2_SESSION_FLAG_IS_GUEST)
			return pkt
		}},
		{"signature stripped", "signature verification", func(pkt, _ []byte) []byte {
			p := PacketCodec(pkt)
			p.SetFlags(p.Flags() &^ SMB2_FLAGS_SIGNED)
			p.SetSignature(make([]byte, 16))
			return pkt
		}},
		{"signature forged", "signature verification", func(pkt, _ []byte) []byte {
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
	wantInvalid(t, sess, err, "signature verification")
}
