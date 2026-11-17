package ntlm

import (
	"bytes"
	"testing"
)

// challengeMessage builds a CHALLENGE_MESSAGE of total length n that clears
// the signature, message type and negotiate flag checks, so a case can set the
// TargetName and TargetInfo fields to whatever it needs to exercise.
func challengeMessage(n int) []byte {
	cmsg := make([]byte, n)
	copy(cmsg[:8], signature)
	le.PutUint32(cmsg[8:12], NtLmChallenge)
	le.PutUint32(cmsg[20:24], defaultFlags)
	return cmsg
}

// Both payload fields were validated as offset+length in uint32, so a
// server-controlled offset of 0xFFFFFFFF with a length of 1 carried the sum
// to 0 and cleared the guard.
func TestClientAuthenticateRejectsWrappingPayloadOffsets(t *testing.T) {
	tests := []struct {
		name  string
		build func() []byte
	}{
		{"TargetName offset wraps the sum to 0", func() []byte {
			cmsg := challengeMessage(64)
			le.PutUint16(cmsg[12:14], 1)          // TargetNameLen
			le.PutUint16(cmsg[14:16], 1)          // TargetNameMaxLen
			le.PutUint32(cmsg[16:20], 0xFFFFFFFF) // TargetNameBufferOffset
			return cmsg
		}},
		{"TargetName offset past the end", func() []byte {
			cmsg := challengeMessage(64)
			le.PutUint16(cmsg[12:14], 8)
			le.PutUint16(cmsg[14:16], 8)
			le.PutUint32(cmsg[16:20], 60)
			return cmsg
		}},
		{"TargetInfo offset wraps the sum to 0", func() []byte {
			cmsg := challengeMessage(64)
			le.PutUint16(cmsg[40:42], 1)          // TargetInfoLen
			le.PutUint16(cmsg[42:44], 1)          // TargetInfoMaxLen
			le.PutUint32(cmsg[44:48], 0xFFFFFFFF) // TargetInfoBufferOffset
			return cmsg
		}},
		{"TargetInfo offset past the end", func() []byte {
			cmsg := challengeMessage(64)
			le.PutUint16(cmsg[40:42], 8)
			le.PutUint16(cmsg[42:44], 8)
			le.PutUint32(cmsg[44:48], 60)
			return cmsg
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{User: "u", Password: "p"}
			if _, err := c.Negotiate(); err != nil {
				t.Fatalf("Negotiate() = %v", err)
			}

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Authenticate() panicked: %v", r)
				}
			}()

			if _, err := c.Authenticate(tt.build()); err == nil {
				t.Error("Authenticate() = nil error, want a rejection")
			}
		})
	}
}

// MS-NLMP 3.1.5.1.2 exchanges a random session key only when KEY_EXCH comes
// with SIGN or SEAL. A server that clears both but keeps KEY_EXCH must get no
// EncryptedRandomSessionKey, and both sides must settle on KeyExchangeKey.
func TestKeyExchangeRequiresSignOrSeal(t *testing.T) {
	c := &Client{User: "user", Password: "password"}
	s := NewServer("server")
	s.AddAccount("user", "password")

	nmsg, err := c.Negotiate()
	if err != nil {
		t.Fatal(err)
	}
	cmsg, err := s.Challenge(nmsg)
	if err != nil {
		t.Fatal(err)
	}
	flags := le.Uint32(cmsg[20:24]) &^ (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL)
	if flags&NTLMSSP_NEGOTIATE_KEY_EXCH == 0 {
		t.Fatal("the challenge does not offer KEY_EXCH; the case tests nothing")
	}
	le.PutUint32(cmsg[20:24], flags)

	amsg, err := c.Authenticate(cmsg)
	if err != nil {
		t.Fatal(err)
	}
	if n := le.Uint16(amsg[52:54]); n != 0 {
		t.Errorf("EncryptedRandomSessionKeyLen = %d, want 0", n)
	}
	if err := s.Authenticate(amsg); err != nil {
		t.Fatalf("server Authenticate() = %v", err)
	}
	if !bytes.Equal(c.Session().SessionKey(), s.Session().SessionKey()) {
		t.Error("client and server derived different session keys")
	}
}
