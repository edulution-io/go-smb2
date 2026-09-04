package ntlm

import "testing"

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

// Both payload fields are validated as offset+length in uint32, and both parts
// come from the server: an offset of 0xFFFFFFFF with a length of 1 carries the
// sum to 0, so the guard reads len(cmsg) < 0 and the slice that follows runs
// from 0xFFFFFFFF. The challenge is parsed during session setup, before any
// key is established, so this is reachable by an on-path attacker.
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
