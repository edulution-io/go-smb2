package smb2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/edulution-io/go-smb2/internal/crypto/ccm"
	. "github.com/edulution-io/go-smb2/internal/smb2"
)

func newTestAEAD(t *testing.T, cipherId uint16) cipher.AEAD {
	t.Helper()

	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}

	ciph, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	switch cipherId {
	case AES128GCM:
		aead, err := cipher.NewGCMWithNonceSize(ciph, 12)
		if err != nil {
			t.Fatal(err)
		}
		return aead
	default:
		aead, err := ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			t.Fatal(err)
		}
		return aead
	}
}

// TestDecryptBufferCapacity covers both buffers decrypt can be handed. On a
// buffer from newRecvBuffer the tag is appended within spare capacity and the
// packet is decrypted in place; on a tightly sized one the append reallocates.
// Both must recover the same plaintext.
func TestDecryptBufferCapacity(t *testing.T) {
	for _, tt := range []struct {
		name     string
		cipherId uint16
	}{
		{"AES128GCM", AES128GCM},
		{"AES128CCM", AES128CCM},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, size := range []int{0, 1, 64, 4096} {
				s := &session{
					sessionId: 0x1122334455667788,
					encrypter: newTestAEAD(t, tt.cipherId),
					decrypter: newTestAEAD(t, tt.cipherId),
				}

				want := benchPacket(size)

				wire, err := s.encrypt(want)
				if err != nil {
					t.Fatalf("encrypt(%d): %v", size, err)
				}

				// In-place path: spare capacity for the appended tag.
				spare := newRecvBuffer(len(wire))
				copy(spare, wire)

				gotInPlace, err := s.decrypt(spare)
				if err != nil {
					t.Fatalf("decrypt in place (%d): %v", size, err)
				}
				if !bytes.Equal(gotInPlace, want) {
					t.Errorf("decrypt in place (%d) = %x, want %x", size, gotInPlace, want)
				}
				// The plaintext must land in the received buffer itself,
				// otherwise the spare capacity stopped saving the copy.
				if &gotInPlace[0] != &spare[52] {
					t.Errorf("decrypt (%d) reallocated instead of decrypting in place", size)
				}

				// Fallback path: no spare capacity, so append must copy.
				tight := make([]byte, len(wire))
				copy(tight, wire)

				gotCopied, err := s.decrypt(tight)
				if err != nil {
					t.Fatalf("decrypt copied (%d): %v", size, err)
				}
				if !bytes.Equal(gotCopied, want) {
					t.Errorf("decrypt copied (%d) = %x, want %x", size, gotCopied, want)
				}
			}
		})
	}
}

// TestDecryptRejectsTamperedPacket guards that decrypting in place does not
// weaken authentication: a flipped ciphertext bit must still fail.
func TestDecryptRejectsTamperedPacket(t *testing.T) {
	s := &session{
		sessionId: 0x1122334455667788,
		encrypter: newTestAEAD(t, AES128GCM),
		decrypter: newTestAEAD(t, AES128GCM),
	}

	wire, err := s.encrypt(benchPacket(256))
	if err != nil {
		t.Fatal(err)
	}

	pkt := newRecvBuffer(len(wire))
	copy(pkt, wire)
	pkt[60] ^= 0x01

	if _, err := s.decrypt(pkt); err == nil {
		t.Fatal("decrypt accepted a tampered packet")
	}
}
