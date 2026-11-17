package smb2

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/edulution-io/go-smb2/internal/crypto/ccm"

	. "github.com/edulution-io/go-smb2/internal/smb2"
)

func encryptingConn(tb testing.TB, cipherId uint16) *conn {
	tb.Helper()
	ciph, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		tb.Fatal(err)
	}
	var aead cipher.AEAD
	switch cipherId {
	case AES128CCM:
		aead, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
	default:
		aead, err = cipher.NewGCMWithNonceSize(ciph, 12)
	}
	if err != nil {
		tb.Fatal(err)
	}
	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(64),
		requireEncryption:   true,
		sequenceWindow:      1,
	}
	c.session = &session{conn: c, sessionId: 9, encrypter: aead, decrypter: aead}
	return c
}

func writeRequest(size int) *WriteRequest {
	req := &WriteRequest{FileId: &FileId{}, Data: bytes.Repeat([]byte{0xab}, size)}
	req.CreditCharge = 1
	return req
}

// Requests are encoded behind the transform header and sealed in place; the
// receiving end must get back exactly the encoded request.
func TestEncryptedRequestRoundTrip(t *testing.T) {
	for _, cipherId := range []uint16{AES128CCM, AES128GCM} {
		c := encryptingConn(t, cipherId)
		req := writeRequest(4096)

		rr, err := c.makeRequestResponse(req, nil, context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !rr.encrypted {
			t.Fatal("request not encrypted")
		}

		pkt, err := c.session.decrypt(append([]byte(nil), rr.pkt...))
		if err != nil {
			t.Fatalf("cipher %#x: %v", cipherId, err)
		}

		want := make([]byte, req.Size())
		req.Encode(want)
		if !bytes.Equal(pkt, want) {
			t.Errorf("cipher %#x: decrypted request differs from the encoded one", cipherId)
		}
	}
}

func BenchmarkEncryptedWriteRequest(b *testing.B) {
	for _, sz := range payloadSizes {
		b.Run(sz.name, func(b *testing.B) {
			c := encryptingConn(b, AES128GCM)
			req := writeRequest(sz.size)
			b.SetBytes(int64(sz.size))
			b.ReportAllocs()
			for b.Loop() {
				rr, err := c.makeRequestResponse(req, nil, context.Background())
				if err != nil {
					b.Fatal(err)
				}
				c.outstandingRequests.pop(rr.msgId)
			}
		})
	}
}
