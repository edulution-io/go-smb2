package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"sync"

	"github.com/edulution-io/go-smb2/internal/crypto/ccm"
	"github.com/edulution-io/go-smb2/internal/crypto/cmac"

	. "github.com/edulution-io/go-smb2/internal/erref"
	. "github.com/edulution-io/go-smb2/internal/smb2"
)

func sessionSetup(conn *conn, i Initiator, ctx context.Context) (*session, error) {
	spnego := newSpnegoClient([]Initiator{i})

	outputToken, err := spnego.initSecContext()
	if err != nil {
		return nil, &InvalidResponseError{err.Error()}
	}

	req := &SessionSetupRequest{
		Flags:             0,
		Capabilities:      conn.capabilities & (SMB2_GLOBAL_CAP_DFS),
		Channel:           0,
		SecurityBuffer:    outputToken,
		PreviousSessionId: 0,
	}

	if conn.requireSigning {
		req.SecurityMode = SMB2_NEGOTIATE_SIGNING_REQUIRED
	} else {
		req.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
	}

	req.CreditCharge = 1
	req.CreditRequestResponse = conn.account.initRequest()

	rr, err := conn.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := conn.recv(rr)
	if err != nil {
		return nil, err
	}

	p := PacketCodec(pkt)

	if NtStatus(p.Status()) != STATUS_MORE_PROCESSING_REQUIRED {
		return nil, &InvalidResponseError{fmt.Sprintf("expected status: %v, got %v", STATUS_MORE_PROCESSING_REQUIRED, NtStatus(p.Status()))}
	}

	res, err := accept(SMB2_SESSION_SETUP, pkt)
	if err != nil {
		return nil, err
	}

	r := SessionSetupResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken session setup response format"}
	}

	sessionFlags := r.SessionFlags()

	s := &session{
		conn:           conn,
		treeConnTables: make(map[uint32]*treeConn),
		sessionFlags:   sessionFlags,
		sessionId:      p.SessionId(),
	}

	switch conn.dialect {
	case SMB311:
		s.preauthIntegrityHashValue = conn.preauthIntegrityHashValue

		switch conn.preauthIntegrityHashId {
		case SHA512:
			h := sha512.New()
			h.Write(s.preauthIntegrityHashValue[:])
			h.Write(rr.pkt)
			h.Sum(s.preauthIntegrityHashValue[:0])

			h.Reset()
			h.Write(s.preauthIntegrityHashValue[:])
			h.Write(pkt)
			h.Sum(s.preauthIntegrityHashValue[:0])
		}

	}

	outputToken, err = spnego.acceptSecContext(r.SecurityBuffer())
	if err != nil {
		return nil, &InvalidResponseError{err.Error()}
	}

	req.SecurityBuffer = outputToken

	req.CreditRequestResponse = 0

	// We set session before sending packet just for setting hdr.SessionId.
	// But, we should not permit access from receiver until the session information is completed.
	conn.session = s

	rr, err = s.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err = s.recv(rr)
	if err != nil {
		return nil, err
	}

	res, err = accept(SMB2_SESSION_SETUP, pkt)
	if err != nil {
		return nil, err
	}

	r = SessionSetupResponseDecoder(res)
	if r.IsInvalid() {
		return nil, &InvalidResponseError{"broken session setup response format"}
	}

	if NtStatus(PacketCodec(pkt).Status()) != STATUS_SUCCESS {
		return nil, &InvalidResponseError{"broken session setup response format"}
	}

	// Only the final response's flags count; trusting the intermediate ones
	// would let them skip key derivation for a session that turns out signed.
	s.sessionFlags = r.SessionFlags()

	if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
		if err := s.deriveKeys(spnego.sessionKey(), rr.pkt); err != nil {
			return nil, err
		}
	}

	if err := s.verifySessionSetup(pkt); err != nil {
		return nil, err
	}

	// now, allow access from receiver
	s.enableSession()

	return s, nil
}

// deriveKeys sets up signing and encryption from the session key. finalReq is
// the last SESSION_SETUP request, which closes the SMB 3.1.1 preauth hash.
func (s *session) deriveKeys(sessionKey, finalReq []byte) error {
	switch s.dialect {
	case SMB202, SMB210:
		s.newSigner = func() hash.Hash { return hmac.New(sha256.New, sessionKey) }
		s.verifier = hmac.New(sha256.New, sessionKey)
	case SMB300, SMB302:
		signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		signingCipher := ciph // ciph is reused for the encryption keys below
		s.newSigner = func() hash.Hash { return cmac.New(signingCipher) }
		s.verifier = cmac.New(ciph)

		// s.applicationKey = kdf(sessionKey, []byte("SMB2APP\x00"), []byte("SmbRpc\x00"))

		encryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))
		decryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))

		ciph, err = aes.NewCipher(encryptionKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			return &InternalError{err.Error()}
		}

		ciph, err = aes.NewCipher(decryptionKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			return &InternalError{err.Error()}
		}
	case SMB311:
		switch s.preauthIntegrityHashId {
		case SHA512:
			h := sha512.New()
			h.Write(s.preauthIntegrityHashValue[:])
			h.Write(finalReq)
			h.Sum(s.preauthIntegrityHashValue[:0])
		}

		signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:])
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.newSigner = func() hash.Hash { return cmac.New(ciph) }
		s.verifier = cmac.New(ciph)

		// s.applicationKey = kdf(sessionKey, []byte("SMBAppKey\x00"), preauthIntegrityHashValue)

		encryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), s.preauthIntegrityHashValue[:])
		decryptionKey := kdf(sessionKey, []byte("SMBS2CCipherKey\x00"), s.preauthIntegrityHashValue[:])

		switch s.cipherId {
		case AES128CCM:
			ciph, err := aes.NewCipher(encryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return &InternalError{err.Error()}
			}
		case AES128GCM:
			ciph, err := aes.NewCipher(encryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
			if err != nil {
				return &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
			if err != nil {
				return &InternalError{err.Error()}
			}
		}
	}

	return nil
}

// verifySessionSetup checks the final SESSION_SETUP response, which the
// receiver does not verify because the session is not enabled yet. For SMB
// 3.1.1 its signature is what proves that the negotiation was not altered.
func (s *session) verifySessionSetup(pkt []byte) error {
	if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) != 0 {
		if s.requireSigning || s.requireEncryption {
			return &InvalidResponseError{"guest or anonymous session cannot be signed or encrypted"}
		}
		return nil
	}

	if PacketCodec(pkt).Flags()&SMB2_FLAGS_SIGNED == 0 {
		if s.dialect == SMB311 || s.requireSigning {
			return &InvalidResponseError{"unsigned session setup response"}
		}
		return nil
	}

	if !s.verify(pkt) {
		return &InvalidResponseError{"unverified session setup response"}
	}

	return nil
}

type session struct {
	*conn
	treeConnTables            map[uint32]*treeConn
	sessionFlags              uint16
	sessionId                 uint64
	preauthIntegrityHashValue [64]byte

	// newSigner makes the signing hashes that sign pools, so that senders
	// sign in parallel; the receiver alone uses verifier.
	newSigner func() hash.Hash
	signers   sync.Pool
	verifier  hash.Hash
	encrypter cipher.AEAD
	decrypter cipher.AEAD

	// applicationKey []byte
}

func (s *session) logoff(ctx context.Context) error {
	req := new(LogoffRequest)

	req.CreditCharge = 1

	_, err := s.sendRecv(SMB2_LOGOFF, req, ctx)
	if err != nil {
		return err
	}

	s.conn.rdone <- struct{}{}
	_ = s.conn.t.Close()

	return nil
}

func (s *session) sendRecv(cmd uint16, req Packet, ctx context.Context) (res []byte, err error) {
	rr, err := s.send(req, ctx)
	if err != nil {
		return nil, err
	}

	pkt, err := s.recv(rr)
	if err != nil {
		return nil, err
	}

	return accept(cmd, pkt)
}

func (s *session) recv(rr *requestResponse) (pkt []byte, err error) {
	pkt, err = s.conn.recv(rr)
	if err != nil {
		return nil, err
	}
	// A closed or dead connection can surface as a short or zero-length packet
	// with a nil error. Guard before reading header fields: PacketCodec
	// accessors slice at fixed offsets (e.g. SessionId reads pkt[40:48]) and
	// would otherwise panic with "slice bounds out of range" on a short buffer,
	// crashing any goroutine without a recover. IsInvalid() checks len < 64 and
	// the SMB2 magic.
	if PacketCodec(pkt).IsInvalid() {
		return nil, &InvalidResponseError{fmt.Sprintf("invalid response packet (length %d)", len(pkt))}
	}
	if sessionId := PacketCodec(pkt).SessionId(); sessionId != s.sessionId {
		return nil, &InvalidResponseError{fmt.Sprintf("expected session id: %v, got %v", s.sessionId, sessionId)}
	}
	return pkt, err
}

func (s *session) sign(pkt []byte) []byte {
	p := PacketCodec(pkt)

	p.SetFlags(p.Flags() | SMB2_FLAGS_SIGNED)

	h, _ := s.signers.Get().(hash.Hash)
	if h == nil {
		h = s.newSigner()
	}
	defer s.signers.Put(h)

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	return pkt
}

func (s *session) verify(pkt []byte) (ok bool) {
	p := PacketCodec(pkt)

	signature := append([]byte{}, p.Signature()...)

	p.SetSignature(zero[:])

	h := s.verifier

	h.Reset()

	h.Write(pkt)

	p.SetSignature(h.Sum(nil))

	return hmac.Equal(signature, p.Signature())
}

const transformHeaderSize = 52

// newTransformBuffer returns a buffer for a message of size bytes that
// encryptInPlace can seal: header room in front, room for the tag behind.
func (s *session) newTransformBuffer(size int) []byte {
	return make([]byte, transformHeaderSize+size, transformHeaderSize+size+s.encrypter.Overhead())
}

// encrypt seals pkt into a new transform message.
func (s *session) encrypt(pkt []byte) ([]byte, error) {
	c := s.newTransformBuffer(len(pkt))
	copy(c[transformHeaderSize:], pkt)
	return s.encryptInPlace(c)
}

// encryptInPlace seals the message that follows the transform header room in
// c, a buffer from newTransformBuffer, without copying it.
func (s *session) encryptInPlace(c []byte) ([]byte, error) {
	pkt := c[transformHeaderSize:]
	if cap(pkt)-len(pkt) < s.encrypter.Overhead() {
		return nil, errors.New("no room for the encryption tag")
	}

	nonce := make([]byte, s.encrypter.NonceSize())

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	t := TransformCodec(c)

	t.SetProtocolId()
	t.SetNonce(nonce)
	t.SetOriginalMessageSize(uint32(len(pkt)))
	t.SetFlags(Encrypted)
	t.SetSessionId(s.sessionId)

	sealed := s.encrypter.Seal(pkt[:0], nonce, pkt, t.AssociatedData())

	t.SetSignature(sealed[len(pkt):])

	return c, nil
}

func (s *session) decrypt(pkt []byte) ([]byte, error) {
	t := TransformCodec(pkt)

	// Reuniting the tag with the ciphertext it signs. This append stays within
	// pkt's spare capacity when pkt came from newRecvBuffer, so the packet is
	// decrypted in place; on a tightly sized buffer it still works, just with a
	// copy.
	c := append(t.EncryptedData(), t.Signature()...)

	return s.decrypter.Open(
		c[:0],
		t.Nonce()[:s.decrypter.NonceSize()],
		c,
		t.AssociatedData(),
	)
}
