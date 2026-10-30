package smb2

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	. "github.com/edulution-io/go-smb2/internal/erref"
	"github.com/edulution-io/go-smb2/internal/ntlm"
	. "github.com/edulution-io/go-smb2/internal/smb2"
	"github.com/edulution-io/go-smb2/internal/spnego"
)

const (
	fakeUser     = "alice"
	fakePassword = "Secret123"
	fakeSession  = 0x1234
)

// fakeServer plays an SMB 2.1 server over one connection: a NEGOTIATE that
// requires signing and a real NTLMv2 login in two SESSION_SETUP legs. final
// may rewrite the last response before it is sent; key is the session key it
// can sign with.
type fakeServer struct {
	conn  net.Conn
	ntlm  *ntlm.Server
	final func(pkt []byte, key []byte) []byte
	// negotiate, when set, answers every request in place of the login.
	negotiate func(req []byte) []byte
	// dialect replaces SMB 2.1 in the NEGOTIATE response.
	dialect uint16
	// signingOptional leaves signing enabled but not required.
	signingOptional bool
}

func readFrame(c net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	pkt := make([]byte, n)
	_, err := io.ReadFull(c, pkt)
	return pkt, err
}

func writeFrame(c net.Conn, pkt []byte) error {
	hdr := []byte{0, byte(len(pkt) >> 16), byte(len(pkt) >> 8), byte(len(pkt))}
	_, err := c.Write(append(hdr, pkt...))
	return err
}

// response builds a response to req with the given status and body.
func response(req []byte, status NtStatus, body []byte) []byte {
	pkt := make([]byte, 64+len(body))
	copy(pkt[64:], body)
	p := PacketCodec(pkt)
	q := PacketCodec(req)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(q.Command())
	p.SetStatus(uint32(status))
	p.SetFlags(SMB2_FLAGS_SERVER_TO_REDIR)
	p.SetMessageId(q.MessageId())
	p.SetCreditResponse(max(q.CreditRequest(), 1))
	return pkt
}

func negotiateResponse(req []byte, dialect uint16) []byte {
	body := make([]byte, 64)
	le := binary.LittleEndian
	le.PutUint16(body[0:], 65)
	le.PutUint16(body[2:], SMB2_NEGOTIATE_SIGNING_ENABLED|SMB2_NEGOTIATE_SIGNING_REQUIRED)
	le.PutUint16(body[4:], dialect)
	le.PutUint32(body[28:], 1<<16) // MaxTransactSize
	le.PutUint32(body[32:], 1<<16) // MaxReadSize
	le.PutUint32(body[36:], 1<<16) // MaxWriteSize
	le.PutUint16(body[56:], 128)   // SecurityBufferOffset
	return response(req, STATUS_SUCCESS, body)
}

func sessionSetupResponse(req []byte, status NtStatus, flags uint16, token []byte) []byte {
	body := make([]byte, 8+len(token))
	le := binary.LittleEndian
	le.PutUint16(body[0:], 9)
	le.PutUint16(body[2:], flags)
	le.PutUint16(body[4:], 64+8)
	le.PutUint16(body[6:], uint16(len(token)))
	copy(body[8:], token)
	pkt := response(req, status, body)
	PacketCodec(pkt).SetSessionId(fakeSession)
	return pkt
}

// signSMB21 signs pkt as an SMB 2.1 server does: HMAC-SHA256 over the packet
// with a zero signature field.
func signSMB21(pkt, key []byte) []byte {
	p := PacketCodec(pkt)
	p.SetFlags(p.Flags() | SMB2_FLAGS_SIGNED)
	p.SetSignature(make([]byte, 16))
	h := hmac.New(sha256.New, key)
	h.Write(pkt)
	p.SetSignature(h.Sum(nil))
	return pkt
}

func (s *fakeServer) serve() {
	defer func() { _ = s.conn.Close() }()

	if s.negotiate != nil {
		for {
			req, err := readFrame(s.conn)
			if err != nil || writeFrame(s.conn, s.negotiate(req)) != nil {
				return
			}
		}
	}

	req, err := readFrame(s.conn)
	if err != nil {
		return
	}
	dialect := uint16(SMB210)
	if s.dialect != 0 {
		dialect = s.dialect
	}
	resp := negotiateResponse(req, dialect)
	if s.signingOptional {
		binary.LittleEndian.PutUint16(resp[64+2:], SMB2_NEGOTIATE_SIGNING_ENABLED)
	}
	if writeFrame(s.conn, resp) != nil {
		return
	}

	// First leg: NTLM challenge.
	req, err = readFrame(s.conn)
	if err != nil {
		return
	}
	init, err := spnego.DecodeNegTokenInit(SessionSetupRequestDecoder(req[64:]).SecurityBuffer())
	if err != nil {
		return
	}
	challenge, err := s.ntlm.Challenge(init.MechToken)
	if err != nil {
		return
	}
	token, err := spnego.EncodeNegTokenResp(1, spnego.NlmpOid, challenge, nil)
	if err != nil {
		return
	}
	if writeFrame(s.conn, sessionSetupResponse(req, STATUS_MORE_PROCESSING_REQUIRED, 0, token)) != nil {
		return
	}

	// Second leg: authenticate, then the final response, signed as a real
	// server signs it unless final rewrites it.
	req, err = readFrame(s.conn)
	if err != nil {
		return
	}
	resp2, err := spnego.DecodeNegTokenResp(SessionSetupRequestDecoder(req[64:]).SecurityBuffer())
	if err != nil {
		return
	}
	if err := s.ntlm.Authenticate(resp2.ResponseToken); err != nil {
		return
	}
	key := s.ntlm.Session().SessionKey()
	final := signSMB21(sessionSetupResponse(req, STATUS_SUCCESS, 0, nil), key)
	if s.final != nil {
		final = s.final(final, key)
	}
	if writeFrame(s.conn, final) != nil {
		return
	}
	_, _ = io.Copy(io.Discard, s.conn)
}

// dialFake runs a login against a fakeServer and returns the client's result.
// A context deadline is never the result a test expects; see wantInvalid.
func dialFake(t *testing.T, s *fakeServer) (*Session, error) {
	t.Helper()
	client, server := net.Pipe()
	s.conn = server
	s.ntlm = ntlm.NewServer("FAKE")
	s.ntlm.AddAccount(fakeUser, fakePassword)
	go s.serve()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := &Dialer{Initiator: &NTLMInitiator{User: fakeUser, Password: fakePassword}}
	sess, err := d.DialContext(ctx, client)
	if err != nil {
		_ = client.Close()
	}
	return sess, err
}

// wantInvalid fails t unless err is an *InvalidResponseError naming want, so a
// dial that merely timed out does not pass for one that was refused.
func wantInvalid(t *testing.T, sess *Session, err error, want string) {
	t.Helper()
	if err == nil {
		_ = sess.s.t.Close()
		t.Fatal("dial succeeded")
	}
	if e, ok := err.(*InvalidResponseError); !ok || !strings.Contains(e.Error(), want) {
		t.Errorf("err = %T %v, want *InvalidResponseError naming %q", err, err, want)
	}
}
