package smb2_test

import (
	"bytes"
	"io"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/edulution-io/go-smb2"
)

// Dials with the hardening options against the test server and round-trips a
// file, so the signed final SESSION_SETUP response and encrypted traffic are
// exercised against a real server.
func TestDialHardened(t *testing.T) {
	if fs == nil {
		t.Skip()
	}

	tests := []struct {
		name string
		n    smb2.Negotiator
	}{
		{name: "min 3.1.1", n: smb2.Negotiator{MinDialect: smb2.Dialect311}},
		{name: "min 3.1.1 signed", n: smb2.Negotiator{MinDialect: smb2.Dialect311, RequireMessageSigning: true}},
		{name: "encrypted 3.1.1", n: smb2.Negotiator{MinDialect: smb2.Dialect311, RequireEncryption: true}},
		{name: "encrypted 3.0", n: smb2.Negotiator{SpecifiedDialect: smb2.Dialect300, RequireEncryption: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.Dial(cfg.Transport.Type, net.JoinHostPort(cfg.Transport.Host, strconv.Itoa(cfg.Transport.Port)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()

			d := &smb2.Dialer{Negotiator: tt.n, Initiator: dialer.Initiator}

			s, err := d.Dial(conn)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Logoff() }()

			share, err := s.Mount(cfg.TreeConn.Share1)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = share.Umount() }()

			name := "hardened-" + strconv.Itoa(os.Getpid())
			want := []byte("hardened dial")

			if err := share.WriteFile(name, want, 0644); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = share.Remove(name) }()

			f, err := share.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()

			got, err := io.ReadAll(f)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("read %q, want %q", got, want)
			}
		})
	}
}
