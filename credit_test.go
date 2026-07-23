package smb2

import (
	"context"
	"testing"

	. "github.com/edulution-io/go-smb2/internal/smb2"
)

const creditPayload = 64 * 1024 // payload a single credit covers

// newTestConn returns a conn whose credit balance holds availableCredits.
func newTestConn(availableCredits uint16) *conn {
	conn := &conn{
		capabilities: SMB2_GLOBAL_CAP_LARGE_MTU,
		account:      openAccount(64),
	}

	// openAccount seeds the balance with a single credit.
	if availableCredits > 1 {
		conn.account.charge(availableCredits-1, availableCredits-1)
	}

	return conn
}

// TestLoanCreditGrantCoversPayload pins the invariant the transact paths rely
// on: the payload size loanCredit reports is never larger than what the credit
// charge it returns actually pays for. A request that declares more than its
// CreditCharge covers is failed by the server (MS-SMB2 3.3.5.2.5) rather than
// queued, which is what the transact paths used to do by discarding the grant.
func TestLoanCreditGrantCoversPayload(t *testing.T) {
	tests := []struct {
		name             string
		availableCredits uint16
		requested        int
		wantCharge       uint16
		wantGranted      int
	}{
		{
			name:             "balance covers the request",
			availableCredits: 16,
			requested:        16 * creditPayload,
			wantCharge:       16,
			wantGranted:      16 * creditPayload,
		},
		{
			name:             "short balance grants a partial charge",
			availableCredits: 4,
			requested:        16 * creditPayload,
			wantCharge:       4,
			wantGranted:      4 * creditPayload,
		},
		{
			name:             "single credit left",
			availableCredits: 1,
			requested:        16 * creditPayload,
			wantCharge:       1,
			wantGranted:      creditPayload,
		},
		{
			name:             "request below one credit",
			availableCredits: 16,
			requested:        512,
			wantCharge:       1,
			wantGranted:      512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newTestConn(tt.availableCredits)

			creditCharge, granted, err := conn.loanCredit(tt.requested, context.Background())
			if err != nil {
				t.Fatalf("loanCredit: unexpected error: %v", err)
			}

			if creditCharge != tt.wantCharge {
				t.Errorf("credit charge = %d, want %d", creditCharge, tt.wantCharge)
			}

			if granted != tt.wantGranted {
				t.Errorf("granted payload size = %d, want %d", granted, tt.wantGranted)
			}

			if covered := int(creditCharge) * creditPayload; granted > covered {
				t.Errorf("granted payload size %d exceeds the %d bytes credit charge %d covers",
					granted, covered, creditCharge)
			}

			// A partial grant is what the transact paths clamp their response
			// buffer to, so it has to stay at or above what one credit covers -
			// clamping must never shrink a buffer to nothing.
			if granted < tt.requested && granted < creditPayload {
				t.Errorf("partial grant %d is below the %d bytes a single credit covers",
					granted, creditPayload)
			}
		})
	}
}

func TestCheckCreditGrant(t *testing.T) {
	tests := []struct {
		name    string
		granted int
		send    int
		wantErr bool
	}{
		{name: "grant covers payload", granted: creditPayload, send: 512, wantErr: false},
		{name: "grant matches payload exactly", granted: 512, send: 512, wantErr: false},
		{name: "grant short of payload", granted: creditPayload, send: 2 * creditPayload, wantErr: true},
		{name: "nothing to send", granted: creditPayload, send: 0, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkCreditGrant(tt.granted, tt.send)
			if tt.wantErr && err == nil {
				t.Errorf("checkCreditGrant(%d, %d) = nil, want error", tt.granted, tt.send)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("checkCreditGrant(%d, %d) = %v, want nil", tt.granted, tt.send, err)
			}
		})
	}
}
