package smb2

import (
	. "github.com/edulution-io/go-smb2/internal/smb2"
)

// client

const (
	clientCapabilities = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_ENCRYPTION
)

var (
	clientHashAlgorithms = []uint16{SHA512}
	clientCiphers        = []uint16{AES128GCM, AES128CCM}
	clientDialects       = []uint16{SMB311, SMB302, SMB300, SMB210, SMB202}
)

const (
	clientMaxCreditBalance = 128
)

const (
	clientMaxSymlinkDepth = 8
)

// Dialects for Negotiator.SpecifiedDialect and Negotiator.MinDialect.
const (
	Dialect202 uint16 = SMB202
	Dialect210 uint16 = SMB210
	Dialect300 uint16 = SMB300
	Dialect302 uint16 = SMB302
	Dialect311 uint16 = SMB311
)
