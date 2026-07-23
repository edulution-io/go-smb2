package msrpc

import (
	"encoding/hex"
	"errors"

	"github.com/edulution-io/go-smb2/internal/utf16le"
)

// LSARPC interface UUID: 12345778-1234-ABCD-EF00-0123456789AB (wire format)
var LSARPC_UUID = []byte("785734123412cdabef000123456789ab")

// decodeUTF16 decodes a UTF-16LE byte slice, stripping any trailing null terminator.
func decodeUTF16(b []byte) string {
	// Strip trailing UTF-16 null terminator (0x0000) if present
	if len(b) >= 2 && b[len(b)-2] == 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-2]
	}
	if len(b) == 0 {
		return ""
	}
	return utf16le.DecodeToString(b)
}

const (
	LSARPC_VERSION       = 0
	LSARPC_VERSION_MINOR = 0

	OP_LSAR_CLOSE        = 0
	OP_LSAR_LOOKUP_SIDS  = 15
	OP_LSAR_OPEN_POLICY2 = 44

	POLICY_LOOKUP_NAMES = 0x00000800

	// rpcHeaderLen is the length of the common DCE/RPC PDU header, i.e. the offset
	// at which the stub data starts.
	rpcHeaderLen = 24

	// lookupSidsMinStub is the smallest stub LsarLookupSids can produce: a null
	// ReferencedDomains pointer, an empty TranslatedNames (count + null pointer),
	// MappedCount, and the status.
	lookupSidsMinStub = 20
)

// NoReturnValue is what a ReturnValue method reports when the PDU does not carry
// a status it can read. It is not a valid NTSTATUS, so a truncated or fragmented
// response cannot be mistaken for STATUS_SUCCESS; callers should treat it as a
// framing error rather than as a verdict from the server.
const NoReturnValue uint32 = 0xFFFFFFFF

// ----------------------------------------------------------------------------
// Bind
//

// LsarpcBind creates an RPC bind request for the LSARPC interface.
type LsarpcBind struct {
	CallId uint32
}

func (r *LsarpcBind) Size() int {
	return 72
}

func (r *LsarpcBind) Encode(b []byte) {
	b[0] = RPC_VERSION
	b[1] = RPC_VERSION_MINOR
	b[2] = RPC_TYPE_BIND
	b[3] = RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST

	b[4] = 0x10 // LE, IEEE, ASCII

	le.PutUint16(b[8:10], 72)        // frag length
	le.PutUint16(b[10:12], 0)        // auth length
	le.PutUint32(b[12:16], r.CallId) // call id
	le.PutUint16(b[16:18], 4280)     // max xmit frag
	le.PutUint16(b[18:20], 4280)     // max recv frag
	le.PutUint32(b[20:24], 0)        // assoc group
	le.PutUint32(b[24:28], 1)        // num ctx items
	le.PutUint16(b[28:30], 0)        // ctx item[1] .context id
	le.PutUint16(b[30:32], 1)        // ctx item[1] .num trans items

	hex.Decode(b[32:48], LSARPC_UUID)
	le.PutUint16(b[48:50], LSARPC_VERSION)
	le.PutUint16(b[50:52], LSARPC_VERSION_MINOR)

	hex.Decode(b[52:68], NDR_UUID)
	le.PutUint32(b[68:72], NDR_VERSION)
}

// ----------------------------------------------------------------------------
// LsarOpenPolicy2
//

// LsarOpenPolicy2Request encodes opnum 44.
type LsarOpenPolicy2Request struct {
	CallId     uint32
	ServerName string
}

func (r *LsarOpenPolicy2Request) Size() int {
	nameLen := utf16le.EncodedStringLen(r.ServerName) + 2 // +2 for null terminator
	count := nameLen / 2
	off := 24           // RPC header
	off += 4            // SystemName referent ID
	off += 4 + 4 + 4    // MaxCount, Offset, ActualCount
	off += count * 2     // string data
	off = roundup(off, 4)
	off += 24           // ObjectAttributes (6 * uint32)
	off += 4            // DesiredAccess
	return off
}

func (r *LsarOpenPolicy2Request) Encode(b []byte) {
	b[0] = RPC_VERSION
	b[1] = RPC_VERSION_MINOR
	b[2] = RPC_TYPE_REQUEST
	b[3] = RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST
	b[4] = 0x10
	le.PutUint32(b[12:16], r.CallId)
	le.PutUint16(b[20:22], 0)                        // context id
	le.PutUint16(b[22:24], OP_LSAR_OPEN_POLICY2)     // opnum

	off := 24

	// SystemName (unique pointer)
	le.PutUint32(b[off:], 0x20000) // referent ID
	off += 4

	count := utf16le.EncodedStringLen(r.ServerName)/2 + 1
	le.PutUint32(b[off:], uint32(count)) // max count
	off += 4
	le.PutUint32(b[off:], 0) // offset
	off += 4
	le.PutUint32(b[off:], uint32(count)) // actual count
	off += 4
	utf16le.EncodeString(b[off:], r.ServerName)
	off += count * 2
	off = roundup(off, 4)

	// ObjectAttributes
	le.PutUint32(b[off:], 24) // Length
	off += 4
	// RootDirectory, ObjectName, Attributes, SecurityDescriptor, QoS = all zero
	off += 20

	// DesiredAccess
	le.PutUint32(b[off:], POLICY_LOOKUP_NAMES)
	off += 4

	le.PutUint16(b[8:10], uint16(off))      // frag length
	le.PutUint32(b[16:20], uint32(off-24))   // alloc hint
}

// LsarOpenPolicy2ResponseDecoder decodes the response.
type LsarOpenPolicy2ResponseDecoder []byte

func (r LsarOpenPolicy2ResponseDecoder) IsInvalid() bool {
	if len(r) < 48 { // 24 header + 20 handle + 4 status
		return true
	}
	if r[0] != RPC_VERSION || r[1] != RPC_VERSION_MINOR || r[2] != RPC_TYPE_RESPONSE {
		return true
	}
	return false
}

func (r LsarOpenPolicy2ResponseDecoder) CallId() uint32 {
	return le.Uint32(r[12:16])
}

func (r LsarOpenPolicy2ResponseDecoder) PolicyHandle() []byte {
	return r[24:44]
}

// ReturnValue returns the NTSTATUS that follows the policy handle, or
// NoReturnValue when the PDU is too short to carry one. Guarded here rather than
// left to IsInvalid, because the method is exported.
func (r LsarOpenPolicy2ResponseDecoder) ReturnValue() uint32 {
	if len(r) < 48 {
		return NoReturnValue
	}
	return le.Uint32(r[44:48])
}

// ----------------------------------------------------------------------------
// LsarLookupSids
//

// SidData holds binary SID components for NDR encoding.
type SidData struct {
	Revision            uint8
	SubAuthorityCount   uint8
	IdentifierAuthority [6]byte
	SubAuthority        []uint32
}

// NewSidData converts from the Sid fields to wire-format SidData.
func NewSidData(revision uint8, authority uint64, subAuthority []uint32) SidData {
	var auth [6]byte
	for j := 0; j < 6; j++ {
		auth[j] = byte(authority >> uint(8*(5-j)))
	}
	return SidData{
		Revision:            revision,
		SubAuthorityCount:   uint8(len(subAuthority)),
		IdentifierAuthority: auth,
		SubAuthority:        subAuthority,
	}
}

func sidNdrSize(sid *SidData) int {
	return 4 + 8 + len(sid.SubAuthority)*4 // MaxCount + (rev+count+auth) + subauths
}

// LsarLookupSidsRequest encodes opnum 15.
type LsarLookupSidsRequest struct {
	CallId       uint32
	PolicyHandle []byte // 20 bytes from OpenPolicy2
	Sids         []SidData
}

func (r *LsarLookupSidsRequest) Size() int {
	n := len(r.Sids)
	off := 24     // RPC header
	off += 20     // PolicyHandle
	off += 4      // SidEnumBuffer.Entries
	off += 4      // SidInfo pointer
	off += 4      // MaxCount (conformant array)
	off += n * 4  // SID pointers
	for i := range r.Sids {
		off += sidNdrSize(&r.Sids[i])
	}
	off += 4 // TranslatedNames.Entries
	off += 4 // TranslatedNames.Names (NULL)
	off += 2 // LookupLevel
	off += 2 // padding
	off += 4 // MappedCount
	return off
}

func (r *LsarLookupSidsRequest) Encode(b []byte) {
	n := len(r.Sids)

	b[0] = RPC_VERSION
	b[1] = RPC_VERSION_MINOR
	b[2] = RPC_TYPE_REQUEST
	b[3] = RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST
	b[4] = 0x10
	le.PutUint32(b[12:16], r.CallId)
	le.PutUint16(b[20:22], 0)                    // context id
	le.PutUint16(b[22:24], OP_LSAR_LOOKUP_SIDS)  // opnum

	off := 24

	// PolicyHandle
	copy(b[off:], r.PolicyHandle[:20])
	off += 20

	// SidEnumBuffer.Entries
	le.PutUint32(b[off:], uint32(n))
	off += 4

	// SidInfo pointer (referent ID)
	le.PutUint32(b[off:], 0x20000)
	off += 4

	// Conformant array MaxCount
	le.PutUint32(b[off:], uint32(n))
	off += 4

	// SID pointers
	refId := uint32(0x20004)
	for i := 0; i < n; i++ {
		le.PutUint32(b[off:], refId)
		off += 4
		refId += 4
	}

	// Deferred SID data
	for i := range r.Sids {
		sid := &r.Sids[i]
		le.PutUint32(b[off:], uint32(sid.SubAuthorityCount)) // MaxCount
		off += 4
		b[off] = sid.Revision
		b[off+1] = sid.SubAuthorityCount
		copy(b[off+2:off+8], sid.IdentifierAuthority[:])
		off += 8
		for _, sa := range sid.SubAuthority {
			le.PutUint32(b[off:], sa)
			off += 4
		}
	}

	// TranslatedNames (empty)
	le.PutUint32(b[off:], 0) // Entries
	off += 4
	le.PutUint32(b[off:], 0) // Names = NULL
	off += 4

	// LookupLevel = LsapLookupWksta (1)
	le.PutUint16(b[off:], 1)
	off += 2
	off += 2 // padding

	// MappedCount
	le.PutUint32(b[off:], 0)
	off += 4

	le.PutUint16(b[8:10], uint16(off))    // frag length
	le.PutUint32(b[16:20], uint32(off-24)) // alloc hint
}

// LookupResult holds a resolved SID name.
type LookupResult struct {
	Name   string // account name
	Domain string // domain name
	Type   uint16 // SID_NAME_USE
}

// NDR element sizes, used to bound a server-declared count against the bytes
// actually present before anything is sized from it.
const (
	// LSAPR_TRUST_INFORMATION: Name(Length+MaximumLength+BufPtr) + SidPtr.
	trustInfoSize = 12

	// LSAPR_TRANSLATED_NAME: Use + Name.Length + Name.MaximumLength + pad +
	// BufPtr + DomainIndex.
	translatedNameSize = 16
)

// fitsIn reports whether count elements of elemSize bytes each are present in
// remaining bytes of buffer.
//
// Every count in a response is a server-declared uint32 that the payload does
// not have to back, so it must be checked before it sizes an allocation: a
// 44-byte PDU declaring four billion entries would otherwise have the decoder
// reserve tens of gigabytes and die before the length check ever ran.
//
// The multiplication is done in 64-bit arithmetic because it overflows int on a
// 32-bit build, where the product can wrap to a small or negative value and slip
// past the very check it is meant to fail.
func fitsIn(count, elemSize, remaining int) bool {
	if count < 0 || remaining < 0 {
		return false
	}
	return uint64(count)*uint64(elemSize) <= uint64(remaining)
}

// LsarLookupSidsResponseDecoder parses opnum 15 response.
type LsarLookupSidsResponseDecoder []byte

func (r LsarLookupSidsResponseDecoder) IsInvalid() bool {
	if len(r) < 28 {
		return true
	}
	if r[0] != RPC_VERSION || r[1] != RPC_VERSION_MINOR || r[2] != RPC_TYPE_RESPONSE {
		return true
	}
	return false
}

func (r LsarLookupSidsResponseDecoder) CallId() uint32 {
	return le.Uint32(r[12:16])
}

// stubEnd reports where the stub data ends, and whether the PDU carries a
// complete final fragment at all.
//
// ReturnValue and Results both go through here so they agree on the stub extent:
// the buffer can hold more than the PDU, since the STATUS_BUFFER_OVERFLOW re-read
// appends a full transact's worth. The header reads are guarded here rather than
// left to IsInvalid, because both callers are exported.
func (r LsarLookupSidsResponseDecoder) stubEnd() (int, bool) {
	if len(r) < rpcHeaderLen+lookupSidsMinStub {
		return 0, false
	}
	// The status is the last field of the last fragment, and this client does not
	// reassemble; the tail of a non-final fragment is stub payload.
	if r[3]&RPC_PACKET_FLAG_LAST == 0 {
		return 0, false
	}
	// Declared longer than what arrived: truncation. Falling back to the buffer
	// end would read a zero-padded stub as STATUS_SUCCESS.
	fragLen := int(le.Uint16(r[8:10]))
	if fragLen > len(r) {
		return 0, false
	}
	end := len(r)
	if fragLen >= rpcHeaderLen {
		end = fragLen
	}
	// An auth verifier is padding plus an 8-byte sec_trailer plus AuthLength token
	// bytes. AuthLength covers only the token, so the trailer has to be located
	// before the padding it declares can be subtracted.
	if authLen := int(le.Uint16(r[10:12])); authLen > 0 {
		trailer := end - authLen - 8
		if trailer < rpcHeaderLen {
			return 0, false
		}
		end = trailer - int(r[trailer+2]) // auth_pad_length
	}
	if end < rpcHeaderLen+lookupSidsMinStub {
		return 0, false
	}
	return end, true
}

// ReturnValue returns the NTSTATUS the server appended to the stub data.
//
// The status is the stub's last field, so it is located from the end rather than
// by walking the variable-length payload before it.
//
// Returns NoReturnValue when the PDU carries no status to read -- too short,
// shorter than it declares, or not the final fragment -- so no framing failure
// reads as STATUS_SUCCESS.
func (r LsarLookupSidsResponseDecoder) ReturnValue() uint32 {
	end, ok := r.stubEnd()
	if !ok {
		return NoReturnValue
	}
	return le.Uint32(r[end-4 : end])
}

// Results parses the referenced domains and translated names from the response.
//
// Parsing stops at the declared stub end, so trailing bytes the buffer happens to
// hold are not read as payload. When the framing does not hold up the whole
// buffer is parsed, bounded by its length; ReturnValue reports that case.
func (r LsarLookupSidsResponseDecoder) Results() ([]LookupResult, error) {
	buf := []byte(r)
	if end, ok := r.stubEnd(); ok {
		buf = buf[:end]
	}
	off := rpcHeaderLen

	// ReferencedDomains pointer
	if off+4 > len(buf) {
		return nil, errors.New("lsarpc: truncated response")
	}
	rdPtr := le.Uint32(buf[off:])
	off += 4

	var domains []string

	if rdPtr != 0 {
		// LSAPR_REFERENCED_DOMAIN_LIST
		// Field order per MS-LSAD: Entries, Domains (pointer), MaxEntries
		if off+12 > len(buf) {
			return nil, errors.New("lsarpc: truncated referenced domains")
		}
		domainCount := int(le.Uint32(buf[off:])) // Entries
		off += 4
		domainsPtr := le.Uint32(buf[off:]) // Domains pointer (referent ID)
		off += 4
		_ = le.Uint32(buf[off:]) // MaxEntries
		off += 4

		if domainsPtr != 0 && domainCount > 0 {
			// Conformant array of LSAPR_TRUST_INFORMATION
			if off+4 > len(buf) {
				return nil, errors.New("lsarpc: truncated domain array")
			}
			off += 4 // MaxCount

			type trustInfo struct {
				namePtr uint32
				sidPtr  uint32
			}

			// Checked before the allocation, not after: domainCount is whatever
			// the server put on the wire.
			if !fitsIn(domainCount, trustInfoSize, len(buf)-off) {
				return nil, errors.New("lsarpc: truncated trust info array")
			}
			infos := make([]trustInfo, domainCount)

			for i := 0; i < domainCount; i++ {
				off += 2 // Name.Length
				off += 2 // Name.MaximumLength
				infos[i].namePtr = le.Uint32(buf[off:])
				off += 4
				infos[i].sidPtr = le.Uint32(buf[off:])
				off += 4
			}

			// Deferred data: per-element (name string + SID for each domain)
			// NDR deferred pointers are ordered per-element, not per-field.
			domains = make([]string, domainCount)
			for i := 0; i < domainCount; i++ {
				// Name string
				if infos[i].namePtr != 0 {
					if off+12 > len(buf) {
						return nil, errors.New("lsarpc: truncated domain name")
					}
					off += 4 // MaxCount
					off += 4 // Offset
					actualCount := int(le.Uint32(buf[off:]))
					off += 4
					if !fitsIn(actualCount, 2, len(buf)-off) {
						return nil, errors.New("lsarpc: truncated domain name data")
					}
					strLen := actualCount * 2
					domains[i] = decodeUTF16(buf[off : off+strLen])
					off += strLen
					off = roundup(off, 4)
				}

				// Domain SID
				if infos[i].sidPtr != 0 {
					if off+4 > len(buf) {
						return nil, errors.New("lsarpc: truncated domain SID")
					}
					subCount := int(le.Uint32(buf[off:]))
					off += 4
					// The fixed 8 bytes are taken off the budget before the
					// sub-authorities are measured against what is left.
					if off+8 > len(buf) || !fitsIn(subCount, 4, len(buf)-off-8) {
						return nil, errors.New("lsarpc: truncated domain SID data")
					}
					off += 8 + subCount*4
				}
			}
		}
	}

	// TranslatedNames
	if off+8 > len(buf) {
		return nil, errors.New("lsarpc: truncated translated names")
	}
	nameCount := int(le.Uint32(buf[off:]))
	off += 4
	namesPtr := le.Uint32(buf[off:])
	off += 4

	// A null array pointer means no translations, whatever Entries claims. Sizing
	// a result slice from a count with no array behind it would let a short
	// response declare four billion entries and allocate on the way to finding
	// out there are none.
	if namesPtr == 0 || nameCount <= 0 {
		return nil, nil
	}

	// Conformant array
	if off+4 > len(buf) {
		return nil, errors.New("lsarpc: truncated names array")
	}
	off += 4 // MaxCount

	type translatedName struct {
		use         uint16
		namePtr     uint32
		domainIndex int32
	}

	// Both slices below are sized from nameCount, so the count has to be backed
	// by the payload before either is allocated.
	if !fitsIn(nameCount, translatedNameSize, len(buf)-off) {
		return nil, errors.New("lsarpc: truncated translated name array")
	}
	results := make([]LookupResult, nameCount)
	names := make([]translatedName, nameCount)

	for i := 0; i < nameCount; i++ {
		names[i].use = le.Uint16(buf[off:])
		off += 2
		off += 2 // Name.Length
		off += 2 // Name.MaximumLength
		off += 2 // pad for pointer alignment
		names[i].namePtr = le.Uint32(buf[off:])
		off += 4
		names[i].domainIndex = int32(le.Uint32(buf[off:]))
		off += 4
	}

	// Deferred: name strings
	for i := 0; i < nameCount; i++ {
		results[i].Type = names[i].use

		if names[i].namePtr != 0 {
			if off+12 > len(buf) {
				return nil, errors.New("lsarpc: truncated translated name string")
			}
			off += 4 // MaxCount
			off += 4 // Offset
			actualCount := int(le.Uint32(buf[off:]))
			off += 4
			if !fitsIn(actualCount, 2, len(buf)-off) {
				return nil, errors.New("lsarpc: truncated translated name data")
			}
			strLen := actualCount * 2
			results[i].Name = decodeUTF16(buf[off : off+strLen])
			off += strLen
			off = roundup(off, 4)
		}

		if names[i].domainIndex >= 0 && int(names[i].domainIndex) < len(domains) {
			results[i].Domain = domains[names[i].domainIndex]
		}
	}

	return results, nil
}

// ----------------------------------------------------------------------------
// LsarClose
//

// LsarCloseRequest encodes opnum 0.
type LsarCloseRequest struct {
	CallId       uint32
	PolicyHandle []byte // 20 bytes
}

func (r *LsarCloseRequest) Size() int {
	return 24 + 20
}

func (r *LsarCloseRequest) Encode(b []byte) {
	b[0] = RPC_VERSION
	b[1] = RPC_VERSION_MINOR
	b[2] = RPC_TYPE_REQUEST
	b[3] = RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST
	b[4] = 0x10
	le.PutUint32(b[12:16], r.CallId)
	le.PutUint16(b[20:22], 0)            // context id
	le.PutUint16(b[22:24], OP_LSAR_CLOSE) // opnum

	copy(b[24:44], r.PolicyHandle[:20])

	le.PutUint16(b[8:10], 44)  // frag length
	le.PutUint32(b[16:20], 20) // alloc hint
}
