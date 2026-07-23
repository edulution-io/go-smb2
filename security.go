package smb2

import (
	"fmt"
	"math/rand"
	"os"
	"strings"

	. "github.com/edulution-io/go-smb2/internal/erref"
	. "github.com/edulution-io/go-smb2/internal/smb2"

	"github.com/edulution-io/go-smb2/internal/msrpc"
)

// SecurityDescriptor represents an NT Security Descriptor.
type SecurityDescriptor struct {
	Revision byte
	Control  uint16
	Owner    *Sid
	Group    *Sid
	DACL     *ACL
	SACL     *ACL
}

// ACL represents an NT Access Control List.
type ACL struct {
	Revision byte
	ACEs     []ACE
}

// ACE represents an NT Access Control Entry.
type ACE struct {
	Type  byte
	Flags byte
	Mask  uint32
	SID   Sid
}

// GetSecurityDescriptor retrieves the NT security descriptor for the file,
// including Owner, Group, and DACL.
func (f *File) GetSecurityDescriptor() (*SecurityDescriptor, error) {
	sd, err := f.getSecurityDescriptor()
	if err != nil {
		return nil, &os.PathError{Op: "get_security_descriptor", Path: f.name, Err: err}
	}
	return sd, nil
}

func (f *File) getSecurityDescriptor() (*SecurityDescriptor, error) {
	req := &QueryInfoRequest{
		InfoType:      INFO_SECURITY,
		FileInfoClass: 0,
		AdditionalInformation: OWNER_SECURITY_INFORMATION |
			GROUP_SECUIRTY_INFORMATION |
			DACL_SECUIRTY_INFORMATION,
		Flags:              0,
		OutputBufferLength: uint32(f.maxTransactSize()),
	}

	infoBytes, err := f.queryInfo(req)
	if err != nil {
		return nil, err
	}

	return parseSecurityDescriptor(infoBytes)
}

func parseSecurityDescriptor(b []byte) (*SecurityDescriptor, error) {
	sd := SecurityDescriptorDecoder(b)
	if sd.IsInvalid() {
		return nil, &InvalidResponseError{"broken security descriptor format"}
	}

	result := &SecurityDescriptor{
		Revision: sd.Revision(),
		Control:  sd.Control(),
	}

	// Parse Owner SID
	if off := sd.OffsetOwner(); off != 0 {
		if int(off) >= len(b) {
			return nil, &InvalidResponseError{"owner SID offset out of bounds"}
		}
		sidDec := SidDecoder(b[off:])
		if sidDec.IsInvalid() {
			return nil, &InvalidResponseError{"invalid owner SID"}
		}
		result.Owner = sidDec.Decode()
	}

	// Parse Group SID
	if off := sd.OffsetGroup(); off != 0 {
		if int(off) >= len(b) {
			return nil, &InvalidResponseError{"group SID offset out of bounds"}
		}
		sidDec := SidDecoder(b[off:])
		if sidDec.IsInvalid() {
			return nil, &InvalidResponseError{"invalid group SID"}
		}
		result.Group = sidDec.Decode()
	}

	// Parse DACL
	if sd.Control()&SE_DACL_PRESENT != 0 {
		if off := sd.OffsetDacl(); off != 0 {
			if int(off) >= len(b) {
				return nil, &InvalidResponseError{"DACL offset out of bounds"}
			}
			acl, err := parseACL(b[off:])
			if err != nil {
				return nil, err
			}
			result.DACL = acl
		}
	}

	// Parse SACL
	if sd.Control()&SE_SACL_PRESENT != 0 {
		if off := sd.OffsetSacl(); off != 0 {
			if int(off) >= len(b) {
				return nil, &InvalidResponseError{"SACL offset out of bounds"}
			}
			acl, err := parseACL(b[off:])
			if err != nil {
				return nil, err
			}
			result.SACL = acl
		}
	}

	return result, nil
}

func parseACL(b []byte) (*ACL, error) {
	hdr := AclHeaderDecoder(b)
	if hdr.IsInvalid() {
		return nil, &InvalidResponseError{"invalid ACL header"}
	}

	aclSize := int(hdr.AclSize())
	if aclSize > len(b) {
		return nil, &InvalidResponseError{"ACL size exceeds buffer"}
	}
	// Restrict parsing to the ACL's declared size.
	b = b[:aclSize]

	aceCount := int(hdr.AceCount())
	acl := &ACL{
		Revision: hdr.AclRevision(),
		ACEs:     make([]ACE, 0, aceCount),
	}

	off := 8 // ACL header is 8 bytes
	for i := 0; i < aceCount; i++ {
		if off+4 > len(b) {
			return nil, &InvalidResponseError{"ACE header out of bounds"}
		}

		aceDec := AceDecoder(b[off:])
		if aceDec.IsInvalid() {
			return nil, &InvalidResponseError{"invalid ACE"}
		}

		aceSize := int(aceDec.AceSize())
		if aceSize < 4 || off+aceSize > len(b) {
			return nil, &InvalidResponseError{"ACE data out of bounds"}
		}

		ace := ACE{
			Type:  aceDec.AceType(),
			Flags: aceDec.AceFlags(),
			Mask:  aceDec.Mask(),
		}

		// Parse SID for standard ACE types (Mask at offset 4, SID at offset 8)
		if aceSize > 8 {
			sidDec := SidDecoder(b[off+8 : off+aceSize])
			if !sidDec.IsInvalid() {
				ace.SID = *sidDec.Decode()
			}
		}

		acl.ACEs = append(acl.ACEs, ace)
		off += aceSize
	}

	return acl, nil
}

// ----------------------------------------------------------------------------
// Well-Known SIDs
//

// wellKnownSids maps SID strings to human-readable names.
var wellKnownSids = map[string]string{
	"S-1-0-0":   "NULL AUTHORITY\\Nobody",
	"S-1-1-0":   "Everyone",
	"S-1-2-0":   "LOCAL",
	"S-1-2-1":   "CONSOLE LOGON",
	"S-1-3-0":   "CREATOR OWNER",
	"S-1-3-1":   "CREATOR GROUP",
	"S-1-3-4":   "OWNER RIGHTS",
	"S-1-5-1":   "NT AUTHORITY\\Dialup",
	"S-1-5-2":   "NT AUTHORITY\\Network",
	"S-1-5-3":   "NT AUTHORITY\\Batch",
	"S-1-5-4":   "NT AUTHORITY\\Interactive",
	"S-1-5-6":   "NT AUTHORITY\\Service",
	"S-1-5-7":   "NT AUTHORITY\\Anonymous Logon",
	"S-1-5-9":   "NT AUTHORITY\\Enterprise Domain Controllers",
	"S-1-5-10":  "NT AUTHORITY\\Self",
	"S-1-5-11":  "NT AUTHORITY\\Authenticated Users",
	"S-1-5-12":  "NT AUTHORITY\\Restricted",
	"S-1-5-13":  "NT AUTHORITY\\Terminal Server User",
	"S-1-5-14":  "NT AUTHORITY\\Remote Interactive Logon",
	"S-1-5-15":  "NT AUTHORITY\\This Organization",
	"S-1-5-17":  "NT AUTHORITY\\IUSR",
	"S-1-5-18":  "NT AUTHORITY\\SYSTEM",
	"S-1-5-19":  "NT AUTHORITY\\LOCAL SERVICE",
	"S-1-5-20":  "NT AUTHORITY\\NETWORK SERVICE",
	"S-1-5-32-544": "BUILTIN\\Administrators",
	"S-1-5-32-545": "BUILTIN\\Users",
	"S-1-5-32-546": "BUILTIN\\Guests",
	"S-1-5-32-547": "BUILTIN\\Power Users",
	"S-1-5-32-548": "BUILTIN\\Account Operators",
	"S-1-5-32-549": "BUILTIN\\Server Operators",
	"S-1-5-32-550": "BUILTIN\\Print Operators",
	"S-1-5-32-551": "BUILTIN\\Backup Operators",
	"S-1-5-32-552": "BUILTIN\\Replicators",
	"S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
	"S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
	"S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
	"S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
	"S-1-5-32-559": "BUILTIN\\Performance Log Users",
	"S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
	"S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
	"S-1-5-32-573": "BUILTIN\\Event Log Readers",
	"S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
	"S-1-5-32-580": "BUILTIN\\Remote Management Users",
	"S-1-5-64-10":  "NT AUTHORITY\\NTLM Authentication",
	"S-1-5-64-14":  "NT AUTHORITY\\SChannel Authentication",
	"S-1-5-64-21":  "NT AUTHORITY\\Digest Authentication",
	"S-1-5-80-0":   "NT SERVICE\\ALL SERVICES",
	"S-1-5-113":    "NT AUTHORITY\\Local account",
	"S-1-5-114":    "NT AUTHORITY\\Local account and member of Administrators group",
	"S-1-16-0":     "Untrusted Mandatory Level",
	"S-1-16-4096":  "Low Mandatory Level",
	"S-1-16-8192":  "Medium Mandatory Level",
	"S-1-16-12288": "High Mandatory Level",
	"S-1-16-16384": "System Mandatory Level",
}

// wellKnownRids maps the last sub-authority (RID) of domain SIDs to names.
var wellKnownRids = map[uint32]string{
	500: "Administrator",
	501: "Guest",
	502: "krbtgt",
	512: "Domain Admins",
	513: "Domain Users",
	514: "Domain Guests",
	515: "Domain Computers",
	516: "Domain Controllers",
	517: "Cert Publishers",
	518: "Schema Admins",
	519: "Enterprise Admins",
	520: "Group Policy Creator Owners",
	521: "Read-only Domain Controllers",
	522: "Cloneable Domain Controllers",
	553: "RAS and IAS Servers",
}

// WellKnownSidName returns the human-readable name for a well-known SID.
// Returns empty string if the SID is not well-known.
//
// Callers that persist the name should use LookupSidNames instead: this function
// cannot tell them that a domain SID's name was derived from its RID and carries
// no domain prefix.
func WellKnownSidName(sid *Sid) string {
	name, _ := wellKnownSidName(sid)
	return name
}

// wellKnownSidName resolves a SID locally and reports where the name came from.
//
// The two sources are not equally good. The static table holds fully qualified,
// domain-independent names (BUILTIN\Administrators) that mean the same thing on
// every host. The RID table holds bare account names (Domain Users) for an
// arbitrary domain, which are a display convenience and not an identity.
func wellKnownSidName(sid *Sid) (name string, source SidNameSource) {
	return wellKnownSidNameFor(sid.String(), sid)
}

// wellKnownSidNameFor is wellKnownSidName for callers that already hold the SID's
// string form. Sid.String rebuilds that string from the sub-authorities on every
// call -- six allocations for a domain SID -- so a caller iterating a map keyed by
// it should pass the key rather than pay for it twice.
func wellKnownSidNameFor(key string, sid *Sid) (name string, source SidNameSource) {
	if name, ok := wellKnownSids[key]; ok {
		return name, SidNameWellKnown
	}
	// Check for domain SID + well-known RID (S-1-5-21-x-x-x-RID)
	if sid.IdentifierAuthority == 5 && len(sid.SubAuthority) >= 5 && sid.SubAuthority[0] == 21 {
		rid := sid.SubAuthority[len(sid.SubAuthority)-1]
		if name, ok := wellKnownRids[rid]; ok {
			return name, SidNameDomainRID
		}
	}
	return "", SidNameNone
}

// ----------------------------------------------------------------------------
// LSARPC SID Resolution
//

// SidNameSource says where a name in a LookupSidNames result came from. It exists
// so that a caller which persists the name, or matches it against names from
// another source, can tell an authoritative translation from a local guess.
type SidNameSource uint8

const (
	// SidNameNone: nothing resolved the SID. Name is empty.
	SidNameNone SidNameSource = iota

	// SidNameLSARPC: the domain controller translated it. Name is DOMAIN\Name,
	// and Type carries the SID_NAME_USE the DC reported. Neither half contains a
	// backslash or a control character, so the single separator in Name is the
	// one this package put there and splitting on it recovers what the DC sent;
	// a translation that did not hold up to that check is reported as
	// SidNameNone rather than as an authoritative name.
	SidNameLSARPC

	// SidNameWellKnown: the static well-known SID table. Name is fully qualified
	// and identical on every host, so it is as good as an LSARPC translation.
	SidNameWellKnown

	// SidNameDomainRID: derived from a domain SID's RID because nothing translated
	// it. Name is unqualified ("Domain Users"), belongs to an unnamed domain, and
	// must not be stored or compared as an identity -- only displayed.
	SidNameDomainRID
)

// SidName is a resolved SID name together with its provenance.
type SidName struct {
	Name   string
	Type   uint16 // SID_NAME_USE; meaningful only when Source is SidNameLSARPC
	Source SidNameSource
}

// LookupSidNames resolves SIDs via LSARPC and reports, per SID, where each name
// came from. Falls back to locally known names when LSARPC fails or does not
// translate a SID. The returned map is keyed by SID string (e.g. "S-1-5-18") and
// holds an entry for every distinct input SID, including unresolved ones.
//
// A partial answer is not an error. A domain routinely holds SIDs nothing can
// translate -- deleted accounts, principals from a domain this DC does not trust
// -- and failing the batch over them would discard the names that did resolve.
// The error reports whether the LSARPC leg itself worked; Source reports what
// each individual name is worth.
func (s *Session) LookupSidNames(sids []*Sid) (map[string]SidName, error) {
	// Deduplicate SIDs
	unique := make(map[string]*Sid, len(sids))
	for _, sid := range sids {
		unique[sid.String()] = sid
	}

	// Try LSARPC
	rpcNames, rpcErr := s.lookupSidsRPC(unique)
	if rpcErr != nil {
		rpcNames = nil
	}

	return mergeSidNames(rpcNames, unique), rpcErr
}

// mergeSidNames lets the DC's translations win and fills every SID it did not
// translate from the local tables, so the result holds an entry -- possibly an
// empty one -- for each input SID.
func mergeSidNames(rpcNames map[string]SidName, unique map[string]*Sid) map[string]SidName {
	names := make(map[string]SidName, len(unique))
	for k, v := range rpcNames {
		names[k] = v
	}
	for key, sid := range unique {
		if _, ok := names[key]; ok {
			continue
		}
		name, source := wellKnownSidNameFor(key, sid)
		names[key] = SidName{Name: name, Source: source}
	}
	return names
}

// LookupSids resolves SIDs to human-readable "DOMAIN\Name" strings via LSARPC.
// Falls back to well-known SID names when LSARPC fails or doesn't resolve a SID.
// The returned map is keyed by SID string (e.g. "S-1-5-18") and omits SIDs that
// resolved to nothing.
//
// Prefer LookupSidNames when the names are stored or compared rather than shown:
// this map cannot distinguish a name the DC returned from one derived from a SID's
// RID, and the latter has no domain prefix.
func (s *Session) LookupSids(sids []*Sid) (map[string]string, error) {
	resolved, err := s.LookupSidNames(sids)

	return namedSids(resolved), err
}

// namedSids flattens resolved names to the pre-provenance shape: SIDs that
// resolved to nothing are dropped, whatever their source.
func namedSids(resolved map[string]SidName) map[string]string {
	names := make(map[string]string, len(resolved))
	for key, r := range resolved {
		if r.Name != "" {
			names[key] = r.Name
		}
	}
	return names
}

func (s *Session) lookupSidsRPC(sids map[string]*Sid) (map[string]SidName, error) {
	servername := s.addr

	fs, err := s.Mount(fmt.Sprintf(`\\%s\IPC$`, servername))
	if err != nil {
		return nil, err
	}
	defer fs.Umount()

	fs = fs.WithContext(s.ctx)

	f, err := fs.OpenFile("lsarpc", os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	callId := rand.Uint32()

	// 1) Bind
	output, err := f.ioctl(&IoctlRequest{
		CtlCode:           FSCTL_PIPE_TRANSCEIVE,
		MaxOutputResponse: 4280,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input:             &msrpc.LsarpcBind{CallId: callId},
	})
	if err != nil {
		return nil, err
	}

	ack := msrpc.BindAckDecoder(output)
	if ack.IsInvalid() || ack.CallId() != callId {
		return nil, &InvalidResponseError{"broken lsarpc bind ack"}
	}

	// 2) OpenPolicy2
	callId++
	output, err = f.ioctl(&IoctlRequest{
		CtlCode:           FSCTL_PIPE_TRANSCEIVE,
		MaxOutputResponse: 4280,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input: &msrpc.LsarOpenPolicy2Request{
			CallId:     callId,
			ServerName: servername,
		},
	})
	if err != nil {
		return nil, err
	}

	openResp := msrpc.LsarOpenPolicy2ResponseDecoder(output)
	if openResp.IsInvalid() || openResp.CallId() != callId {
		return nil, &InvalidResponseError{"broken lsarpc open policy2 response"}
	}
	if openResp.ReturnValue() != 0 {
		return nil, &InvalidResponseError{fmt.Sprintf("lsarpc open policy2 failed: %v", NtStatus(openResp.ReturnValue()))}
	}

	policyHandle := make([]byte, 20)
	copy(policyHandle, openResp.PolicyHandle())

	// 3) LookupSids
	sidKeys := make([]string, 0, len(sids))
	sidData := make([]msrpc.SidData, 0, len(sids))
	for key, sid := range sids {
		sidKeys = append(sidKeys, key)
		sidData = append(sidData, msrpc.NewSidData(sid.Revision, sid.IdentifierAuthority, sid.SubAuthority))
	}

	callId++
	output, err = f.ioctl(&IoctlRequest{
		CtlCode:           FSCTL_PIPE_TRANSCEIVE,
		MaxOutputResponse: uint32(f.maxTransactSize()),
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input: &msrpc.LsarLookupSidsRequest{
			CallId:       callId,
			PolicyHandle: policyHandle,
			Sids:         sidData,
		},
	})
	if err != nil {
		// STATUS_BUFFER_OVERFLOW: read remaining data
		if rerr, ok := err.(*ResponseError); ok && NtStatus(rerr.Code) == STATUS_BUFFER_OVERFLOW {
			buf := make([]byte, f.maxTransactSize())
			n, readErr := f.readAt(buf, 0)
			if readErr != nil {
				return nil, readErr
			}
			output = append(output, buf[:n]...)
		} else {
			return nil, err
		}
	}

	lookupResp := msrpc.LsarLookupSidsResponseDecoder(output)
	if lookupResp.IsInvalid() || lookupResp.CallId() != callId {
		return nil, &InvalidResponseError{"broken lsarpc lookup sids response"}
	}

	// TODO: reassemble fragments. PFC_LAST_FRAG is never checked, so a batch whose
	// reply exceeds the negotiated fragment size is decoded from its first fragment
	// alone: Results errors out and the status check below reads stub bytes rather
	// than the NTSTATUS. Callers should keep batches small until this is handled.

	// SOME_NOT_MAPPED and NONE_MAPPED are answers, not failures: the arrays are
	// valid and the unmapped entries come back typed as Unknown. Any other status
	// means the lookup did not happen, which must not read as "resolved nothing" --
	// the arrays are then absent and Results would report zero translations with
	// no error at all.
	rv := lookupResp.ReturnValue()
	if rv == msrpc.NoReturnValue {
		// A framing problem on our side, not a verdict from the DC -- say so, rather
		// than reporting 0xFFFFFFFF as if the server had sent it.
		return nil, &InvalidResponseError{"lsarpc lookup sids response too short to carry a status"}
	}
	switch status := NtStatus(rv); status {
	case STATUS_SUCCESS, STATUS_SOME_NOT_MAPPED, STATUS_NONE_MAPPED:
	default:
		return nil, &InvalidResponseError{fmt.Sprintf("lsarpc lookup sids failed: %v", status)}
	}

	results, err := lookupResp.Results()
	if err != nil {
		return nil, err
	}

	// 4) Close policy handle (best-effort)
	callId++
	f.ioctl(&IoctlRequest{
		CtlCode:           FSCTL_PIPE_TRANSCEIVE,
		MaxOutputResponse: 256,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input: &msrpc.LsarCloseRequest{
			CallId:       callId,
			PolicyHandle: policyHandle,
		},
	})

	return buildSidNames(results, sidKeys), nil
}

// buildSidNames keys the translations onto the SIDs they answer. LSARPC returns
// them positionally, so results[i] belongs to sidKeys[i]; a server that returns
// more entries than were asked for has nothing left to key them to.
func buildSidNames(results []msrpc.LookupResult, sidKeys []string) map[string]SidName {
	names := make(map[string]SidName, len(results))
	for i, r := range results {
		if i >= len(sidKeys) {
			break
		}
		// Unknown and Invalid are the DC saying it could not translate the SID. Any
		// name attached to them is not a translation, so it is left out and the
		// local tables get their turn.
		if r.Name == "" || r.Type == SidTypeUnknown || r.Type == SidTypeInvalid {
			continue
		}
		// Both halves come off the wire, and joining them produces a string callers
		// are invited to store and compare as an identity. A backslash inside either
		// half would forge a qualification the server was never given: an account
		// named `CORP\Domain Admins` with no domain is byte-identical to a genuine
		// translation from CORP. Neither half is a translation then, so the SID is
		// left to the local tables like an untranslated one.
		if !isSidNamePart(r.Name) || (r.Domain != "" && !isSidNamePart(r.Domain)) {
			continue
		}
		name := r.Name
		if r.Domain != "" {
			name = r.Domain + `\` + r.Name
		}
		names[sidKeys[i]] = SidName{Name: name, Type: r.Type, Source: SidNameLSARPC}
	}

	return names
}

// isSidNamePart reports whether s is usable as one half of a DOMAIN\Name pair.
//
// It rejects the separator itself, so that the structure of a joined name always
// reflects what the server actually sent, and rejects C0/C1 control characters,
// which carry no meaning in an account name and would otherwise reach terminals
// and log files verbatim. Windows forbids a backslash in a SAM account or domain
// name, so nothing legitimate is turned away.
func isSidNamePart(s string) bool {
	for _, r := range s {
		if r == '\\' || r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	return true
}

// CollectSids extracts all unique SIDs from a SecurityDescriptor.
func (sd *SecurityDescriptor) CollectSids() []*Sid {
	seen := make(map[string]bool)
	var result []*Sid
	add := func(s *Sid) {
		if s == nil {
			return
		}
		key := s.String()
		if !seen[key] {
			seen[key] = true
			result = append(result, s)
		}
	}
	add(sd.Owner)
	add(sd.Group)
	if sd.DACL != nil {
		for i := range sd.DACL.ACEs {
			add(&sd.DACL.ACEs[i].SID)
		}
	}
	if sd.SACL != nil {
		for i := range sd.SACL.ACEs {
			add(&sd.SACL.ACEs[i].SID)
		}
	}
	return result
}

// FormatSid returns the human-readable name for a SID if available in the
// provided names map, otherwise falls back to the SID string representation.
func FormatSid(sid *Sid, names map[string]string) string {
	s := sid.String()
	if name, ok := names[s]; ok {
		return fmt.Sprintf("%s (%s)", name, s)
	}
	return s
}

// FormatSidShort returns just the name if found, otherwise the SID string.
func FormatSidShort(sid *Sid, names map[string]string) string {
	s := sid.String()
	if name, ok := names[s]; ok {
		return name
	}
	return s
}

// SID_NAME_USE values, as reported by LSARPC in SidName.Type.
const (
	SidTypeUser           uint16 = 1
	SidTypeGroup          uint16 = 2
	SidTypeDomain         uint16 = 3
	SidTypeAlias          uint16 = 4
	SidTypeWellKnownGroup uint16 = 5
	SidTypeDeletedAccount uint16 = 6
	SidTypeInvalid        uint16 = 7
	SidTypeUnknown        uint16 = 8
	SidTypeComputer       uint16 = 9
	SidTypeLabel          uint16 = 10
)

// SidTypeString returns a human-readable name for SID_NAME_USE values.
func SidTypeString(t uint16) string {
	switch t {
	case SidTypeUser:
		return "User"
	case SidTypeGroup:
		return "Group"
	case SidTypeDomain:
		return "Domain"
	case SidTypeAlias:
		return "Alias"
	case SidTypeWellKnownGroup:
		return "WellKnownGroup"
	case SidTypeDeletedAccount:
		return "DeletedAccount"
	case SidTypeInvalid:
		return "Invalid"
	case SidTypeUnknown:
		return "Unknown"
	case SidTypeComputer:
		return "Computer"
	case SidTypeLabel:
		return "Label"
	default:
		return fmt.Sprintf("Type(%d)", t)
	}
}

// FilterSids filters a SID name map to only well-known entries (no LSARPC needed).
func FilterSidsWellKnown(sids []*Sid) map[string]string {
	names := make(map[string]string, len(sids))
	for _, sid := range sids {
		if name := WellKnownSidName(sid); name != "" {
			names[sid.String()] = name
		}
	}
	return names
}

// isDomainSid returns true if the SID is a domain SID (S-1-5-21-...).
func isDomainSid(sid *Sid) bool {
	return sid.IdentifierAuthority == 5 && len(sid.SubAuthority) >= 4 && sid.SubAuthority[0] == 21
}

// DomainSidString returns the domain portion of a domain SID (without the RID).
func DomainSidString(sid *Sid) string {
	if !isDomainSid(sid) {
		return ""
	}
	parts := make([]string, 0, 3+len(sid.SubAuthority)-1)
	parts = append(parts, "S-1-5")
	for _, sa := range sid.SubAuthority[:len(sid.SubAuthority)-1] {
		parts = append(parts, fmt.Sprintf("%d", sa))
	}
	return strings.Join(parts, "-")
}
