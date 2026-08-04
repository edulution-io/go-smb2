// ref: MS-DTYP

package smb2

import (
	"strconv"
)

type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func (ft *Filetime) Size() int {
	return 8
}

func (ft *Filetime) Encode(p []byte) {
	le.PutUint32(p[:4], ft.LowDateTime)
	le.PutUint32(p[4:8], ft.HighDateTime)
}

func (ft *Filetime) Nanoseconds() int64 {
	nsec := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime)
	nsec -= 116444736000000000
	nsec *= 100
	return nsec
}

func NsecToFiletime(nsec int64) (ft *Filetime) {
	nsec /= 100
	nsec += 116444736000000000

	return &Filetime{
		LowDateTime:  uint32(nsec & 0xffffffff),
		HighDateTime: uint32(nsec >> 32 & 0xffffffff),
	}
}

type FiletimeDecoder []byte

func (ft FiletimeDecoder) LowDateTime() uint32 {
	return le.Uint32(ft[:4])
}

func (ft FiletimeDecoder) HighDateTime() uint32 {
	return le.Uint32(ft[4:8])
}

func (ft FiletimeDecoder) Nanoseconds() int64 {
	nsec := int64(ft.HighDateTime())<<32 + int64(ft.LowDateTime())
	nsec -= 116444736000000000
	nsec *= 100
	return nsec
}

func (ft FiletimeDecoder) Decode() *Filetime {
	return &Filetime{
		LowDateTime:  ft.LowDateTime(),
		HighDateTime: ft.HighDateTime(),
	}
}

type Sid struct {
	Revision            uint8
	IdentifierAuthority uint64
	SubAuthority        []uint32
}

// IsWellFormed reports whether the SID satisfies the structural constraints of
// MS-DTYP 2.4.2.2: revision 1 and between 1 and 15 sub-authorities.
//
// A SID that fails this is not merely unknown, it cannot name anything. Sending
// one to a domain controller costs more than it looks: an LSARPC lookup answers
// per request, not per SID, so Samba rejecting a single malformed SID with
// STATUS_INVALID_SID discards the translations for every other SID in the batch.
//
// Requiring at least one sub-authority is deliberately stricter than Windows,
// whose RtlValidSid checks the revision and the 15-element cap but accepts a
// count of zero. That count is what makes a SID misread out of non-SID bytes
// detectable, and no SID with no sub-authorities can identify a principal, so
// the rule stays. Do not relax it to match RtlValidSid.
func (sid *Sid) IsWellFormed() bool {
	return sid != nil &&
		sid.Revision == 1 &&
		len(sid.SubAuthority) >= 1 &&
		len(sid.SubAuthority) <= 15
}

func (sid *Sid) String() string {
	// Formatted into a stack buffer rather than joined from a []string: the join
	// form allocated the slice plus one string per sub-authority, six allocations
	// for a typical domain SID, and this is the hot primitive behind every SID map
	// key. The buffer holds the MS-DTYP maximum of 15 sub-authorities, so it never
	// has to grow in practice; a longer slice still formats correctly via append.
	var buf [192]byte
	b := append(buf[:0], 'S', '-')
	b = strconv.AppendUint(b, uint64(sid.Revision), 10)
	b = append(b, '-')
	if sid.IdentifierAuthority < uint64(1<<32) {
		b = strconv.AppendUint(b, sid.IdentifierAuthority, 10)
	} else {
		b = append(b, '0', 'x')
		b = strconv.AppendUint(b, sid.IdentifierAuthority, 16)
	}
	for _, a := range sid.SubAuthority {
		b = append(b, '-')
		b = strconv.AppendUint(b, uint64(a), 10)
	}
	return string(b)
}

func (sid *Sid) Size() int {
	return 8 + len(sid.SubAuthority)*4
}

func (sid *Sid) Encode(p []byte) {
	p[0] = sid.Revision
	p[1] = uint8(len(sid.SubAuthority))
	for j := 0; j < 6; j++ {
		p[2+j] = byte(sid.IdentifierAuthority >> uint64(8*(6-j)))
	}
	off := 8
	for _, u := range sid.SubAuthority {
		le.PutUint32(p[off:off+4], u)
		off += 4
	}
}

type SidDecoder []byte

// IsInvalid reports whether the buffer does not hold a decodable SID.
//
// It enforces the structure MS-DTYP 2.4.2.2 fixes -- revision 1, 1 to 15
// sub-authorities -- and not only that the buffer is long enough. A length-only
// check accepts a zero-sub-authority SID read out of arbitrary bytes and hands
// back something Decode() renders as a plausible "S-3-808530483", which then
// travels to a domain controller and fails the lookup it takes part in.
func (c SidDecoder) IsInvalid() bool {
	if len(c) < 8 {
		return true
	}

	if c.Revision() != 1 {
		return true
	}

	count := int(c.SubAuthorityCount())
	if count < 1 || count > 15 {
		return true
	}

	return len(c) < 8+count*4
}

func (c SidDecoder) Revision() uint8 {
	return c[0]
}

func (c SidDecoder) SubAuthorityCount() uint8 {
	return c[1]
}

func (c SidDecoder) IdentifierAuthority() uint64 {
	var u uint64
	for j := 0; j < 6; j++ {
		u += uint64(c[7-j]) << uint64(8*j)
	}
	return u
}

func (c SidDecoder) SubAuthority() []uint32 {
	count := c.SubAuthorityCount()
	as := make([]uint32, count)
	off := 8
	for i := uint8(0); i < count; i++ {
		as[i] = le.Uint32(c[off : off+4])
		off += 4
	}
	return as
}

func (c SidDecoder) Decode() *Sid {
	return &Sid{
		Revision:            c.Revision(),
		IdentifierAuthority: c.IdentifierAuthority(),
		SubAuthority:        c.SubAuthority(),
	}
}

// ----------------------------------------------------------------------------
// Security Descriptor (Self-Relative Format)
// ref: MS-DTYP 2.4.6
//

// Security Descriptor Control Flags
const (
	SE_OWNER_DEFAULTED       = 0x0001
	SE_GROUP_DEFAULTED       = 0x0002
	SE_DACL_PRESENT          = 0x0004
	SE_DACL_DEFAULTED        = 0x0008
	SE_SACL_PRESENT          = 0x0010
	SE_SACL_DEFAULTED        = 0x0020
	SE_DACL_AUTO_INHERIT_REQ = 0x0100
	SE_SACL_AUTO_INHERIT_REQ = 0x0200
	SE_DACL_AUTO_INHERITED   = 0x0400
	SE_SACL_AUTO_INHERITED   = 0x0800
	SE_DACL_PROTECTED        = 0x1000
	SE_SACL_PROTECTED        = 0x2000
	SE_RM_CONTROL_VALID      = 0x4000
	SE_SELF_RELATIVE         = 0x8000
)

// ACE Types
// ref: MS-DTYP 2.4.4.1
const (
	ACCESS_ALLOWED_ACE_TYPE                 = 0x00
	ACCESS_DENIED_ACE_TYPE                  = 0x01
	SYSTEM_AUDIT_ACE_TYPE                   = 0x02
	SYSTEM_ALARM_ACE_TYPE                   = 0x03
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE        = 0x04
	ACCESS_ALLOWED_OBJECT_ACE_TYPE          = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE           = 0x06
	SYSTEM_AUDIT_OBJECT_ACE_TYPE            = 0x07
	SYSTEM_ALARM_OBJECT_ACE_TYPE            = 0x08
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE        = 0x09
	ACCESS_DENIED_CALLBACK_ACE_TYPE         = 0x0A
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 0x0C
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE          = 0x0D
	SYSTEM_ALARM_CALLBACK_ACE_TYPE          = 0x0E
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   = 0x0F
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   = 0x10
	SYSTEM_MANDATORY_LABEL_ACE_TYPE         = 0x11
	SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      = 0x12
	SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        = 0x13
)

// Object ACE Flags
// ref: MS-DTYP 2.4.4.3
const (
	ACE_OBJECT_TYPE_PRESENT           = 0x00000001
	ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002
)

// ACE Flags
const (
	OBJECT_INHERIT_ACE         = 0x01
	CONTAINER_INHERIT_ACE      = 0x02
	NO_PROPAGATE_INHERIT_ACE   = 0x04
	INHERIT_ONLY_ACE           = 0x08
	INHERITED_ACE              = 0x10
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
	FAILED_ACCESS_ACE_FLAG     = 0x80
)

// SecurityDescriptorDecoder decodes a self-relative security descriptor.
//
// Layout (20 bytes minimum):
//
//	Offset  Size  Field
//	0       1     Revision
//	1       1     Sbz1
//	2       2     Control
//	4       4     OffsetOwner
//	8       4     OffsetGroup
//	12      4     OffsetSacl
//	16      4     OffsetDacl
type SecurityDescriptorDecoder []byte

func (sd SecurityDescriptorDecoder) IsInvalid() bool {
	return len(sd) < 20
}

func (sd SecurityDescriptorDecoder) Revision() uint8 {
	return sd[0]
}

func (sd SecurityDescriptorDecoder) Control() uint16 {
	return le.Uint16(sd[2:4])
}

func (sd SecurityDescriptorDecoder) OffsetOwner() uint32 {
	return le.Uint32(sd[4:8])
}

func (sd SecurityDescriptorDecoder) OffsetGroup() uint32 {
	return le.Uint32(sd[8:12])
}

func (sd SecurityDescriptorDecoder) OffsetSacl() uint32 {
	return le.Uint32(sd[12:16])
}

func (sd SecurityDescriptorDecoder) OffsetDacl() uint32 {
	return le.Uint32(sd[16:20])
}

// AclHeaderDecoder decodes an ACL header.
//
// Layout (8 bytes):
//
//	Offset  Size  Field
//	0       1     AclRevision
//	1       1     Sbz1
//	2       2     AclSize
//	4       2     AceCount
//	6       2     Sbz2
type AclHeaderDecoder []byte

func (a AclHeaderDecoder) IsInvalid() bool {
	return len(a) < 8
}

func (a AclHeaderDecoder) AclRevision() uint8 {
	return a[0]
}

func (a AclHeaderDecoder) AclSize() uint16 {
	return le.Uint16(a[2:4])
}

func (a AclHeaderDecoder) AceCount() uint16 {
	return le.Uint16(a[4:6])
}

// AceDecoder decodes an ACE (Access Control Entry).
//
// Layout for ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE:
//
//	Offset  Size  Field
//	0       1     AceType
//	1       1     AceFlags
//	2       2     AceSize
//	4       4     Mask
//	8       var   SID
//
// The SID does not sit at offset 8 for every type -- see SidOffset.
type AceDecoder []byte

// NoSidOffset is SidOffset's answer for an ACE whose layout places no SID where
// this package can find one.
const NoSidOffset = -1

// SidOffset returns the offset of a SID that is actually within the ACE, or
// NoSidOffset when the type's layout does not put one at a position this package
// can derive or the entry is too short to hold it. The result is always safe to
// slice from.
//
// Three layouts share the ACE header. The standard one (MS-DTYP 2.4.4.2) puts
// the SID right behind Mask, at offset 8, and the callback and label types keep
// it there and append their payload after it. The object types (2.4.4.3) insert
// Flags and up to two 16-byte GUIDs first, each present only when Flags says so,
// so their SID starts anywhere from 12 to 44. Reading offset 8 for those yields
// the low bytes of Flags as Revision and SubAuthorityCount -- a SID that decodes
// without complaint and names nothing.
//
// MS-DTYP lists the compound type 0x04 as reserved without giving a structure,
// so there is nothing to derive an offset from and it gets NoSidOffset rather
// than a guess. The other reserved types do get one: 0x03, 0x08, 0x0E and 0x10
// are reserved for use but their layouts are documented. Any type this package
// does not know is treated like 0x04, since an unknown layout gives no reason to
// believe a SID sits at any particular place.
func (a AceDecoder) SidOffset() int {
	switch a.AceType() {
	case ACCESS_ALLOWED_ACE_TYPE,
		ACCESS_DENIED_ACE_TYPE,
		SYSTEM_AUDIT_ACE_TYPE,
		SYSTEM_ALARM_ACE_TYPE,
		ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
		ACCESS_DENIED_CALLBACK_ACE_TYPE,
		SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
		SYSTEM_ALARM_CALLBACK_ACE_TYPE,
		SYSTEM_MANDATORY_LABEL_ACE_TYPE,
		SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
		SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
		return sidOffsetWithin(a, 8)

	case ACCESS_ALLOWED_OBJECT_ACE_TYPE,
		ACCESS_DENIED_OBJECT_ACE_TYPE,
		SYSTEM_AUDIT_OBJECT_ACE_TYPE,
		SYSTEM_ALARM_OBJECT_ACE_TYPE,
		ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
		ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
		SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
		SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
		if len(a) < 12 {
			return NoSidOffset
		}
		off := 12
		flags := le.Uint32(a[8:12])
		if flags&ACE_OBJECT_TYPE_PRESENT != 0 {
			off += 16
		}
		if flags&ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
			off += 16
		}
		return sidOffsetWithin(a, off)

	default:
		return NoSidOffset
	}
}

// sidOffsetWithin returns off only if a SID could begin there, so an entry whose
// Flags claim GUIDs it is too short to hold reports no SID instead of an offset
// past its own end.
func sidOffsetWithin(a AceDecoder, off int) int {
	if len(a) < off+8 { // 8 bytes is the shortest SID
		return NoSidOffset
	}
	return off
}

func (a AceDecoder) IsInvalid() bool {
	return len(a) < 4
}

func (a AceDecoder) AceType() uint8 {
	return a[0]
}

func (a AceDecoder) AceFlags() uint8 {
	return a[1]
}

func (a AceDecoder) AceSize() uint16 {
	return le.Uint16(a[2:4])
}

func (a AceDecoder) Mask() uint32 {
	if len(a) < 8 {
		return 0
	}
	return le.Uint32(a[4:8])
}

func (a AceDecoder) Sid() SidDecoder {
	off := a.SidOffset()
	if off == NoSidOffset {
		return nil
	}
	return SidDecoder(a[off:])
}
