// ref: MS-DTYP

package smb2

import (
	"strconv"
	"strings"
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

func (sid *Sid) String() string {
	list := make([]string, 0, 3+len(sid.SubAuthority))
	list = append(list, "S")
	list = append(list, strconv.Itoa(int(sid.Revision)))
	if sid.IdentifierAuthority < uint64(1<<32) {
		list = append(list, strconv.FormatUint(sid.IdentifierAuthority, 10))
	} else {
		list = append(list, "0x"+strconv.FormatUint(sid.IdentifierAuthority, 16))
	}
	for _, a := range sid.SubAuthority {
		list = append(list, strconv.FormatUint(uint64(a), 10))
	}
	return strings.Join(list, "-")
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

func (c SidDecoder) IsInvalid() bool {
	if len(c) < 8 {
		return true
	}

	if len(c) < 8+int(c.SubAuthorityCount())*4 {
		return true
	}

	return false
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
const (
	ACCESS_ALLOWED_ACE_TYPE = 0
	ACCESS_DENIED_ACE_TYPE  = 1
	SYSTEM_AUDIT_ACE_TYPE   = 2
	SYSTEM_ALARM_ACE_TYPE   = 3
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
//   Offset  Size  Field
//   0       1     Revision
//   1       1     Sbz1
//   2       2     Control
//   4       4     OffsetOwner
//   8       4     OffsetGroup
//   12      4     OffsetSacl
//   16      4     OffsetDacl
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
//   Offset  Size  Field
//   0       1     AclRevision
//   1       1     Sbz1
//   2       2     AclSize
//   4       2     AceCount
//   6       2     Sbz2
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
//   Offset  Size  Field
//   0       1     AceType
//   1       1     AceFlags
//   2       2     AceSize
//   4       4     Mask
//   8       var   SID
type AceDecoder []byte

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
	if len(a) < 16 { // 8 bytes ACE header+mask + 8 bytes minimum SID
		return nil
	}
	return SidDecoder(a[8:])
}
