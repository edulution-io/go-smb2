package smb2

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/edulution-io/go-smb2/internal/msrpc"
	. "github.com/edulution-io/go-smb2/internal/smb2"
)

// buildSID constructs a binary SID with the given authority and sub-authorities.
func buildSID(revision byte, authority uint64, subAuthorities ...uint32) []byte {
	size := 8 + len(subAuthorities)*4
	b := make([]byte, size)
	b[0] = revision
	b[1] = byte(len(subAuthorities))
	// IdentifierAuthority is 6 bytes big-endian
	for j := 0; j < 6; j++ {
		b[2+j] = byte(authority >> uint(8*(5-j)))
	}
	off := 8
	for _, sa := range subAuthorities {
		binary.LittleEndian.PutUint32(b[off:off+4], sa)
		off += 4
	}
	return b
}

// withSubAuthorityCount overwrites a binary SID's declared sub-authority count,
// so a test can present a count the buffer does not match.
func withSubAuthorityCount(sid []byte, count byte) []byte {
	b := append([]byte{}, sid...)
	b[1] = count
	return b
}

// buildACE constructs a binary ACE with standard layout (header + mask + SID).
func buildACE(aceType, aceFlags byte, mask uint32, sid []byte) []byte {
	aceSize := 8 + len(sid)
	b := make([]byte, aceSize)
	b[0] = aceType
	b[1] = aceFlags
	binary.LittleEndian.PutUint16(b[2:4], uint16(aceSize))
	binary.LittleEndian.PutUint32(b[4:8], mask)
	copy(b[8:], sid)
	return b
}

// buildACL constructs a binary ACL from ACE byte slices.
func buildACL(revision byte, aces ...[]byte) []byte {
	totalSize := 8
	for _, ace := range aces {
		totalSize += len(ace)
	}
	b := make([]byte, totalSize)
	b[0] = revision
	binary.LittleEndian.PutUint16(b[2:4], uint16(totalSize))
	binary.LittleEndian.PutUint16(b[4:6], uint16(len(aces)))
	off := 8
	for _, ace := range aces {
		copy(b[off:], ace)
		off += len(ace)
	}
	return b
}

// buildSecurityDescriptor constructs a self-relative security descriptor.
func buildSecurityDescriptor(control uint16, owner, group, sacl, dacl []byte) []byte {
	// Header is 20 bytes
	size := 20 + len(owner) + len(group) + len(sacl) + len(dacl)
	b := make([]byte, size)
	b[0] = 1                                              // Revision
	binary.LittleEndian.PutUint16(b[2:4], control|0x8000) // SE_SELF_RELATIVE

	off := uint32(20)
	if len(owner) > 0 {
		binary.LittleEndian.PutUint32(b[4:8], off)
		copy(b[off:], owner)
		off += uint32(len(owner))
	}
	if len(group) > 0 {
		binary.LittleEndian.PutUint32(b[8:12], off)
		copy(b[off:], group)
		off += uint32(len(group))
	}
	if len(sacl) > 0 {
		binary.LittleEndian.PutUint32(b[12:16], off)
		copy(b[off:], sacl)
		off += uint32(len(sacl))
	}
	if len(dacl) > 0 {
		binary.LittleEndian.PutUint32(b[16:20], off)
		copy(b[off:], dacl)
		off += uint32(len(dacl))
	}
	return b
}

func TestParseSecurityDescriptor_StandardACL(t *testing.T) {
	// Owner: S-1-5-21-100-200-300-1000 (typical domain user)
	ownerSID := buildSID(1, 5, 21, 100, 200, 300, 1000)
	// Group: S-1-5-21-100-200-300-513 (Domain Users)
	groupSID := buildSID(1, 5, 21, 100, 200, 300, 513)

	// Single allow ACE for the owner
	ace := buildACE(0, 0, 0x1F01FF, ownerSID) // ACCESS_ALLOWED, Full Control
	dacl := buildACL(2, ace)

	sd := buildSecurityDescriptor(0x0004, ownerSID, groupSID, nil, dacl) // SE_DACL_PRESENT

	result, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Revision != 1 {
		t.Errorf("expected revision 1, got %d", result.Revision)
	}

	if result.Owner == nil {
		t.Fatal("expected owner SID, got nil")
	}
	if result.Owner.String() != "S-1-5-21-100-200-300-1000" {
		t.Errorf("unexpected owner SID: %s", result.Owner.String())
	}

	if result.Group == nil {
		t.Fatal("expected group SID, got nil")
	}
	if result.Group.String() != "S-1-5-21-100-200-300-513" {
		t.Errorf("unexpected group SID: %s", result.Group.String())
	}

	if result.DACL == nil {
		t.Fatal("expected DACL, got nil")
	}
	if len(result.DACL.ACEs) != 1 {
		t.Fatalf("expected 1 ACE, got %d", len(result.DACL.ACEs))
	}
	if result.DACL.ACEs[0].Mask != 0x1F01FF {
		t.Errorf("unexpected ACE mask: 0x%X", result.DACL.ACEs[0].Mask)
	}
	if result.DACL.ACEs[0].Type != 0 {
		t.Errorf("expected ACCESS_ALLOWED (0), got %d", result.DACL.ACEs[0].Type)
	}

	if result.SACL != nil {
		t.Error("expected nil SACL")
	}
}

func TestParseSecurityDescriptor_AllowDenyACEs(t *testing.T) {
	ownerSID := buildSID(1, 5, 21, 100, 200, 300, 1000)
	groupSID := buildSID(1, 5, 21, 100, 200, 300, 513)
	everyoneSID := buildSID(1, 1, 0) // S-1-1-0 (Everyone)

	// Deny write to Everyone, Allow read to owner
	denyACE := buildACE(1, 0, 0x00000002, everyoneSID) // ACCESS_DENIED, FILE_WRITE_DATA
	allowACE := buildACE(0, 0, 0x00000001, ownerSID)   // ACCESS_ALLOWED, FILE_READ_DATA
	dacl := buildACL(2, denyACE, allowACE)

	sd := buildSecurityDescriptor(0x0004, ownerSID, groupSID, nil, dacl)

	result, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DACL == nil {
		t.Fatal("expected DACL, got nil")
	}
	if len(result.DACL.ACEs) != 2 {
		t.Fatalf("expected 2 ACEs, got %d", len(result.DACL.ACEs))
	}

	// First ACE: Deny
	if result.DACL.ACEs[0].Type != 1 {
		t.Errorf("expected ACCESS_DENIED (1), got %d", result.DACL.ACEs[0].Type)
	}
	if result.DACL.ACEs[0].Mask != 0x00000002 {
		t.Errorf("unexpected deny mask: 0x%X", result.DACL.ACEs[0].Mask)
	}
	if result.DACL.ACEs[0].SID.String() != "S-1-1-0" {
		t.Errorf("unexpected deny SID: %s", result.DACL.ACEs[0].SID.String())
	}

	// Second ACE: Allow
	if result.DACL.ACEs[1].Type != 0 {
		t.Errorf("expected ACCESS_ALLOWED (0), got %d", result.DACL.ACEs[1].Type)
	}
	if result.DACL.ACEs[1].Mask != 0x00000001 {
		t.Errorf("unexpected allow mask: 0x%X", result.DACL.ACEs[1].Mask)
	}
}

func TestParseSecurityDescriptor_MultipleACEs(t *testing.T) {
	ownerSID := buildSID(1, 5, 21, 100, 200, 300, 1000)
	groupSID := buildSID(1, 5, 21, 100, 200, 300, 513)
	adminsSID := buildSID(1, 5, 32, 544) // S-1-5-32-544 (BUILTIN\Administrators)
	systemSID := buildSID(1, 5, 18)      // S-1-5-18 (Local System)
	everyoneSID := buildSID(1, 1, 0)     // S-1-1-0 (Everyone)

	ace1 := buildACE(0, 0x03, 0x1F01FF, ownerSID)   // Allow Full Control, inherited
	ace2 := buildACE(0, 0x03, 0x1F01FF, adminsSID)  // Allow Full Control, inherited
	ace3 := buildACE(0, 0x03, 0x1F01FF, systemSID)  // Allow Full Control, inherited
	ace4 := buildACE(0, 0, 0x001200A9, everyoneSID) // Allow Read+Execute

	dacl := buildACL(2, ace1, ace2, ace3, ace4)
	sd := buildSecurityDescriptor(0x0004, ownerSID, groupSID, nil, dacl)

	result, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.DACL == nil {
		t.Fatal("expected DACL, got nil")
	}
	if len(result.DACL.ACEs) != 4 {
		t.Fatalf("expected 4 ACEs, got %d", len(result.DACL.ACEs))
	}

	// Verify inheritance flags
	if result.DACL.ACEs[0].Flags != 0x03 {
		t.Errorf("expected flags 0x03, got 0x%02X", result.DACL.ACEs[0].Flags)
	}

	// Verify administrators SID
	if result.DACL.ACEs[1].SID.String() != "S-1-5-32-544" {
		t.Errorf("unexpected admins SID: %s", result.DACL.ACEs[1].SID.String())
	}

	// Verify system SID
	if result.DACL.ACEs[2].SID.String() != "S-1-5-18" {
		t.Errorf("unexpected system SID: %s", result.DACL.ACEs[2].SID.String())
	}

	// Verify everyone ACE has no inheritance flags
	if result.DACL.ACEs[3].Flags != 0 {
		t.Errorf("expected flags 0, got 0x%02X", result.DACL.ACEs[3].Flags)
	}
}

func TestParseSecurityDescriptor_NoDACL(t *testing.T) {
	ownerSID := buildSID(1, 5, 21, 100, 200, 300, 1000)
	groupSID := buildSID(1, 5, 21, 100, 200, 300, 513)

	// No SE_DACL_PRESENT flag, no DACL data
	sd := buildSecurityDescriptor(0, ownerSID, groupSID, nil, nil)

	result, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Owner == nil {
		t.Fatal("expected owner SID, got nil")
	}
	if result.Group == nil {
		t.Fatal("expected group SID, got nil")
	}
	if result.DACL != nil {
		t.Error("expected nil DACL")
	}
	if result.SACL != nil {
		t.Error("expected nil SACL")
	}
}

func TestParseSecurityDescriptor_ADUserSID(t *testing.T) {
	// Realistic AD domain SID: S-1-5-21-3623811015-3361044348-30300820-1013
	ownerSID := buildSID(1, 5, 21, 3623811015, 3361044348, 30300820, 1013)
	groupSID := buildSID(1, 5, 21, 3623811015, 3361044348, 30300820, 513)

	ace := buildACE(0, 0, 0x1F01FF, ownerSID)
	dacl := buildACL(2, ace)
	sd := buildSecurityDescriptor(0x0004, ownerSID, groupSID, nil, dacl)

	result, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "S-1-5-21-3623811015-3361044348-30300820-1013"
	if result.Owner.String() != expected {
		t.Errorf("expected owner %s, got %s", expected, result.Owner.String())
	}

	expectedGroup := "S-1-5-21-3623811015-3361044348-30300820-513"
	if result.Group.String() != expectedGroup {
		t.Errorf("expected group %s, got %s", expectedGroup, result.Group.String())
	}

	// Verify the SID in the ACE matches
	if result.DACL.ACEs[0].SID.String() != expected {
		t.Errorf("expected ACE SID %s, got %s", expected, result.DACL.ACEs[0].SID.String())
	}
}

func TestParseSecurityDescriptor_EmptyDescriptor(t *testing.T) {
	// Minimal security descriptor: just the 20-byte header with no offsets
	b := make([]byte, 20)
	b[0] = 1                                      // Revision
	binary.LittleEndian.PutUint16(b[2:4], 0x8000) // SE_SELF_RELATIVE

	result, err := parseSecurityDescriptor(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Owner != nil {
		t.Error("expected nil owner")
	}
	if result.Group != nil {
		t.Error("expected nil group")
	}
	if result.DACL != nil {
		t.Error("expected nil DACL")
	}
	if result.SACL != nil {
		t.Error("expected nil SACL")
	}
}

func TestParseSecurityDescriptor_TooShort(t *testing.T) {
	b := make([]byte, 10) // Less than 20 bytes
	_, err := parseSecurityDescriptor(b)
	if err == nil {
		t.Fatal("expected error for too-short descriptor")
	}
}

func TestParseSecurityDescriptor_InvalidOwnerOffset(t *testing.T) {
	b := make([]byte, 20)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[2:4], 0x8000)
	binary.LittleEndian.PutUint32(b[4:8], 100) // Owner offset beyond buffer

	_, err := parseSecurityDescriptor(b)
	if err == nil {
		t.Fatal("expected error for out-of-bounds owner offset")
	}
}

func TestParseSecurityDescriptor_ControlFlags(t *testing.T) {
	ownerSID := buildSID(1, 5, 18)
	dacl := buildACL(2)

	control := uint16(0x0004 | 0x0800 | 0x1000) // DACL_PRESENT | DACL_AUTO_INHERITED | DACL_PROTECTED
	sd := buildSecurityDescriptor(control, ownerSID, nil, nil, dacl)

	result, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// SE_SELF_RELATIVE is always added by buildSecurityDescriptor
	expectedControl := control | 0x8000
	if result.Control != expectedControl {
		t.Errorf("expected control 0x%04X, got 0x%04X", expectedControl, result.Control)
	}

	if result.DACL == nil {
		t.Fatal("expected DACL, got nil")
	}
	if len(result.DACL.ACEs) != 0 {
		t.Errorf("expected 0 ACEs in empty DACL, got %d", len(result.DACL.ACEs))
	}
}

func TestWellKnownSidName(t *testing.T) {
	tests := []struct {
		sid      string
		rev      byte
		auth     uint64
		sub      []uint32
		expected string
	}{
		{"SYSTEM", 1, 5, []uint32{18}, "NT AUTHORITY\\SYSTEM"},
		{"Everyone", 1, 1, []uint32{0}, "Everyone"},
		{"Administrators", 1, 5, []uint32{32, 544}, "BUILTIN\\Administrators"},
		{"Users", 1, 5, []uint32{32, 545}, "BUILTIN\\Users"},
		{"LOCAL SERVICE", 1, 5, []uint32{19}, "NT AUTHORITY\\LOCAL SERVICE"},
		{"NETWORK SERVICE", 1, 5, []uint32{20}, "NT AUTHORITY\\NETWORK SERVICE"},
		{"Authenticated Users", 1, 5, []uint32{11}, "NT AUTHORITY\\Authenticated Users"},
		{"CREATOR OWNER", 1, 3, []uint32{0}, "CREATOR OWNER"},
		// Domain SID with well-known RID
		{"Domain Admins", 1, 5, []uint32{21, 100, 200, 300, 512}, "Domain Admins"},
		{"Domain Users", 1, 5, []uint32{21, 100, 200, 300, 513}, "Domain Users"},
		{"Administrator", 1, 5, []uint32{21, 100, 200, 300, 500}, "Administrator"},
		// Unknown SID
		{"unknown", 1, 5, []uint32{21, 100, 200, 300, 9999}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.sid, func(t *testing.T) {
			sid := &Sid{
				Revision:            tt.rev,
				IdentifierAuthority: tt.auth,
				SubAuthority:        tt.sub,
			}
			got := WellKnownSidName(sid)
			if got != tt.expected {
				t.Errorf("WellKnownSidName(%s) = %q, want %q", sid.String(), got, tt.expected)
			}
		})
	}
}

// TestWellKnownSidNameSource pins the distinction LookupSidNames is built on: a
// name from the static table is qualified and portable, a name derived from a
// domain SID's RID is neither.
func TestWellKnownSidNameSource(t *testing.T) {
	tests := []struct {
		name     string
		rev      byte
		auth     uint64
		sub      []uint32
		wantName string
		wantSrc  SidNameSource
	}{
		{"static table entry", 1, 5, []uint32{18}, "NT AUTHORITY\\SYSTEM", SidNameWellKnown},
		{"static table alias", 1, 5, []uint32{32, 544}, "BUILTIN\\Administrators", SidNameWellKnown},
		{"domain RID guess", 1, 5, []uint32{21, 100, 200, 300, 513}, "Domain Users", SidNameDomainRID},
		{"domain RID guess admin", 1, 5, []uint32{21, 100, 200, 300, 500}, "Administrator", SidNameDomainRID},
		{"ordinary domain account", 1, 5, []uint32{21, 100, 200, 300, 1103}, "", SidNameNone},
		{"non-domain unknown", 1, 5, []uint32{99}, "", SidNameNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sid := &Sid{
				Revision:            tt.rev,
				IdentifierAuthority: tt.auth,
				SubAuthority:        tt.sub,
			}
			name, src := wellKnownSidName(sid)
			if name != tt.wantName || src != tt.wantSrc {
				t.Errorf("wellKnownSidName(%s) = (%q, %v), want (%q, %v)",
					sid.String(), name, src, tt.wantName, tt.wantSrc)
			}
			if got := WellKnownSidName(sid); got != tt.wantName {
				t.Errorf("WellKnownSidName(%s) = %q, want %q", sid.String(), got, tt.wantName)
			}
		})
	}
}

func TestCollectSids(t *testing.T) {
	ownerSID := buildSID(1, 5, 21, 100, 200, 300, 1000)
	groupSID := buildSID(1, 5, 21, 100, 200, 300, 513)
	everyoneSID := buildSID(1, 1, 0)

	ace1 := buildACE(0, 0, 0x1F01FF, ownerSID)
	ace2 := buildACE(0, 0, 0x001200A9, everyoneSID)
	dacl := buildACL(2, ace1, ace2)

	sd := buildSecurityDescriptor(0x0004, ownerSID, groupSID, nil, dacl)

	result, err := parseSecurityDescriptor(sd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sids := result.CollectSids()

	// Owner + Group + 2 ACE SIDs, but owner appears twice (in Owner and ACE)
	// so we expect 3 unique SIDs
	if len(sids) != 3 {
		t.Errorf("expected 3 unique SIDs, got %d", len(sids))
		for _, s := range sids {
			t.Logf("  %s", s.String())
		}
	}
}

func TestFormatSid(t *testing.T) {
	sid := &Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{18}}

	names := map[string]string{
		"S-1-5-18": "NT AUTHORITY\\SYSTEM",
	}

	got := FormatSid(sid, names)
	expected := "NT AUTHORITY\\SYSTEM (S-1-5-18)"
	if got != expected {
		t.Errorf("FormatSid = %q, want %q", got, expected)
	}

	// Without name in map
	unknown := &Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{99}}
	got = FormatSid(unknown, names)
	if got != "S-1-5-99" {
		t.Errorf("FormatSid (unknown) = %q, want %q", got, "S-1-5-99")
	}
}

// TestBuildSidNames covers the translation-to-provenance mapping: what counts as
// an answer from the DC, how the name is qualified, and how results are keyed.
func TestBuildSidNames(t *testing.T) {
	sidKeys := []string{"S-1-5-21-100-200-300-1103", "S-1-5-21-100-200-300-1104"}

	tests := []struct {
		name    string
		results []msrpc.LookupResult
		keys    []string
		want    map[string]SidName
	}{
		{
			name:    "qualified with the domain the dc reported",
			results: []msrpc.LookupResult{{Name: "jdoe", Domain: "CONTOSO", Type: SidTypeUser}},
			keys:    sidKeys,
			want: map[string]SidName{
				sidKeys[0]: {Name: `CONTOSO\jdoe`, Type: SidTypeUser, Source: SidNameLSARPC},
			},
		},
		{
			name:    "unqualified when no domain came back",
			results: []msrpc.LookupResult{{Name: "jdoe", Type: SidTypeUser}},
			keys:    sidKeys,
			want: map[string]SidName{
				sidKeys[0]: {Name: "jdoe", Type: SidTypeUser, Source: SidNameLSARPC},
			},
		},
		{
			// The case this change exists for: a named translation typed Unknown is
			// the DC saying it could not translate the SID, so it must not be reported
			// as an LSARPC answer -- otherwise the local tables never get their turn.
			name: "unknown and invalid types are not translations",
			results: []msrpc.LookupResult{
				{Name: "S-1-5-21-100-200-300-1103", Domain: "CONTOSO", Type: SidTypeUnknown},
				{Name: "whatever", Domain: "CONTOSO", Type: SidTypeInvalid},
			},
			keys: sidKeys,
			want: map[string]SidName{},
		},
		{
			name:    "empty name is not a translation",
			results: []msrpc.LookupResult{{Domain: "CONTOSO", Type: SidTypeUser}},
			keys:    sidKeys,
			want:    map[string]SidName{},
		},
		{
			// A domain SID has no account half: the DC answers with the type, an empty
			// name and the referenced domain.
			name:    "domain sid resolves to the domain name",
			results: []msrpc.LookupResult{{Domain: "CONTOSO", Type: SidTypeDomain}},
			keys:    sidKeys,
			want: map[string]SidName{
				sidKeys[0]: {Name: "CONTOSO", Type: SidTypeDomain, Source: SidNameLSARPC},
			},
		},
		{
			name:    "domain sid without a domain is not a translation",
			results: []msrpc.LookupResult{{Type: SidTypeDomain}},
			keys:    sidKeys,
			want:    map[string]SidName{},
		},
		{
			// A backslash in the account name would forge the qualification the
			// joined string is supposed to carry: with no domain reported, this is
			// byte-identical to a genuine translation of a CORP domain admin, and
			// would be handed to the caller stamped SidNameLSARPC.
			name:    "backslash in the name is not a translation",
			results: []msrpc.LookupResult{{Name: `CORP\Domain Admins`, Type: SidTypeUser}},
			keys:    sidKeys,
			want:    map[string]SidName{},
		},
		{
			// Same forgery from the other half: the join would produce
			// EVIL\CORP\Administrator, which splits the wrong way.
			name:    "backslash in the domain is not a translation",
			results: []msrpc.LookupResult{{Name: "Administrator", Domain: `EVIL\CORP`, Type: SidTypeUser}},
			keys:    sidKeys,
			want:    map[string]SidName{},
		},
		{
			name:    "control characters are not a translation",
			results: []msrpc.LookupResult{{Name: "jdoe\nADMIN: granted", Domain: "CONTOSO", Type: SidTypeUser}},
			keys:    sidKeys,
			want:    map[string]SidName{},
		},
		{
			// Rejection must stay narrow: non-ASCII account names are ordinary in a
			// domain and have to survive.
			name:    "non-ascii names are kept",
			results: []msrpc.LookupResult{{Name: "münchner-dienst", Domain: "CONTOSO", Type: SidTypeUser}},
			keys:    sidKeys,
			want: map[string]SidName{
				sidKeys[0]: {Name: `CONTOSO\münchner-dienst`, Type: SidTypeUser, Source: SidNameLSARPC},
			},
		},
		{
			name: "results are keyed positionally, gaps included",
			results: []msrpc.LookupResult{
				{Type: SidTypeUnknown},
				{Name: "grp", Domain: "CONTOSO", Type: SidTypeGroup},
			},
			keys: sidKeys,
			want: map[string]SidName{
				sidKeys[1]: {Name: `CONTOSO\grp`, Type: SidTypeGroup, Source: SidNameLSARPC},
			},
		},
		{
			name: "surplus results have no sid to key them to",
			results: []msrpc.LookupResult{
				{Name: "jdoe", Domain: "CONTOSO", Type: SidTypeUser},
				{Name: "extra", Domain: "CONTOSO", Type: SidTypeUser},
			},
			keys: sidKeys[:1],
			want: map[string]SidName{
				sidKeys[0]: {Name: `CONTOSO\jdoe`, Type: SidTypeUser, Source: SidNameLSARPC},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSidNames(tt.results, tt.keys)
			if len(got) != len(tt.want) {
				t.Fatalf("buildSidNames() = %v, want %v", got, tt.want)
			}
			for key, want := range tt.want {
				if got[key] != want {
					t.Errorf("buildSidNames()[%q] = %+v, want %+v", key, got[key], want)
				}
			}
		})
	}
}

// TestMergeSidNames pins the fallback order: an LSARPC translation wins, and every
// SID it did not answer is filled from the local tables -- with an empty entry when
// those do not know it either.
func TestMergeSidNames(t *testing.T) {
	var (
		system    = &Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{18}}
		domainGrp = &Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{21, 100, 200, 300, 513}}
		user      = &Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{21, 100, 200, 300, 1103}}
	)

	unique := map[string]*Sid{
		system.String():    system,
		domainGrp.String(): domainGrp,
		user.String():      user,
	}

	rpcNames := map[string]SidName{
		user.String(): {Name: `CONTOSO\jdoe`, Type: SidTypeUser, Source: SidNameLSARPC},
		// The DC also answers for a SID the static table knows; its answer wins.
		system.String(): {Name: `CONTOSO\SYSTEM`, Type: SidTypeWellKnownGroup, Source: SidNameLSARPC},
	}

	want := map[string]SidName{
		user.String():      {Name: `CONTOSO\jdoe`, Type: SidTypeUser, Source: SidNameLSARPC},
		system.String():    {Name: `CONTOSO\SYSTEM`, Type: SidTypeWellKnownGroup, Source: SidNameLSARPC},
		domainGrp.String(): {Name: "Domain Users", Source: SidNameDomainRID},
	}

	got := mergeSidNames(rpcNames, unique)
	if len(got) != len(want) {
		t.Fatalf("mergeSidNames() = %v, want %v", got, want)
	}
	for key, w := range want {
		if got[key] != w {
			t.Errorf("mergeSidNames()[%q] = %+v, want %+v", key, got[key], w)
		}
	}

	// Without an LSARPC leg every SID still gets an entry, empty when nothing knows it.
	local := mergeSidNames(nil, unique)
	if len(local) != len(unique) {
		t.Fatalf("mergeSidNames(nil, ...) returned %d entries, want %d", len(local), len(unique))
	}
	if entry := local[user.String()]; entry.Name != "" || entry.Source != SidNameNone {
		t.Errorf("unresolved SID = %+v, want an empty SidNameNone entry", entry)
	}
	if entry := local[system.String()]; entry.Name != `NT AUTHORITY\SYSTEM` || entry.Source != SidNameWellKnown {
		t.Errorf("well-known SID = %+v, want the static table name", entry)
	}
}

// TestNamedSids pins what LookupSids still promises: names only, unresolved SIDs
// dropped, regardless of where a name came from.
func TestNamedSids(t *testing.T) {
	resolved := map[string]SidName{
		"S-1-5-21-100-200-300-1103": {Name: `CONTOSO\jdoe`, Type: SidTypeUser, Source: SidNameLSARPC},
		"S-1-5-18":                  {Name: `NT AUTHORITY\SYSTEM`, Source: SidNameWellKnown},
		"S-1-5-21-100-200-300-513":  {Name: "Domain Users", Source: SidNameDomainRID},
		"S-1-5-21-100-200-300-1104": {Source: SidNameNone},
	}

	want := map[string]string{
		"S-1-5-21-100-200-300-1103": `CONTOSO\jdoe`,
		"S-1-5-18":                  `NT AUTHORITY\SYSTEM`,
		"S-1-5-21-100-200-300-513":  "Domain Users",
	}

	got := namedSids(resolved)
	if len(got) != len(want) {
		t.Fatalf("namedSids() = %v, want %v", got, want)
	}
	for key, w := range want {
		if got[key] != w {
			t.Errorf("namedSids()[%q] = %q, want %q", key, got[key], w)
		}
	}
}

// buildObjectACE constructs a binary object ACE (MS-DTYP 2.4.4.3): header, mask,
// Flags, then each GUID that Flags declares present, then the SID.
func buildObjectACE(aceType, aceFlags byte, mask, objectFlags uint32, sid []byte) []byte {
	aceSize := 12 + len(sid)
	if objectFlags&ACE_OBJECT_TYPE_PRESENT != 0 {
		aceSize += 16
	}
	if objectFlags&ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
		aceSize += 16
	}

	b := make([]byte, aceSize)
	b[0] = aceType
	b[1] = aceFlags
	binary.LittleEndian.PutUint16(b[2:4], uint16(aceSize))
	binary.LittleEndian.PutUint32(b[4:8], mask)
	binary.LittleEndian.PutUint32(b[8:12], objectFlags)

	off := 12
	if objectFlags&ACE_OBJECT_TYPE_PRESENT != 0 {
		copy(b[off:off+16], []byte("OBJECTTYPEGUID--"))
		off += 16
	}
	if objectFlags&ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
		copy(b[off:off+16], []byte("INHERITEDGUID---"))
		off += 16
	}
	copy(b[off:], sid)
	return b
}

// An object ACE puts Flags and up to two GUIDs between Mask and the SID. Reading
// the SID at the standard offset 8 lands on Flags and yields a SID with no
// sub-authorities, which a DC rejects for the whole lookup batch it appears in.
func TestParseACL_ObjectACESidOffset(t *testing.T) {
	sid := buildSID(1, 5, 21, 100, 200, 300, 1000)
	const want = "S-1-5-21-100-200-300-1000"

	objectTypes := []struct {
		name    string
		aceType byte
	}{
		{"ACCESS_ALLOWED_OBJECT", ACCESS_ALLOWED_OBJECT_ACE_TYPE},
		{"ACCESS_DENIED_OBJECT", ACCESS_DENIED_OBJECT_ACE_TYPE},
		{"SYSTEM_AUDIT_OBJECT", SYSTEM_AUDIT_OBJECT_ACE_TYPE},
		{"SYSTEM_ALARM_OBJECT", SYSTEM_ALARM_OBJECT_ACE_TYPE},
		{"ACCESS_ALLOWED_CALLBACK_OBJECT", ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE},
		{"ACCESS_DENIED_CALLBACK_OBJECT", ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE},
		{"SYSTEM_AUDIT_CALLBACK_OBJECT", SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE},
		{"SYSTEM_ALARM_CALLBACK_OBJECT", SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE},
	}
	flagCases := []struct {
		name  string
		flags uint32
	}{
		{"both GUIDs", ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT},
		{"object type only", ACE_OBJECT_TYPE_PRESENT},
		{"inherited type only", ACE_INHERITED_OBJECT_TYPE_PRESENT},
		{"no GUID", 0},
	}

	for _, ot := range objectTypes {
		for _, fc := range flagCases {
			t.Run(ot.name+"/"+fc.name, func(t *testing.T) {
				ace := buildObjectACE(ot.aceType, 0, 0x1F01FF, fc.flags, sid)
				acl, err := parseACL(buildACL(2, ace))
				if err != nil {
					t.Fatalf("parseACL: %v", err)
				}
				if len(acl.ACEs) != 1 {
					t.Fatalf("expected 1 ACE, got %d", len(acl.ACEs))
				}
				if !acl.ACEs[0].SIDValid {
					t.Fatalf("SIDValid = false, want the SID decoded")
				}
				if got := acl.ACEs[0].SID.String(); got != want {
					t.Errorf("SID = %q, want %q", got, want)
				}
				if acl.ACEs[0].Type != ot.aceType {
					t.Errorf("Type = %#x, want %#x", acl.ACEs[0].Type, ot.aceType)
				}
				if acl.ACEs[0].Mask != 0x1F01FF {
					t.Errorf("Mask = %#x, want 0x1F01FF", acl.ACEs[0].Mask)
				}
			})
		}
	}
}

// Callback and label ACEs keep the SID at offset 8 and append their payload
// behind it, so the trailing bytes must not disturb the decode.
func TestParseACL_ACEsWithTrailingPayload(t *testing.T) {
	sid := buildSID(1, 5, 21, 100, 200, 300, 1000)

	for _, tt := range []struct {
		name    string
		aceType byte
	}{
		{"ACCESS_ALLOWED_CALLBACK", ACCESS_ALLOWED_CALLBACK_ACE_TYPE},
		{"ACCESS_DENIED_CALLBACK", ACCESS_DENIED_CALLBACK_ACE_TYPE},
		{"SYSTEM_AUDIT_CALLBACK", SYSTEM_AUDIT_CALLBACK_ACE_TYPE},
		{"SYSTEM_RESOURCE_ATTRIBUTE", SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Conditional expression / attribute blob trailing the SID.
			payload := []byte("artx\x00\x00\x00\x00condition-blob")
			ace := buildACE(tt.aceType, 0, 0x1F01FF, append(append([]byte{}, sid...), payload...))

			acl, err := parseACL(buildACL(2, ace))
			if err != nil {
				t.Fatalf("parseACL: %v", err)
			}
			if !acl.ACEs[0].SIDValid {
				t.Fatalf("SIDValid = false, want the SID decoded")
			}
			if got, want := acl.ACEs[0].SID.String(), "S-1-5-21-100-200-300-1000"; got != want {
				t.Errorf("SID = %q, want %q", got, want)
			}
		})
	}
}

// A mandatory label carries an ordinary SID at offset 8.
func TestParseACL_MandatoryLabel(t *testing.T) {
	ace := buildACE(SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0, 0x1, buildSID(1, 16, 8192))

	acl, err := parseACL(buildACL(2, ace))
	if err != nil {
		t.Fatalf("parseACL: %v", err)
	}
	if !acl.ACEs[0].SIDValid {
		t.Fatalf("SIDValid = false, want the SID decoded")
	}
	if got, want := acl.ACEs[0].SID.String(), "S-1-16-8192"; got != want {
		t.Errorf("SID = %q, want %q", got, want)
	}
}

// A layout this package cannot read must not produce a SID out of whatever bytes
// sit at offset 8. The entry itself is kept: dropping it would change what the
// ACL says it grants.
func TestParseACL_UnreadableLayoutYieldsNoSid(t *testing.T) {
	sid := buildSID(1, 5, 21, 100, 200, 300, 1000)

	for _, tt := range []struct {
		name    string
		ace     []byte
		aceType byte
	}{
		{"compound ACE", buildACE(ACCESS_ALLOWED_COMPOUND_ACE_TYPE, 0, 0x1F01FF, sid), ACCESS_ALLOWED_COMPOUND_ACE_TYPE},
		{"unknown type", buildACE(0x42, 0, 0x1F01FF, sid), 0x42},
		{"truncated SID", buildACE(ACCESS_ALLOWED_ACE_TYPE, 0, 0x1F01FF, sid[:12]), ACCESS_ALLOWED_ACE_TYPE},
		{"no SID at all", buildACE(ACCESS_ALLOWED_ACE_TYPE, 0, 0x1F01FF, nil), ACCESS_ALLOWED_ACE_TYPE},
	} {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := parseACL(buildACL(2, tt.ace))
			if err != nil {
				t.Fatalf("parseACL: %v", err)
			}
			if len(acl.ACEs) != 1 {
				t.Fatalf("expected the ACE to be kept, got %d ACEs", len(acl.ACEs))
			}
			if acl.ACEs[0].SIDValid {
				t.Errorf("SIDValid = true, want the SID reported as absent (got %q)", acl.ACEs[0].SID.String())
			}
			if acl.ACEs[0].Type != tt.aceType {
				t.Errorf("Type = %#x, want %#x", acl.ACEs[0].Type, tt.aceType)
			}
			if acl.ACEs[0].Mask != 0x1F01FF {
				t.Errorf("Mask = %#x, want 0x1F01FF", acl.ACEs[0].Mask)
			}
		})
	}
}

// An ACE whose SID did not decode must stay out of CollectSids: one malformed
// SID fails the entire LSARPC batch it travels in.
func TestCollectSids_ExcludesUndecodedACESids(t *testing.T) {
	good := buildACE(ACCESS_ALLOWED_ACE_TYPE, 0, 0x1F01FF, buildSID(1, 5, 21, 100, 200, 300, 1000))
	unreadable := buildACE(0x42, 0, 0x1F01FF, buildSID(1, 5, 21, 100, 200, 300, 1001))

	acl, err := parseACL(buildACL(2, good, unreadable))
	if err != nil {
		t.Fatalf("parseACL: %v", err)
	}

	sids := (&SecurityDescriptor{DACL: acl}).CollectSids()
	if len(sids) != 1 {
		t.Fatalf("CollectSids() returned %d SIDs, want 1", len(sids))
	}
	if got, want := sids[0].String(), "S-1-5-21-100-200-300-1000"; got != want {
		t.Errorf("CollectSids()[0] = %q, want %q", got, want)
	}
	for _, s := range sids {
		if !s.IsWellFormed() {
			t.Errorf("CollectSids() returned malformed SID %q", s.String())
		}
	}
}

// An owner or group SID that cannot be read leaves the field nil. Failing the
// parse over it would cost the caller the DACL as well, which is the opposite of
// how an unreadable ACE SID is handled.
func TestParseSecurityDescriptor_MalformedOwnerAndGroupAreNil(t *testing.T) {
	for _, tt := range []struct {
		name string
		sid  []byte
	}{
		{"zero sub-authorities", buildSID(1, 5)},
		{"revision 3", buildSID(3, 5, 21, 100, 200, 300, 1000)},
		{"sub-authority count above 15", withSubAuthorityCount(buildSID(1, 5, 21, 100, 200, 300, 1000), 16)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := buildSecurityDescriptor(0, tt.sid, tt.sid, nil, nil)

			result, err := parseSecurityDescriptor(b)
			if err != nil {
				t.Fatalf("parseSecurityDescriptor: %v", err)
			}
			if result.Owner != nil {
				t.Errorf("Owner = %q, want nil", result.Owner.String())
			}
			if result.Group != nil {
				t.Errorf("Group = %q, want nil", result.Group.String())
			}
			if sids := result.CollectSids(); len(sids) != 0 {
				t.Errorf("CollectSids() = %v, want none", sids)
			}
		})
	}
}

// A descriptor offset arrives as a uint32. Compared as a signed int it goes
// negative on a 32-bit build from 0x80000000 up, passes the bounds check and
// panics on the slice.
func TestParseSecurityDescriptor_HighOffsetsRejected(t *testing.T) {
	for _, field := range []struct {
		name string
		off  int
	}{
		{"owner", 4},
		{"group", 8},
		{"sacl", 12},
		{"dacl", 16},
	} {
		for _, off := range []uint32{0x80000000, 0xFFFFFFFF} {
			t.Run(fmt.Sprintf("%s/%#x", field.name, off), func(t *testing.T) {
				b := make([]byte, 64)
				b[0] = 1
				// SE_SELF_RELATIVE plus both ACL-present bits, so the SACL and DACL
				// offsets are reached at all.
				binary.LittleEndian.PutUint16(b[2:4], 0x8000|SE_DACL_PRESENT|SE_SACL_PRESENT)
				binary.LittleEndian.PutUint32(b[field.off:field.off+4], off)

				if _, err := parseSecurityDescriptor(b); err == nil {
					t.Fatalf("parseSecurityDescriptor accepted offset %#x", off)
				}
			})
		}
	}
}

// Every concrete ACE type carries an ACCESS_MASK, so an entry declaring fewer
// than 8 bytes cannot be one. Admitting it produced a phantom ACCESS_DENIED with
// Mask 0, which reads as denying nothing.
func TestParseACL_RejectsUndersizedACE(t *testing.T) {
	for _, aceSize := range []uint16{4, 5, 6, 7} {
		t.Run(fmt.Sprintf("aceSize=%d", aceSize), func(t *testing.T) {
			ace := make([]byte, aceSize)
			ace[0] = ACCESS_DENIED_ACE_TYPE
			binary.LittleEndian.PutUint16(ace[2:4], aceSize)

			if _, err := parseACL(buildACL(2, ace)); err == nil {
				t.Fatalf("parseACL accepted a %d-byte ACE", aceSize)
			}
		})
	}
}

// An entry must not read a field it is too short to hold out of the ACE behind
// it. An 8-byte ACE has no SID, and its Mask must not come from its neighbour.
func TestParseACL_FieldsDoNotBleedBetweenACEs(t *testing.T) {
	short := make([]byte, 8)
	short[0] = ACCESS_DENIED_ACE_TYPE
	binary.LittleEndian.PutUint16(short[2:4], 8)
	// Mask deliberately left zero; the neighbour's is 0xDEADBEEF.

	next := buildACE(ACCESS_ALLOWED_ACE_TYPE, 0, 0xDEADBEEF, buildSID(1, 5, 21, 100, 200, 300, 1000))

	acl, err := parseACL(buildACL(2, short, next))
	if err != nil {
		t.Fatalf("parseACL: %v", err)
	}
	if len(acl.ACEs) != 2 {
		t.Fatalf("expected 2 ACEs, got %d", len(acl.ACEs))
	}
	if acl.ACEs[0].Mask != 0 {
		t.Errorf("ACEs[0].Mask = %#x, want 0 (bled in from the next ACE)", acl.ACEs[0].Mask)
	}
	if acl.ACEs[0].SIDValid {
		t.Errorf("ACEs[0].SIDValid = true, want false")
	}
	if acl.ACEs[1].Mask != 0xDEADBEEF {
		t.Errorf("ACEs[1].Mask = %#x, want 0xDEADBEEF", acl.ACEs[1].Mask)
	}
}

// An object ACE whose Flags claim GUIDs the entry is too short to hold must not
// report a SID offset past its own end.
func TestParseACL_ObjectACEShorterThanItsFlagsClaim(t *testing.T) {
	ace := make([]byte, 16)
	ace[0] = ACCESS_ALLOWED_OBJECT_ACE_TYPE
	binary.LittleEndian.PutUint16(ace[2:4], 16)
	binary.LittleEndian.PutUint32(ace[8:12], ACE_OBJECT_TYPE_PRESENT|ACE_INHERITED_OBJECT_TYPE_PRESENT)

	acl, err := parseACL(buildACL(2, ace))
	if err != nil {
		t.Fatalf("parseACL: %v", err)
	}
	if len(acl.ACEs) != 1 {
		t.Fatalf("expected 1 ACE, got %d", len(acl.ACEs))
	}
	if acl.ACEs[0].SIDValid {
		t.Errorf("SIDValid = true, want false (SID would start past the ACE)")
	}
}

// A lying AceCount must not size the allocation on its own.
func TestParseACL_AceCountDoesNotDriveAllocation(t *testing.T) {
	ace := buildACE(ACCESS_ALLOWED_ACE_TYPE, 0, 0x1F01FF, buildSID(1, 5, 21, 100, 200, 300, 1000))
	b := buildACL(2, ace)
	binary.LittleEndian.PutUint16(b[4:6], 0xFFFF) // AceCount far beyond what fits

	// The parse fails on the second entry; what matters is that it did not
	// preallocate for 65535 ACEs on the way there.
	acl, err := parseACL(b)
	if err == nil {
		t.Fatalf("parseACL accepted AceCount 0xFFFF, got %d ACEs", len(acl.ACEs))
	}
}

func TestPartitionSids(t *testing.T) {
	good := &Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{21, 100, 200, 300, 1000}}
	wellKnown := &Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{18}}
	noSubAuthority := &Sid{Revision: 1, IdentifierAuthority: 5}
	badRevision := &Sid{Revision: 3, IdentifierAuthority: 5, SubAuthority: []uint32{21}}

	unique, lookupable := partitionSids([]*Sid{good, wellKnown, noSubAuthority, badRevision, nil, good})

	// Every non-nil input is answered for, the duplicate collapses.
	if len(unique) != 4 {
		t.Errorf("len(unique) = %d, want 4: %v", len(unique), unique)
	}
	// Only the two that can name something go on the wire.
	if len(lookupable) != 2 {
		t.Errorf("len(lookupable) = %d, want 2: %v", len(lookupable), lookupable)
	}
	for _, key := range []string{good.String(), wellKnown.String()} {
		if _, ok := lookupable[key]; !ok {
			t.Errorf("lookupable is missing %q", key)
		}
	}
	for _, key := range []string{noSubAuthority.String(), badRevision.String()} {
		if _, ok := lookupable[key]; ok {
			t.Errorf("lookupable contains malformed %q", key)
		}
		if _, ok := unique[key]; !ok {
			t.Errorf("unique is missing %q -- it must still be answered for", key)
		}
	}
}

func TestPartitionSidsAllMalformed(t *testing.T) {
	unique, lookupable := partitionSids([]*Sid{{Revision: 1, IdentifierAuthority: 5}, nil})

	if len(lookupable) != 0 {
		t.Errorf("len(lookupable) = %d, want 0", len(lookupable))
	}
	// mergeSidNames still answers for the malformed one, with no name.
	names := mergeSidNames(nil, unique)
	if len(names) != 1 {
		t.Fatalf("len(names) = %d, want 1", len(names))
	}
	for key, n := range names {
		if n.Source != SidNameNone || n.Name != "" {
			t.Errorf("names[%q] = %+v, want an empty SidNameNone entry", key, n)
		}
	}
}

// A declared ACL size below the header is malformed. It also drove the ACE
// capacity negative, which panicked in make rather than returning an error.
func TestParseACL_RejectsUndersizedACL(t *testing.T) {
	for _, aclSize := range []uint16{0, 1, 7} {
		t.Run(fmt.Sprintf("aclSize=%d", aclSize), func(t *testing.T) {
			b := make([]byte, 32)
			b[0] = 2
			binary.LittleEndian.PutUint16(b[2:4], aclSize)
			binary.LittleEndian.PutUint16(b[4:6], 1)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseACL panicked on AclSize %d: %v", aclSize, r)
				}
			}()
			if _, err := parseACL(b); err == nil {
				t.Fatalf("parseACL accepted AclSize %d", aclSize)
			}
		})
	}
}

// 0x14 and 0x15 are documented types carrying a SID at offset 8, so they must
// not fall through to the unknown-layout path.
func TestParseACL_ProcessTrustLabelAndAccessFilter(t *testing.T) {
	sid := buildSID(1, 5, 21, 100, 200, 300, 1000)

	for _, tt := range []struct {
		name    string
		aceType byte
	}{
		{"SYSTEM_PROCESS_TRUST_LABEL", SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE},
		{"SYSTEM_ACCESS_FILTER", SYSTEM_ACCESS_FILTER_ACE_TYPE},
	} {
		t.Run(tt.name, func(t *testing.T) {
			acl, err := parseACL(buildACL(2, buildACE(tt.aceType, 0, 0x1F01FF, sid)))
			if err != nil {
				t.Fatalf("parseACL: %v", err)
			}
			if !acl.ACEs[0].SIDValid {
				t.Fatalf("SIDValid = false, want the SID decoded")
			}
			if got, want := acl.ACEs[0].SID.String(), "S-1-5-21-100-200-300-1000"; got != want {
				t.Errorf("SID = %q, want %q", got, want)
			}
		})
	}
}

// A descriptor a caller assembled has no parser behind it to set SIDValid, so
// CollectSids must judge the SID itself rather than the flag.
func TestCollectSids_CallerConstructedDescriptor(t *testing.T) {
	valid := Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{21, 100, 200, 300, 1000}}
	owner := Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{18}}

	sd := &SecurityDescriptor{
		Owner: &owner,
		DACL: &ACL{ACEs: []ACE{
			{Type: ACCESS_ALLOWED_ACE_TYPE, Mask: 0x1F01FF, SID: valid},
			{Type: ACCESS_DENIED_ACE_TYPE, Mask: 0x2}, // zero SID, never populated
		}},
	}

	got := sd.CollectSids()
	if len(got) != 2 {
		t.Fatalf("CollectSids() = %v, want the owner and the one valid ACE SID", got)
	}
	for _, s := range got {
		if !s.IsWellFormed() {
			t.Errorf("CollectSids() returned malformed SID %q", s.String())
		}
	}
}
