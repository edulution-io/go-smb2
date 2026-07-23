package smb2

import (
	"encoding/binary"
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
	b[0] = 1 // Revision
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
	denyACE := buildACE(1, 0, 0x00000002, everyoneSID)  // ACCESS_DENIED, FILE_WRITE_DATA
	allowACE := buildACE(0, 0, 0x00000001, ownerSID)     // ACCESS_ALLOWED, FILE_READ_DATA
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
	adminsSID := buildSID(1, 5, 32, 544)    // S-1-5-32-544 (BUILTIN\Administrators)
	systemSID := buildSID(1, 5, 18)          // S-1-5-18 (Local System)
	everyoneSID := buildSID(1, 1, 0)         // S-1-1-0 (Everyone)

	ace1 := buildACE(0, 0x03, 0x1F01FF, ownerSID)    // Allow Full Control, inherited
	ace2 := buildACE(0, 0x03, 0x1F01FF, adminsSID)   // Allow Full Control, inherited
	ace3 := buildACE(0, 0x03, 0x1F01FF, systemSID)   // Allow Full Control, inherited
	ace4 := buildACE(0, 0, 0x001200A9, everyoneSID)  // Allow Read+Execute

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
	b[0] = 1 // Revision
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
