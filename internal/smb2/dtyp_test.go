package smb2

import "testing"

// Sid.String is the primitive behind every SID map key, so it is formatted by
// hand into a stack buffer rather than by joining a []string. These cases cover
// the branches that hand-rolled formatting can get wrong: the hex form used for
// identifier authorities that do not fit in 32 bits, sub-authorities past the
// point where strconv's small-integer fast path applies, a SID with no
// sub-authority at all, and one long enough to outgrow the stack buffer.
func TestSidString(t *testing.T) {
	tests := []struct {
		name string
		sid  Sid
		want string
	}{
		{
			name: "well known",
			sid:  Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{18}},
			want: "S-1-5-18",
		},
		{
			name: "builtin alias",
			sid:  Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 544}},
			want: "S-1-5-32-544",
		},
		{
			name: "domain sid with large sub authorities",
			sid: Sid{Revision: 1, IdentifierAuthority: 5,
				SubAuthority: []uint32{21, 3623811015, 3361044348, 30300820, 1013}},
			want: "S-1-5-21-3623811015-3361044348-30300820-1013",
		},
		{
			name: "max uint32 sub authority",
			sid:  Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{4294967295}},
			want: "S-1-5-4294967295",
		},
		{
			name: "no sub authority",
			sid:  Sid{Revision: 1, IdentifierAuthority: 5},
			want: "S-1-5",
		},
		{
			name: "zero values",
			sid:  Sid{Revision: 0, IdentifierAuthority: 0, SubAuthority: []uint32{0}},
			want: "S-0-0-0",
		},
		{
			// Authorities below 1<<32 are decimal; this is the largest of them.
			name: "largest decimal authority",
			sid:  Sid{Revision: 1, IdentifierAuthority: 1<<32 - 1, SubAuthority: []uint32{1}},
			want: "S-1-4294967295-1",
		},
		{
			// At 1<<32 the format switches to hex, per MS-DTYP 2.4.2.1.
			name: "hex authority at the boundary",
			sid:  Sid{Revision: 1, IdentifierAuthority: 1 << 32, SubAuthority: []uint32{1}},
			want: "S-1-0x100000000-1",
		},
		{
			name: "max six byte hex authority",
			sid:  Sid{Revision: 1, IdentifierAuthority: 1<<48 - 1, SubAuthority: []uint32{1, 2}},
			want: "S-1-0xffffffffffff-1-2",
		},
		{
			name: "max revision",
			sid:  Sid{Revision: 255, IdentifierAuthority: 5, SubAuthority: []uint32{1}},
			want: "S-255-5-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sid.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// A SID with more sub-authorities than the stack buffer holds must still format
// correctly -- append falls back to the heap rather than truncating.
func TestSidStringBeyondStackBuffer(t *testing.T) {
	sid := Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: make([]uint32, 64)}
	for i := range sid.SubAuthority {
		sid.SubAuthority[i] = 4294967295
	}

	got := sid.String()

	want := "S-1-5"
	for range sid.SubAuthority {
		want += "-4294967295"
	}
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestSidDecoderIsInvalid(t *testing.T) {
	// S-1-5-21-100-200-300-1000
	valid := []byte{
		1, 5, 0, 0, 0, 0, 0, 5,
		21, 0, 0, 0, 100, 0, 0, 0, 200, 0, 0, 0, 44, 1, 0, 0, 232, 3, 0, 0,
	}

	withByte := func(index int, value byte) []byte {
		b := append([]byte{}, valid...)
		b[index] = value
		return b
	}

	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"valid domain SID", valid, false},
		{"single sub-authority", []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}, false},
		{"empty", nil, true},
		{"header only", valid[:8], true},
		{"truncated sub-authorities", valid[:20], true},
		// The object-ACE misread: Flags 0x00000003 read as a SID header gives
		// revision 3 and no sub-authorities, which a length-only check accepts.
		{"zero sub-authorities", withByte(1, 0), true},
		{"revision 0", withByte(0, 0), true},
		{"revision 3", withByte(0, 3), true},
		{"sub-authority count above 15", withByte(1, 16), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SidDecoder(tt.b).IsInvalid(); got != tt.want {
				t.Errorf("IsInvalid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSidIsWellFormed(t *testing.T) {
	tests := []struct {
		name string
		sid  *Sid
		want bool
	}{
		{"domain SID", &Sid{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{21, 1, 2, 3, 1000}}, true},
		{"single sub-authority", &Sid{Revision: 1, IdentifierAuthority: 1, SubAuthority: []uint32{0}}, true},
		{"nil", nil, false},
		{"zero value", &Sid{}, false},
		{"no sub-authorities", &Sid{Revision: 1, IdentifierAuthority: 5}, false},
		{"revision 3", &Sid{Revision: 3, IdentifierAuthority: 5, SubAuthority: []uint32{21}}, false},
		{"16 sub-authorities", &Sid{Revision: 1, SubAuthority: make([]uint32, 16)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sid.IsWellFormed(); got != tt.want {
				t.Errorf("IsWellFormed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAceDecoderSidOffset(t *testing.T) {
	// An ACE long enough to carry Flags, both GUIDs and a SID.
	ace := func(aceType byte, objectFlags uint32) AceDecoder {
		b := make([]byte, 72)
		b[0] = aceType
		le.PutUint16(b[2:4], 72)
		le.PutUint32(b[8:12], objectFlags)
		return AceDecoder(b)
	}

	tests := []struct {
		name    string
		aceType byte
		flags   uint32
		want    int
	}{
		{"access allowed", ACCESS_ALLOWED_ACE_TYPE, 0, 8},
		{"access denied", ACCESS_DENIED_ACE_TYPE, 0, 8},
		{"system audit", SYSTEM_AUDIT_ACE_TYPE, 0, 8},
		{"access allowed callback", ACCESS_ALLOWED_CALLBACK_ACE_TYPE, 0, 8},
		{"mandatory label", SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0, 8},
		{"resource attribute", SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, 0, 8},
		{"scoped policy id", SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, 0, 8},

		{"object, both GUIDs", ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT, 44},
		{"object, object type only", ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACE_OBJECT_TYPE_PRESENT, 28},
		{"object, inherited type only", ACCESS_DENIED_OBJECT_ACE_TYPE, ACE_INHERITED_OBJECT_TYPE_PRESENT, 28},
		{"object, no GUID", SYSTEM_AUDIT_OBJECT_ACE_TYPE, 0, 12},
		{"callback object, both GUIDs", ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT, 44},

		// Reserved by MS-DTYP; offset 8 holds a discriminator, not a SID.
		{"compound", ACCESS_ALLOWED_COMPOUND_ACE_TYPE, 0, NoSidOffset},
		{"unknown type", 0x42, 0, NoSidOffset},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ace(tt.aceType, tt.flags).SidOffset(); got != tt.want {
				t.Errorf("SidOffset() = %d, want %d", got, tt.want)
			}
		})
	}
}

// An object ACE shorter than its own Flags field cannot say where its SID is.
func TestAceDecoderSidOffsetTruncatedObjectAce(t *testing.T) {
	b := make([]byte, 10)
	b[0] = ACCESS_ALLOWED_OBJECT_ACE_TYPE
	le.PutUint16(b[2:4], 10)

	if got := AceDecoder(b).SidOffset(); got != NoSidOffset {
		t.Errorf("SidOffset() = %d, want NoSidOffset", got)
	}
	if sid := AceDecoder(b).Sid(); sid != nil {
		t.Errorf("Sid() = %v, want nil", sid)
	}
}
