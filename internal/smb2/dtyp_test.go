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
