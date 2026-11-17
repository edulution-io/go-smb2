package smb2

import (
	"reflect"
	"testing"
)

// Decoders for data a server controls. Request decoders are left out: the
// client only builds requests.
var serverDecoders = []reflect.Type{
	reflect.TypeOf(PacketCodec(nil)),
	reflect.TypeOf(TransformCodec(nil)),
	reflect.TypeOf(ErrorResponseDecoder(nil)),
	reflect.TypeOf(ErrorContextResponseDecoder(nil)),
	reflect.TypeOf(SmallBufferErrorResponseDecoder(nil)),
	reflect.TypeOf(SymbolicLinkErrorResponseDecoder(nil)),
	reflect.TypeOf(NegotiateResponseDecoder(nil)),
	reflect.TypeOf(NegotiateContextDecoder(nil)),
	reflect.TypeOf(HashContextDataDecoder(nil)),
	reflect.TypeOf(CipherContextDataDecoder(nil)),
	reflect.TypeOf(SessionSetupResponseDecoder(nil)),
	reflect.TypeOf(LogoffResponseDecoder(nil)),
	reflect.TypeOf(TreeConnectResponseDecoder(nil)),
	reflect.TypeOf(TreeDisconnectResponseDecoder(nil)),
	reflect.TypeOf(CreateResponseDecoder(nil)),
	reflect.TypeOf(CloseResponseDecoder(nil)),
	reflect.TypeOf(FlushResponseDecoder(nil)),
	reflect.TypeOf(ReadResponseDecoder(nil)),
	reflect.TypeOf(WriteResponseDecoder(nil)),
	reflect.TypeOf(IoctlResponseDecoder(nil)),
	reflect.TypeOf(QueryDirectoryResponseDecoder(nil)),
	reflect.TypeOf(QueryInfoResponseDecoder(nil)),
	reflect.TypeOf(SetInfoResponseDecoder(nil)),
	reflect.TypeOf(SidDecoder(nil)),
	reflect.TypeOf(SecurityDescriptorDecoder(nil)),
	reflect.TypeOf(AclHeaderDecoder(nil)),
	reflect.TypeOf(AceDecoder(nil)),
	reflect.TypeOf(SymbolicLinkReparseDataBufferDecoder(nil)),
	reflect.TypeOf(SrvRequestResumeKeyResponseDecoder(nil)),
	reflect.TypeOf(SrvCopychunkResponseDecoder(nil)),
	reflect.TypeOf(FileDirectoryInformationDecoder(nil)),
	reflect.TypeOf(FileFsFullSizeInformationDecoder(nil)),
	reflect.TypeOf(FileQuotaInformationDecoder(nil)),
	reflect.TypeOf(FileEndOfFileInformationDecoder(nil)),
	reflect.TypeOf(FileAllInformationDecoder(nil)),
	reflect.TypeOf(FileBasicInformationDecoder(nil)),
	reflect.TypeOf(FileStandardInformationDecoder(nil)),
	reflect.TypeOf(FileInternalInformationDecoder(nil)),
	reflect.TypeOf(FileEaInformationDecoder(nil)),
	reflect.TypeOf(FileAccessInformationDecoder(nil)),
	reflect.TypeOf(FilePositionInformationDecoder(nil)),
	reflect.TypeOf(FileModeInformationDecoder(nil)),
	reflect.TypeOf(FileAlignmentInformationDecoder(nil)),
	reflect.TypeOf(FileNameInformationDecoder(nil)),
}

// decoder holds the method indices exercise calls, resolved once per type.
type decoder struct {
	isInvalid int // -1 if the type has no IsInvalid
	accessors []int
}

// register records typ and every decoder type its accessors return.
func register(decoders map[reflect.Type]decoder, typ reflect.Type) {
	if _, ok := decoders[typ]; ok {
		return
	}
	d := decoder{isInvalid: -1}
	decoders[typ] = d // stops the recursion on a type that returns itself
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		switch {
		case m.Name == "IsInvalid":
			d.isInvalid = i
		case m.Type.NumIn() == 1: // the receiver only
			d.accessors = append(d.accessors, i)
			for j := 0; j < m.Type.NumOut(); j++ {
				if out := m.Type.Out(j); out.Kind() == reflect.Slice && out.Elem().Kind() == reflect.Uint8 && out.NumMethod() > 0 {
					register(decoders, out)
				}
			}
		}
	}
	decoders[typ] = d
}

// exercise calls every argument-free accessor of a decoder that IsInvalid
// cleared, and of the decoders those accessors return.
func exercise(decoders map[reflect.Type]decoder, v reflect.Value, depth int) {
	d := decoders[v.Type()]
	if depth > 3 || d.isInvalid >= 0 && v.Method(d.isInvalid).Call(nil)[0].Bool() {
		return
	}
	for _, i := range d.accessors {
		for _, r := range v.Method(i).Call(nil) {
			if _, ok := decoders[r.Type()]; ok {
				exercise(decoders, r, depth+1)
			}
		}
	}
}

// Every server-controlled decoder must reject a buffer its accessors cannot
// slice: IsInvalid is the only guard between a response and the accessors.
func FuzzServerDecoders(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 256))
	f.Add([]byte(negotiateResponse(256, SMB311, 128, 16, 192)))

	decoders := map[reflect.Type]decoder{}
	for _, typ := range serverDecoders {
		register(decoders, typ)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		for _, typ := range serverDecoders {
			exercise(decoders, reflect.ValueOf(b).Convert(typ), 0)
		}
	})
}
