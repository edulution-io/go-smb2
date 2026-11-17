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

// exercise calls every argument-free accessor of a decoder that IsInvalid
// cleared, and of the decoders those accessors return.
func exercise(t *testing.T, v reflect.Value, depth int) {
	t.Helper()
	if depth > 3 {
		return
	}
	if m := v.MethodByName("IsInvalid"); m.IsValid() && m.Call(nil)[0].Bool() {
		return
	}
	for i := 0; i < v.NumMethod(); i++ {
		m := v.Method(i)
		if v.Type().Method(i).Name == "IsInvalid" || m.Type().NumIn() != 0 {
			continue
		}
		for _, r := range call(t, v.Type().Name()+"."+v.Type().Method(i).Name, m) {
			if r.Kind() == reflect.Slice && r.Type().Elem().Kind() == reflect.Uint8 && r.Type().NumMethod() > 0 {
				exercise(t, r, depth+1)
			}
		}
	}
}

func call(t *testing.T, name string, m reflect.Value) []reflect.Value {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked on a buffer IsInvalid cleared: %v", name, r)
		}
	}()
	return m.Call(nil)
}

// Every server-controlled decoder must reject a buffer its accessors cannot
// slice: IsInvalid is the only guard between a response and the accessors.
func FuzzServerDecoders(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Add(make([]byte, 256))
	f.Add([]byte(negotiateResponse(256, SMB311, 128, 16, 192)))

	f.Fuzz(func(t *testing.T, b []byte) {
		for _, typ := range serverDecoders {
			exercise(t, reflect.ValueOf(b).Convert(typ), 0)
		}
	})
}
