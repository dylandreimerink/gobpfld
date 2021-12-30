package gobpfld

import (
	"bytes"
	"testing"
)

func TestBTFKind_String(t *testing.T) {
	for i := BTFKind(0); i < btfKindMax; i++ {
		if i.String() == "" {
			t.Fatalf("missing string translation for BPFKind %d", i)
		}
	}
}

func TestStringTbl_ParseSerializeSymmetry(t *testing.T) {
	type fields struct {
		Blob []byte
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "happy path",
			fields: fields{
				Blob: []byte("\x00abc\x00def\x00ghi\x00"),
			},
		},
		{
			name: "no elements",
			fields: fields{
				Blob: []byte(""),
			},
		},
		{
			name: "nil elem",
			fields: fields{
				Blob: []byte("\x00"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cp := make([]byte, len(tt.fields.Blob))
			copy(cp, tt.fields.Blob)

			st := StringTblFromBlob(tt.fields.Blob)
			st.Serialize()

			if !bytes.Equal(cp, st.btfStringBlob) {
				t.Fail()
			}
		})
	}
}
