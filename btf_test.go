package gobpfld

import "testing"

func TestBTFKind_String(t *testing.T) {
	for i := BTFKind(0); i < btfKindMax; i++ {
		if i.String() == "" {
			t.Fatalf("missing string translation for BPFKind %d", i)
		}
	}
}
