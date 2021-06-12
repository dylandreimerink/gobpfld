package ebpf

import (
	"bytes"
	"embed"
	"testing"
)

//go:embed asm_test.bpfasm
var assembly embed.FS

const filename = "asm_test.bpfasm"

// This test ensures that the format accepted by the dissasembler matches the output of decoded instructions.
// This test doesn't include dissasembly specific features like labels and number formatting.
func TestDecodeEncodeSymmetry(t *testing.T) {
	fileContents, err := assembly.ReadFile(filename)
	if err != nil {
		t.Error(err)
	}

	disInst, err := AssemblyToInstructions(filename, bytes.NewReader(fileContents))
	if err != nil {
		t.Error(err)
	}

	var disassembled string
	for _, inst := range disInst {
		disassembled += inst.String() + "\n"
	}

	encoded, err := Encode(disInst)
	if err != nil {
		t.Error(err)
	}

	decInst, err := Decode(encoded)
	if err != nil {
		t.Error(err)
	}

	var decoded string
	for _, inst := range decInst {
		decoded += inst.String() + "\n"
	}

	if string(fileContents) != decoded {
		t.Error("Encoding and decoding not symetric")
	}
}
