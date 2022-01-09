//go:build bpftests
// +build bpftests

package integration

import (
	"bytes"
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

// This intergration test, tests the loaders capability to relocate global data
func TestIntegrationGlobalData(t *testing.T) {
	if !kernelsupport.CurrentFeatures.Misc.Has(kernelsupport.KFeatGlobalData) {
		t.Skip("skipping, current kernel version doesn't support global data")
	}

	elfFileBytes, err := ebpf.ReadFile("ebpf/global_data_test")
	if err != nil {
		t.Fatalf("error opening ELF file: %s\n", err.Error())
	}

	elf, err := gobpfld.LoadProgramFromELF(bytes.NewReader(elfFileBytes), gobpfld.ELFParseSettings{
		TruncateNames: true,
	})
	if err != nil {
		t.Fatalf("error while reading ELF file: %s\n", err.Error())
	}

	prog := elf.Programs["load_static_data"].(*gobpfld.ProgramXDP)
	log, err := prog.Load(gobpfld.ProgXDPLoadOpts{
		VerifierLogLevel: bpftypes.BPFLogLevelVerbose,
	})
	if err != nil {
		prog.DecodeToReader(os.Stdout)
		t.Log(log)
		t.Fatalf("error while loading program: %s\n", err.Error())
	}

	_, err = prog.XDPTestProgram(gobpfld.TestXDPProgSettings{
		Repeat: 1,
		Data:   make([]byte, 20),
	})
	if err != nil {
		t.Fatalf("error while testing program: %s\n", err.Error())
	}

	numTests := []struct {
		Name     string
		Index    uint32
		Expected uint64
	}{
		{Name: "relocate .bss reference", Index: 0, Expected: 0},
		{Name: "relocate .data reference", Index: 1, Expected: 42},
		{Name: "relocate .rodata reference", Index: 2, Expected: 24},
		{Name: "relocate .bss reference", Index: 3, Expected: 0},
		{Name: "relocate .data reference", Index: 4, Expected: 0xffeeff},
		{Name: "relocate .rodata reference", Index: 5, Expected: 0xabab},
		{Name: "relocate .bss reference", Index: 6, Expected: 1234},
		{Name: "relocate .bss reference", Index: 7, Expected: 0},
		{Name: "relocate .rodata reference", Index: 8, Expected: 0xab},
		{Name: "relocate .rodata reference", Index: 9, Expected: 0x1111111111111111},
		{Name: "relocate .rodata reference", Index: 10, Expected: math.MaxUint64},
	}

	resultNumber := elf.Maps["result_number"].(*gobpfld.ArrayMap)
	for _, test := range numTests {
		t.Run("num_"+test.Name+"_"+strconv.Itoa(int(test.Index)), func(t *testing.T) {
			var v uint64
			err = resultNumber.Get(test.Index, &v)
			if err != nil {
				t.Fatalf("map get: %s", err.Error())
			}

			if v != test.Expected {
				t.Fatalf("expected: '%d', got: '%d'", test.Expected, v)
			}
		})
	}

	strTests := []struct {
		Name     string
		Index    uint32
		Expected string
	}{
		{Name: "relocate .rodata reference", Index: 0, Expected: "abcdefghijklmnopqrstuvwxyz"},
		{Name: "relocate .data reference", Index: 1, Expected: "abcdefghijklmnopqrstuvwxyz"},
		{Name: "relocate .bss reference", Index: 2, Expected: ""},
		{Name: "relocate .data reference", Index: 3, Expected: "abcdexghijklmnopqrstuvwxyz"},
		{Name: "relocate .bss reference", Index: 4, Expected: "\x00\x00hello"},
	}

	resultStr := elf.Maps["result_string"].(*gobpfld.ArrayMap)
	for _, test := range strTests {
		t.Run("num_"+test.Name+"_"+strconv.Itoa(int(test.Index)), func(t *testing.T) {
			v := make([]byte, 32)
			err = resultStr.Get(test.Index, &v)
			if err != nil {
				t.Fatalf("map get: %s", err.Error())
			}

			vStr := string(bytes.TrimRight(v, "\x00"))
			if vStr != test.Expected {
				t.Fatalf("expected: '%s', got: '%s'", test.Expected, vStr)
			}
		})
	}

	type foo struct {
		a uint8
		b uint32
		c uint64
	}

	structTests := []struct {
		Name     string
		Index    uint32
		Expected foo
	}{
		{Name: "relocate .rodata reference", Index: 0, Expected: foo{a: 42, b: 0xfefeefef, c: 0x1111111111111111}},
		{Name: "relocate .bss reference", Index: 1, Expected: foo{}},
		{Name: "relocate .rodata reference", Index: 2, Expected: foo{}},
		{Name: "relocate .data reference", Index: 3, Expected: foo{a: 41, b: 0xeeeeefef, c: 0x2111111111111111}},
	}

	resultStruct := elf.Maps["result_struct"].(*gobpfld.ArrayMap)
	for _, test := range structTests {
		t.Run("struct_"+test.Name+"_"+strconv.Itoa(int(test.Index)), func(t *testing.T) {
			var v foo
			err = resultStruct.Get(test.Index, &v)
			if err != nil {
				t.Fatalf("map get: %s", err.Error())
			}

			if v != test.Expected {
				t.Fatalf("expected: '%v', got: '%v'", test.Expected, v)
			}
		})
	}
}
