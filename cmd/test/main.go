package main

import (
	"fmt"
	"os"
	"time"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/perf"
)

func main() {
	elf, err := os.Open("bpf/syscall_tp_kernel")
	if err != nil {
		panic(err)
	}

	loadedElf, err := gobpfld.LoadProgramFromELF(elf, gobpfld.ELFParseSettings{
		TruncateNames: true,
	})
	if err != nil {
		panic(err)
	}

	for name, bpfmap := range loadedElf.Maps {
		fmt.Println("loading map: ", name)
		err = bpfmap.Load()
		if err != nil {
			panic(err)
		}
	}

	for name, program := range loadedElf.Programs {
		fmt.Println("loading program: ", name)
		log, err := program.Load(gobpfld.BPFProgramLoadSettings{
			ProgramType:      bpftypes.BPF_PROG_TYPE_TRACEPOINT,
			VerifierLogLevel: bpftypes.BPFLogLevelVerbose,
			VerifierLogSize:  1 << 20,
		})
		if err != nil {
			fmt.Println(log)
			panic(err)
		}

		event, err := perf.OpenTracepointEvent("syscalls", name)
		if err != nil {
			panic(err)
		}

		progFD, err := program.Fd()
		if err != nil {
			panic(err)
		}

		err = event.AttachBPFProgram(progFD)
		if err != nil {
			panic(err)
		}
	}

	for {
		time.Sleep(1 * time.Second)

		for name, bpfmap := range loadedElf.Maps {
			arrayMap := bpfmap.(*gobpfld.ArrayMap)

			var val uint64
			err = arrayMap.Get(0, &val)
			if err != nil {
				panic(err)
			}

			fmt.Println(name, ": ", val)
		}
	}
}
