package main

import (
	"fmt"
	"os"
	"time"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

func main() {
	elf, err := os.Open("bpf/tracex1_kern")
	if err != nil {
		panic(err)
	}

	loadedElf, err := gobpfld.LoadProgramFromELF(elf, gobpfld.ELFParseSettings{
		TruncateNames: true,
	})
	if err != nil {
		panic(err)
	}

	stats := loadedElf.Maps["execve_stats"].(*gobpfld.ArrayMap)
	err = stats.Load()
	if err != nil {
		panic(err)
	}

	program := loadedElf.Programs["bpf_prog1"].(*gobpfld.ProgramKProbe)

	log, err := program.Load(gobpfld.ProgKPLoadOpts{
		VerifierLogLevel: bpftypes.BPFLogLevelVerbose,
		VerifierLogSize:  1 << 20,
	})
	if err != nil {
		fmt.Println(log)
		panic(err)
	}

	err = program.Attach(gobpfld.ProgKPAttachOpts{})
	if err != nil {
		panic(err)
	}

	defer func() {
		err = program.Detach()
		if err != nil {
			panic(err)
		}
	}()

	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		var val uint64
		err = stats.Get(0, &val)
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println(val)
	}
}
