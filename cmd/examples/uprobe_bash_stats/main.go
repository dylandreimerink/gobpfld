package main

import (
	"fmt"
	"os"
	"time"

	"github.com/dylandreimerink/gobpfld"
	"github.com/dylandreimerink/gobpfld/bpftypes"
)

func main() {
	elf, err := os.Open("bpf/bash_stats")
	if err != nil {
		panic(err)
	}

	loadedElf, err := gobpfld.LoadProgramFromELF(elf, gobpfld.ELFParseSettings{
		TruncateNames: true,
	})
	if err != nil {
		panic(err)
	}

	stats := loadedElf.Maps["bash_stats"].(*gobpfld.ArrayMap)
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

	fmt.Println("attaching")

	err = program.Attach(gobpfld.ProgKPAttachOpts{
		Event: "bash_trace",
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("attached")

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
