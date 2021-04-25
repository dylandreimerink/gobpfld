package kernelsupport

import (
	"fmt"
	"strconv"
	"strings"
	"syscall"
)

// KernelFeatures is a set of flagsets which describe the eBPF support of a kernel version.
// Flags are split amount several sets since the won't all fit in one uint64
type KernelFeatures struct {
	// BPF is set to true if eBPF is supported on the current kernel version and arch combo
	BPF     bool
	Arch    ArchSupport
	Map     MapSupport
	API     APISupport
	Program ProgramSupport
	Attach  AttachSupport
	// TODO helper functions
	// TODO misc (xdp, sleepable, ect.)
}

// Check the kernel features at startup since they will not change during program execution.
// This singleton should be used rather than constantly calling GetKernelFeatures or
// MustGetKernelFeatures to improve performance.
var CurrentFeatures = MustGetKernelFeatures()

// MustGetKernelFeatures runs GetKernelFeatures but panics if any error is detected
func MustGetKernelFeatures() KernelFeatures {
	features, err := GetKernelFeatures()
	if err != nil {
		panic(err)
	}
	return features
}

// GetKernelFeatures returns a list of kernel features for the kernel on which
// the current program is currently running.
func GetKernelFeatures() (KernelFeatures, error) {
	var utsname syscall.Utsname
	err := syscall.Uname(&utsname)
	if err != nil {
		return KernelFeatures{}, fmt.Errorf("error while calling syscall.Uname: %w", err)
	}

	var releaseBytes = make([]byte, len(utsname.Release))
	for i, v := range utsname.Release {
		if v == 0x00 {
			releaseBytes = releaseBytes[:i]
			break
		}
		releaseBytes[i] = byte(v)
	}
	release := string(releaseBytes)

	version, err := parseKernelVersion(release)
	if err != nil {
		return KernelFeatures{}, err
	}

	features := KernelFeatures{}
	for _, kvf := range featureMinVersion {
		if version.Higher(kvf.version) {
			features.Arch = features.Arch | kvf.features.Arch
			features.Map = features.Map | kvf.features.Map
			features.API = features.API | kvf.features.API
			features.Program = features.Program | kvf.features.Program
			features.Attach = features.Attach | kvf.features.Attach
		}
	}

	var machineBytes = make([]byte, len(utsname.Machine))
	for i, v := range utsname.Machine {
		if v == 0x00 {
			machineBytes = machineBytes[:i]
			break
		}
		machineBytes[i] = byte(v)
	}
	machine := string(machineBytes)

	// Attempt to match the machine UTS string to an architecture
	switch machine {
	case "x86_64":
		features.BPF = features.Arch.Has(KFeatArchx86_64)
	case "arm64", "armv8b", "aarch64_be", "aarch64":
		features.BPF = features.Arch.Has(KFeatArchARM64)
	case "s309", "s390x":
		features.BPF = features.Arch.Has(KFeatArchs390)
	case "ppc64":
		features.BPF = features.Arch.Has(KFeatArchPP64)
	case "sparc64":
		features.BPF = features.Arch.Has(KFeatArchSparc64)
	case "mips64", "mips32", "mips":
		features.BPF = features.Arch.Has(KFeatArchMIPS)
	case "arm", "arm32", "armv8l":
		features.BPF = features.Arch.Has(KFeatArchARM32)
	case "i386", "i486", "i586", "i686":
		features.BPF = features.Arch.Has(KFeatArchx86)
	case "riscv64":
		features.BPF = features.Arch.Has(KFeatArchRiscVRV64G)
	case "riscv32":
		features.BPF = features.Arch.Has(KFeatArchRiscVRV32G)
	}

	return features, nil
}

type kernelVersion struct {
	major int
	minor int
	patch int
}

// Higher returns true if the 'cmp' version is higher than the 'kv' version
func (kv kernelVersion) Higher(cmp kernelVersion) bool {
	if kv.major > cmp.major {
		return true
	}
	if kv.major < cmp.major {
		return false
	}

	// Majors are equal

	if kv.minor > cmp.minor {
		return true
	}
	if kv.minor < cmp.minor {
		return false
	}

	// Minors are equal

	if kv.patch >= cmp.patch {
		return true
	}

	return false
}

func parseKernelVersion(release string) (version kernelVersion, err error) {
	parts := strings.Split(release, "-")

	// The base version is before the -, discard anything after the -
	base := parts[0]
	baseParts := strings.Split(base, ".")
	if len(baseParts) > 2 {
		version.patch, err = strconv.Atoi(baseParts[2])
		if err != nil {
			return version, fmt.Errorf("error while parsing kernel patch version '%s': %w", baseParts[2], err)
		}
	}

	if len(baseParts) > 1 {
		version.minor, err = strconv.Atoi(baseParts[1])
		if err != nil {
			return version, fmt.Errorf("error while parsing kernel minor version '%s': %w", baseParts[1], err)
		}
	}

	version.major, err = strconv.Atoi(baseParts[0])
	if err != nil {
		return version, fmt.Errorf("error while parsing kernel patch version '%s': %w", baseParts[0], err)
	}

	return version, nil
}
