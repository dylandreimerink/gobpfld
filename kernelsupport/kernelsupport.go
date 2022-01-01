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
	Misc MiscSupport
}

// CurrentFeatures is a singleton containing the result of MustGetKernelFeatures. Assuming kernel features don't
// change during the lifetime. Using this singleton saves a lot of performance.
var CurrentFeatures = MustGetKernelFeatures()

// CurrentVersion is a singleton containing the result of MustGetKernelVersion. Assuming the kernel version doesn't
// change during the lifetime. Using this singleton saves a lot of performance.
var CurrentVersion = MustGetKernelVersion()

// MustGetKernelFeatures runs GetKernelFeatures but panics if any error is detected
func MustGetKernelFeatures() KernelFeatures {
	features, err := getKernelFeatures(true)
	if err != nil {
		panic(err)
	}
	return features
}

// GetKernelFeatures returns a list of kernel features for the kernel on which
// the current program is currently running.
func GetKernelFeatures() (KernelFeatures, error) {
	return getKernelFeatures(false)
}

func getKernelFeatures(must bool) (KernelFeatures, error) {
	utsname, version, err := getKernelVersion(must)
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
			features.Misc = features.Misc | kvf.features.Misc
		}
	}

	machineBytes := make([]byte, len(utsname.Machine))
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

// MustGetKernelVersion runs GetKernelFeatures but panics if any error is detected
func MustGetKernelVersion() KernelVersion {
	_, features, err := getKernelVersion(true)
	if err != nil {
		panic(err)
	}
	return features
}

func GetKernelVersion() (KernelVersion, error) {
	_, version, err := getKernelVersion(false)
	return version, err
}

func getKernelVersion(must bool) (*syscall.Utsname, KernelVersion, error) {
	var utsname syscall.Utsname
	err := syscall.Uname(&utsname)
	if err != nil {
		return nil, KernelVersion{}, fmt.Errorf("error while calling syscall.Uname: %w", err)
	}

	releaseBytes := make([]byte, len(utsname.Release))
	for i, v := range utsname.Release {
		if v == 0x00 {
			releaseBytes = releaseBytes[:i]
			break
		}
		releaseBytes[i] = byte(v)
	}
	release := string(releaseBytes)

	version, err := ParseKernelVersion(release, true)
	if err != nil {
		return nil, version, err
	}

	return &utsname, version, err
}

func Version(major, minor, patch int) KernelVersion {
	return KernelVersion{
		Major: major,
		Minor: minor,
		Patch: patch,
	}
}

type KernelVersion struct {
	Major int
	Minor int
	Patch int
}

// Higher returns true if the 'cmp' version is higher than the 'kv' version
func (kv KernelVersion) Higher(cmp KernelVersion) bool {
	if kv.Major > cmp.Major {
		return true
	}
	if kv.Major < cmp.Major {
		return false
	}

	// Majors are equal

	if kv.Minor > cmp.Minor {
		return true
	}
	if kv.Minor < cmp.Minor {
		return false
	}

	// Minors are equal

	if kv.Patch >= cmp.Patch {
		return true
	}

	return false
}

func ParseKernelVersion(release string, must bool) (version KernelVersion, err error) {
	parts := strings.Split(release, "-")

	// The base version is before the -, discard anything after the -
	base := parts[0]
	baseParts := strings.Split(base, ".")
	if len(baseParts) > 2 {
		version.Patch, err = strconv.Atoi(baseParts[2])
		if err != nil {
			// The patch version is not critically important in most cases. If 'must' is true this would result
			// in a panic, instread ignore the error.
			// A malformed patch version is possible with incorrect kernel parameters, so handle it gracefully
			if !must {
				return version, fmt.Errorf("error while parsing kernel patch version '%s': %w", baseParts[2], err)
			}
		}
	}

	if len(baseParts) > 1 {
		version.Minor, err = strconv.Atoi(baseParts[1])
		if err != nil {
			return version, fmt.Errorf("error while parsing kernel minor version '%s': %w", baseParts[1], err)
		}
	}

	version.Major, err = strconv.Atoi(baseParts[0])
	if err != nil {
		return version, fmt.Errorf("error while parsing kernel major version '%s': %w", baseParts[0], err)
	}

	return version, nil
}
