package kernelsupport

import (
	"fmt"
	"strings"
)

// ArchSupport is a flagset which describes on which architectures eBPF is supported
type ArchSupport uint64

const (
	// KFeatArchx86_64 means the kernel has eBPF support on the x86_64 architecture
	KFeatArchx86_64 ArchSupport = 1 << iota
	// KFeatArchARM64 means the kernel has eBPF support on the ARM64 architecture
	KFeatArchARM64
	// KFeatArchs390 means the kernel has eBPF support on the s390 architecture
	KFeatArchs390
	// KFeatArchPP64 means the kernel has eBPF support on the PowerPC64 architecture
	KFeatArchPP64
	// KFeatArchSparc64 means the kernel has eBPF support on the Sparc64 architecture
	KFeatArchSparc64
	// KFeatArchMIPS means the kernel has eBPF support on the MIPS architecture
	KFeatArchMIPS
	// KFeatArchARM32 means the kernel has eBPF support on the ARM32 architecture
	KFeatArchARM32
	// KFeatArchx86 means the kernel has eBPF support on the x86_32 architecture
	KFeatArchx86
	// KFeatArchRiscVRV64G means the kernel has eBPF support on the RISC-V RV64G architecture
	KFeatArchRiscVRV64G
	// KFeatArchRiscVRV32G means the kernel has eBPF support on the RISC-V RV32G architecture
	KFeatArchRiscVRV32G

	// An end marker for enumeration, not an actual feature flag
	kFeatArchMax //nolint:revive // leading k is used to stay consistent with exported vars
)

// Has returns true if 'as' has all the specified flags
func (as ArchSupport) Has(flags ArchSupport) bool {
	return as&flags == flags
}

var archSupportToString = map[ArchSupport]string{
	KFeatArchx86_64:     "x86_64",
	KFeatArchARM64:      "ARM64",
	KFeatArchs390:       "s309",
	KFeatArchPP64:       "PowerPC64",
	KFeatArchSparc64:    "Sparc64",
	KFeatArchMIPS:       "MIPS",
	KFeatArchARM32:      "ARM32",
	KFeatArchx86:        "x86_32",
	KFeatArchRiscVRV64G: "RISC-V RV64G",
	KFeatArchRiscVRV32G: "RISC-V RV32G",
}

func (as ArchSupport) String() string {
	var archs []string
	for i := ArchSupport(1); i < kFeatArchMax; i = i << 1 {
		// If this flag is set
		if as&i > 0 {
			archStr := archSupportToString[i]
			if archStr == "" {
				archStr = fmt.Sprintf("missing arch str(%d)", i)
			}
			archs = append(archs, archStr)
		}
	}

	if len(archs) == 0 {
		return "No support"
	}

	if len(archs) == 1 {
		return archs[0]
	}

	return strings.Join(archs, ", ")
}
