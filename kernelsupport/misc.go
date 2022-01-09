package kernelsupport

import (
	"fmt"
	"strings"
)

// MiscSupport is a flagset that describes features that don't neatly fit into any other category
type MiscSupport uint64

const (
	// KFeatMiscXSKRingFlags indicates that the kernel version has flags in AF_XDP rings
	// https://github.com/torvalds/linux/commit/77cd0d7b3f257fd0e3096b4fdcff1a7d38e99e10
	KFeatMiscXSKRingFlags MiscSupport = iota
	// KFeatBTFFuncScope indicates that the kernel doesn't require BTF FUNC types to have a vlen of 0.
	// Since kernel 5.6, the scope of functions is encoded in vlen.
	// https://github.com/cilium/ebpf/issues/43
	// https://github.com/llvm/llvm-project/commit/fbb64aa69835c8e3e9efe0afc8a73058b5a0fb3c
	KFeatBTFFuncScope
	// KFeatGlobalData indicates that the kernel supports global data sections.
	// https://lwn.net/Articles/784936/
	// https://github.com/torvalds/linux/commit/d8eca5bbb2be9bc7546f9e733786fa2f1a594c67
	KFeatGlobalData
	kFeatMiscMax //nolint:revive // leading k is used to stay consistent with exported vars
)

// Has returns true if 'as' has all the specified flags
func (ms MiscSupport) Has(flags MiscSupport) bool {
	return ms&flags == flags
}

var miscSupportToString = map[MiscSupport]string{
	KFeatMiscXSKRingFlags: "XSK ring flags",
}

func (ms MiscSupport) String() string {
	var miscFeats []string
	for i := MiscSupport(1); i < kFeatMiscMax; i = i << 1 {
		// If this flag is set
		if ms&i > 0 {
			miscStr := miscSupportToString[i]
			if miscStr == "" {
				miscStr = fmt.Sprintf("missing attach str(%d)", i)
			}
			miscFeats = append(miscFeats, miscStr)
		}
	}

	if len(miscFeats) == 0 {
		return "No support"
	}

	if len(miscFeats) == 1 {
		return miscFeats[0]
	}

	return strings.Join(miscFeats, ", ")
}
