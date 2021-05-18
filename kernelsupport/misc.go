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
	kFeatMiscMax                      //nolint:revive // leading k is used to stay consistent with exported vars
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
