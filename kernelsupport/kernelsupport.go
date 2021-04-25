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
	Arch ArchSupport
	Map  MapSupport
	API  APISupport
	// TODO program types
	// TODO attach types
	// TODO helper functions
	// TODO misc (xdp, sleepable, ect.)
}

// Check the kernel features at startup since they will not change during program execution.
// This singleton should be used rather than constantly calling GetKernelFeatures or
// MustGetKernelFeatures to improve performance.
var CurrentFeatures = MustGetKernelFeatures()

type kernelFeatureVersion struct {
	version  kernelVersion
	features KernelFeatures
}

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
		}
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
