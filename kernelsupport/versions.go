package kernelsupport

type kernelFeatureVersion struct {
	version  kernelVersion
	features KernelFeatures
}

// a list of eBPF kernel features which are available from a given kernel version forward.
// largely based on https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
var featureMinVersion = []kernelFeatureVersion{
	{
		version: kernelVersion{major: 3, minor: 16},
		features: KernelFeatures{
			Arch: KFeatArchx86_64,
		},
	},
	{
		version: kernelVersion{major: 3, minor: 18},
		features: KernelFeatures{
			Arch: KFeatArchARM64,
			API:  KFeatAPIMapLookup | KFeatAPIMapUpdate | KFeatAPIMapDelete | KFeatAPIMapGetNext,
		},
	},
	{
		version: kernelVersion{major: 3, minor: 19},
		features: KernelFeatures{
			Map: KFeatMapHash | KFeatMapArray,
			API: KFeatAPIMapUpdate,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 1},
		features: KernelFeatures{
			Arch: KFeatArchs390,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 2},
		features: KernelFeatures{
			Map: KFeatMapTailCall,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 3},
		features: KernelFeatures{
			Map: KFeatMapPerfEvent,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 6},
		features: KernelFeatures{
			Map: KFeatMapPerCPUHash | KFeatMapPerCPUArray | KFeatMapStackTrace,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 8},
		features: KernelFeatures{
			Arch: KFeatArchPP64,
			Map:  KFeatMapCGroupArray,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 10},
		features: KernelFeatures{
			Map: KFeatMapLRUHash | KFeatMapLRUPerCPUHash,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 11},
		features: KernelFeatures{
			Map: KFeatMapLPMTrie,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 12},
		features: KernelFeatures{
			Arch: KFeatArchSparc64,
			Map:  KFeatMapArrayOfMaps | KFeatMapHashOfMaps,
			API:  KFeatAPIMapGetNextNull,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 13},
		features: KernelFeatures{
			Arch: KFeatArchMIPS,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 14},
		features: KernelFeatures{
			Arch: KFeatArchARM32,
			Map:  KFeatMapNetdevArray | KFeatMapSocketArray,
			API:  KFeatAPIMapNumaCreate,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 15},
		features: KernelFeatures{
			Map: KFeatMapCPU,
			API: KFeatAPIMapSyscallRW | KFeatAPIMapName,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 18},
		features: KernelFeatures{
			Arch: KFeatArchx86,
			Map:  KFeatMapAFXDP | KFeatMapSocketHash,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 19},
		features: KernelFeatures{
			Map: KFeatMapCGroupStorage | KFeatMapReuseportSocketArray,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 20},
		features: KernelFeatures{
			Map: KFeatMapPerCPUCGroupStorage | KFeatMapQueue | KFeatMapStack,
			API: KFeatAPIMapLookupAndDelete,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 0},
		features: KernelFeatures{
			API: KFeatAPIMapZeroSeed,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 1},
		features: KernelFeatures{
			Arch: KFeatArchRiscVRV64G,
			API:  KFeatAPIMapLock,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 2},
		features: KernelFeatures{
			Map: KFeatMapSocketLocalStorage,
			API: KFeatAPIMapBPFRW | KFeatAPIMapFreeze,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 4},
		features: KernelFeatures{
			Map: KFeatMapNetdevHash,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 5},
		features: KernelFeatures{
			API: KFeatAPIMapMMap,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 6},
		features: KernelFeatures{
			Map: KFeatMapStructOps,
			API: KFeatAPIMapLookupBatch | KFeatAPIMapUpdateBatch | KFeatAPIMapDeleteBatch | KFeatAPIMapLookupAndDeleteBatch,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 7},
		features: KernelFeatures{
			Arch: KFeatArchRiscVRV32G,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 8},
		features: KernelFeatures{
			Map: KFeatMapRingBuffer,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 10},
		features: KernelFeatures{
			Map: KFeatMapINodeStorage,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 11},
		features: KernelFeatures{
			Map: KFeatMapTaskStorage,
		},
	},
}
