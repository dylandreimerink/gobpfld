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
			API:  KFeatAPIBasic,
		},
	},
	{
		version: kernelVersion{major: 3, minor: 19},
		features: KernelFeatures{
			Map:     KFeatMapHash | KFeatMapArray,
			Program: KFeatProgSocketFilter,
			Attach:  KFeatAttachINetIngressEgress,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 1},
		features: KernelFeatures{
			Arch:    KFeatArchs390,
			Program: KFeatProgKProbe | KFeatProgSchedCLS | KFeatProgSchedACT,
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
		version: kernelVersion{major: 4, minor: 4},
		features: KernelFeatures{
			API: KFeatAPIObjPinGet,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 6},
		features: KernelFeatures{
			Map: KFeatMapPerCPUHash | KFeatMapPerCPUArray | KFeatMapStackTrace,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 7},
		features: KernelFeatures{
			Program: KFeatProgTracepoint,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 8},
		features: KernelFeatures{
			Arch:    KFeatArchPP64,
			Map:     KFeatMapCGroupArray,
			Program: KFeatProgXDP,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 9},
		features: KernelFeatures{
			Program: KFeatProgPerfEvent,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 10},
		features: KernelFeatures{
			Map: KFeatMapLRUHash | KFeatMapLRUPerCPUHash,
			Program: KFeatProgCGroupSKB | KFeatProgCGroupSocket | KFeatProgLWTIn |
				KFeatProgLWTOut | KFeatProgLWTXmit,
			Attach: KFeatAttachInetSocketCreate,
			API:    KFeatAPIProgramAttachDetach,
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
			API:  KFeatAPIMapGetNextNull | KFeatAPIProgramTestRun,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 13},
		features: KernelFeatures{
			Arch:    KFeatArchMIPS,
			Program: KFeatProgSocketOps,
			Attach:  KFeatAttachSocketOps,
			API: KFeatAPIProgramGetNextID | KFeatAPIMapGetNextID |
				KFeatAPIProgramGetFDByID | KFeatAPIMapGetFDByID | KFeatAPIObjectGetInfoByFD,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 14},
		features: KernelFeatures{
			Arch:    KFeatArchARM32,
			Map:     KFeatMapNetdevArray | KFeatMapSocketArray,
			API:     KFeatAPIMapNumaCreate,
			Program: KFeatProgSKSKB,
			Attach:  KFeatAttachStreamParserVerdict,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 15},
		features: KernelFeatures{
			Map:     KFeatMapCPU,
			API:     KFeatAPIMapSyscallRW | KFeatAPIMapName | KFeatAPIProgramQuery,
			Program: KFeatProgCGroupDevice,
			Attach:  KFeatAttachCGroupDevice,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 17},
		features: KernelFeatures{
			Program: KFeatProgSKMsg | KFeatProgRawTracepoint | KFeatProgCGroupSocketAddr,
			Attach: KFeatAttachSKMsgVerdict | KFeatAttachCGroupInetBind |
				KFeatAttachCGroupInetConnect | KFeatAttachCGroupInetPostBind,
			API: KFeatAPIRawTracepointOpen,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 18},
		features: KernelFeatures{
			Arch:    KFeatArchx86,
			Map:     KFeatMapAFXDP | KFeatMapSocketHash,
			Program: KFeatProgLWTSeg6Local | KFeatProgLIRCMode2,
			Attach:  KFeatAttachCGroupUDPSendMsg | KFeatAttachLIRCMode2,
			API:     KFeatAPIBTFLoad | KFeatAPIBTFGetFDByID | KFeatAPITaskFDQuery,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 19},
		features: KernelFeatures{
			Map:     KFeatMapCGroupStorage | KFeatMapReuseportSocketArray,
			Program: KFeatProgSKReusePort,
		},
	},
	{
		version: kernelVersion{major: 4, minor: 20},
		features: KernelFeatures{
			Map:     KFeatMapPerCPUCGroupStorage | KFeatMapQueue | KFeatMapStack,
			API:     KFeatAPIMapLookupAndDelete,
			Program: KFeatProgFlowDissector,
			Attach:  KFeatAttachFlowDissector,
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
			Map:     KFeatMapSocketLocalStorage,
			API:     KFeatAPIMapBPFRW | KFeatAPIMapFreeze,
			Program: KFeatProgCGroupSysctl | KFeatProgRawTracepointWritable,
			Attach:  KFeatAttachCGroupSysctl | KFeatAttachCGroupUDPRecvMsg,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 3},
		features: KernelFeatures{
			Program: KFeatProgCgroupSocketOpt,
			Attach:  KFeatAttachCGroupGetSetSocket,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 4},
		features: KernelFeatures{
			Map: KFeatMapNetdevHash,
			API: KFeatAPIBTFGetNextID,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 5},
		features: KernelFeatures{
			API:     KFeatAPIMapMMap,
			Program: KFeatProgTracing,
			Attach:  KFeatAttachTraceRawTP | KFeatAttachTraceFentry | KFeatAttachTraceFExit,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 6},
		features: KernelFeatures{
			Map:     KFeatMapStructOps,
			API:     KFeatAPIMapLookupBatch | KFeatAPIMapUpdateBatch | KFeatAPIMapDeleteBatch | KFeatAPIMapLookupAndDeleteBatch,
			Program: KFeatProgStructOps | KFeatProgExt,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 7},
		features: KernelFeatures{
			Arch:    KFeatArchRiscVRV32G,
			Program: KFeatProgLSM,
			Attach:  KFeatAttachModifyReturn | KFeatAttachLSMMAC,
			API:     KFeatAPILinkCreate | KFeatAPILinkUpdate,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 8},
		features: KernelFeatures{
			Map: KFeatMapRingBuffer,
			Attach: KFeatAttachTraceIter | KFeatAttachCGroupINetGetPeerName |
				KFeatAttachCGroupINetGetSocketName | KFeatAttachXDPDevMap,
			API: KFeatAPILinkGetFDByID | KFeatAPILinkGetNextID | KFeatAPIEnableStats | KFeatAPIIterCreate,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 9},
		features: KernelFeatures{
			Program: KFeatProgSKLookup,
			Attach: KFeatAttachCGroupInetSocketRelease | KFeatAttachXDPCPUMap |
				KFeatAttachSKLookup | KFeatAttachXDP,
			API: KFeatAPILinkDetach,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 10},
		features: KernelFeatures{
			Map: KFeatMapINodeStorage,
			API: KFeatAPIProgBindMap,
		},
	},
	{
		version: kernelVersion{major: 5, minor: 11},
		features: KernelFeatures{
			Map: KFeatMapTaskStorage,
		},
	},
}
