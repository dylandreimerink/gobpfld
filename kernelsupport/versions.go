package kernelsupport

type kernelFeatureVersion struct {
	version  KernelVersion
	features KernelFeatures
}

// a list of eBPF kernel features which are available from a given kernel version forward.
// largely based on https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
var featureMinVersion = []kernelFeatureVersion{
	{
		version: KernelVersion{Major: 3, Minor: 16},
		features: KernelFeatures{
			Arch: KFeatArchx86_64,
		},
	},
	{
		version: KernelVersion{Major: 3, Minor: 18},
		features: KernelFeatures{
			Arch: KFeatArchARM64,
			API:  KFeatAPIBasic,
		},
	},
	{
		version: KernelVersion{Major: 3, Minor: 19},
		features: KernelFeatures{
			Map:     KFeatMapHash | KFeatMapArray,
			Program: KFeatProgSocketFilter,
			Attach:  KFeatAttachINetIngressEgress,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 1},
		features: KernelFeatures{
			Arch:    KFeatArchs390,
			Program: KFeatProgKProbe | KFeatProgSchedCLS | KFeatProgSchedACT,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 2},
		features: KernelFeatures{
			Map: KFeatMapTailCall,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 3},
		features: KernelFeatures{
			Map: KFeatMapPerfEvent,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 4},
		features: KernelFeatures{
			API: KFeatAPIObjPinGet,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 6},
		features: KernelFeatures{
			Map: KFeatMapPerCPUHash | KFeatMapPerCPUArray | KFeatMapStackTrace,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 7},
		features: KernelFeatures{
			Program: KFeatProgTracepoint,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 8},
		features: KernelFeatures{
			Arch:    KFeatArchPP64,
			Map:     KFeatMapCGroupArray,
			Program: KFeatProgXDP,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 9},
		features: KernelFeatures{
			Program: KFeatProgPerfEvent,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 10},
		features: KernelFeatures{
			Map: KFeatMapLRUHash | KFeatMapLRUPerCPUHash,
			Program: KFeatProgCGroupSKB | KFeatProgCGroupSocket | KFeatProgLWTIn |
				KFeatProgLWTOut | KFeatProgLWTXmit,
			Attach: KFeatAttachInetSocketCreate,
			API:    KFeatAPIProgramAttachDetach,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 11},
		features: KernelFeatures{
			Map: KFeatMapLPMTrie,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 12},
		features: KernelFeatures{
			Arch: KFeatArchSparc64,
			Map:  KFeatMapArrayOfMaps | KFeatMapHashOfMaps,
			API:  KFeatAPIMapGetNextNull | KFeatAPIProgramTestRun,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 13},
		features: KernelFeatures{
			Arch:    KFeatArchMIPS,
			Program: KFeatProgSocketOps,
			Attach:  KFeatAttachSocketOps,
			API: KFeatAPIProgramGetNextID | KFeatAPIMapGetNextID |
				KFeatAPIProgramGetFDByID | KFeatAPIMapGetFDByID | KFeatAPIObjectGetInfoByFD,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 14},
		features: KernelFeatures{
			Arch:    KFeatArchARM32,
			Map:     KFeatMapNetdevArray | KFeatMapSocketArray,
			API:     KFeatAPIMapNumaCreate,
			Program: KFeatProgSKSKB,
			Attach:  KFeatAttachStreamParserVerdict,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 15},
		features: KernelFeatures{
			Map:     KFeatMapCPU,
			API:     KFeatAPIMapSyscallRW | KFeatAPIMapName | KFeatAPIProgramQuery,
			Program: KFeatProgCGroupDevice,
			Attach:  KFeatAttachCGroupDevice,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 16},
		features: KernelFeatures{
			Map: KFeatMapLPMTrieNextKey,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 17},
		features: KernelFeatures{
			Program: KFeatProgSKMsg | KFeatProgRawTracepoint | KFeatProgCGroupSocketAddr,
			Attach: KFeatAttachSKMsgVerdict | KFeatAttachCGroupInetBind |
				KFeatAttachCGroupInetConnect | KFeatAttachCGroupInetPostBind,
			API: KFeatAPIRawTracepointOpen,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 18},
		features: KernelFeatures{
			Arch:    KFeatArchx86,
			Map:     KFeatMapAFXDP | KFeatMapSocketHash,
			Program: KFeatProgLWTSeg6Local | KFeatProgLIRCMode2,
			Attach:  KFeatAttachCGroupUDPSendMsg | KFeatAttachLIRCMode2,
			API:     KFeatAPIBTFLoad | KFeatAPIBTFGetFDByID | KFeatAPITaskFDQuery,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 19},
		features: KernelFeatures{
			Map:     KFeatMapCGroupStorage | KFeatMapReuseportSocketArray,
			Program: KFeatProgSKReusePort,
		},
	},
	{
		version: KernelVersion{Major: 4, Minor: 20},
		features: KernelFeatures{
			Map:     KFeatMapPerCPUCGroupStorage | KFeatMapQueue | KFeatMapStack,
			API:     KFeatAPIMapLookupAndDelete,
			Program: KFeatProgFlowDissector,
			Attach:  KFeatAttachFlowDissector,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 0},
		features: KernelFeatures{
			API: KFeatAPIMapZeroSeed,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 1},
		features: KernelFeatures{
			Arch: KFeatArchRiscVRV64G,
			API:  KFeatAPIMapLock,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 2},
		features: KernelFeatures{
			Map:     KFeatMapSocketLocalStorage,
			API:     KFeatAPIMapBPFRW | KFeatAPIMapFreeze,
			Program: KFeatProgCGroupSysctl | KFeatProgRawTracepointWritable,
			Attach:  KFeatAttachCGroupSysctl | KFeatAttachCGroupUDPRecvMsg,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 3},
		features: KernelFeatures{
			Program: KFeatProgCgroupSocketOpt,
			Attach:  KFeatAttachCGroupGetSetSocket,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 4},
		features: KernelFeatures{
			Map:  KFeatMapNetdevHash,
			API:  KFeatAPIBTFGetNextID,
			Misc: KFeatMiscXSKRingFlags,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 5},
		features: KernelFeatures{
			API:     KFeatAPIMapMMap,
			Program: KFeatProgTracing,
			Attach:  KFeatAttachTraceRawTP | KFeatAttachTraceFentry | KFeatAttachTraceFExit,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 6},
		features: KernelFeatures{
			Map:     KFeatMapStructOps,
			API:     KFeatAPIMapBatchOps,
			Program: KFeatProgStructOps | KFeatProgExt,
			Misc:    KFeatBTFFuncScope,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 7},
		features: KernelFeatures{
			Arch:    KFeatArchRiscVRV32G,
			Program: KFeatProgLSM,
			Attach:  KFeatAttachModifyReturn | KFeatAttachLSMMAC,
			API:     KFeatAPILinkCreate | KFeatAPILinkUpdate,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 8},
		features: KernelFeatures{
			Map: KFeatMapRingBuffer,
			Attach: KFeatAttachTraceIter | KFeatAttachCGroupINetGetPeerName |
				KFeatAttachCGroupINetGetSocketName | KFeatAttachXDPDevMap,
			API: KFeatAPILinkGetFDByID | KFeatAPILinkGetNextID | KFeatAPIEnableStats | KFeatAPIIterCreate,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 9},
		features: KernelFeatures{
			Program: KFeatProgSKLookup,
			Attach: KFeatAttachCGroupInetSocketRelease | KFeatAttachXDPCPUMap |
				KFeatAttachSKLookup | KFeatAttachXDP,
			API: KFeatAPILinkDetach,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 10},
		features: KernelFeatures{
			Map: KFeatMapINodeStorage | KFeatMapDynamicInnerMap,
			API: KFeatAPIProgBindMap,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 11},
		features: KernelFeatures{
			Map: KFeatMapTaskStorage,
		},
	},
	{
		version: KernelVersion{Major: 5, Minor: 13},
		features: KernelFeatures{
			Map: KFeatMapPerCPUArrayBatchOps | KFeatMapLPMTrieBatchOps,
		},
	},
}
