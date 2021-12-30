package integration

import "embed"

// ebpf contains all files in the ebpf sub-dir
//go:embed ebpf
var ebpf embed.FS
