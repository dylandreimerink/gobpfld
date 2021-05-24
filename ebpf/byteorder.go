package ebpf

import (
	"encoding/binary"
	"unsafe"
)

// multi-byte constants in eBPF programs must always be in network order. Since constants in golang are represented in
// the byte order of the host this may cause issues. The functions in this file automatically detect the endianness
// of the host at runtime and converts them to or from network byte order.

var nativeEndian binary.ByteOrder

func getNativeEndianness() binary.ByteOrder {
	if nativeEndian != nil {
		return nativeEndian
	}

	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}

	return nativeEndian
}

// HtonU16 converts a uint16 from host-to-network byte order.
func HtonU16(i uint16) uint16 {
	b := make([]byte, 2)
	getNativeEndianness().PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

// Hton16 converts a int16 from host-to-network byte order.
func Hton16(u int16) int16 {
	return int16(HtonU16(uint16(u)))
}

// HtonU32 converts a uint32 from host-to-network byte order.
func HtonU32(i uint32) uint32 {
	b := make([]byte, 4)
	getNativeEndianness().PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}

// Hton32 converts a int32 from host-to-network byte order.
func Hton32(u int32) int32 {
	return int32(HtonU32(uint32(u)))
}

// HtonU64 converts a uint64 from host-to-network byte order.
func HtonU64(i uint64) uint64 {
	b := make([]byte, 8)
	getNativeEndianness().PutUint64(b, i)
	return binary.BigEndian.Uint64(b)
}

// Hton64 converts a int64 from host-to-network byte order.
func Hton64(u int64) int64 {
	return int64(HtonU64(uint64(u)))
}

// NtohU16 converts a uint16 from network-to-host byte order.
func NtohU16(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return getNativeEndianness().Uint16(b)
}

// Ntoh16 converts a int16 from host-to-network byte order.
func Ntoh16(u int16) int16 {
	return int16(NtohU16(uint16(u)))
}

// NtohU32 converts a uint32 from network-to-host byte order.
func NtohU32(i uint32) uint32 {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return getNativeEndianness().Uint32(b)
}

// Ntoh32 converts a int32 from host-to-network byte order.
func Ntoh32(u int32) int32 {
	return int32(NtohU32(uint32(u)))
}

// NtohU64 converts a uint64 from network-to-host byte order.
func NtohU64(i uint64) uint64 {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, i)
	return getNativeEndianness().Uint64(b)
}

// Ntoh64 converts a int64 from host-to-network byte order.
func Ntoh64(u int64) int64 {
	return int64(NtohU64(uint64(u)))
}
