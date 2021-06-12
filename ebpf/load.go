package ebpf

import "fmt"

const (
	// BPF_PSEUDO_MAP_FD is used in the SRC register to mark the imm value as a map file descriptor
	// https://elixir.bootlin.com/linux/v5.12.4/source/include/uapi/linux/bpf.h#L376
	BPF_PSEUDO_MAP_FD = 1
	// BPF_PSEUDO_MAP_FD_VALUE is used in the SRC register to mark the imm value as a map value
	// https://elixir.bootlin.com/linux/v5.12.4/source/include/uapi/linux/bpf.h#L385
	BPF_PSEUDO_MAP_FD_VALUE = 2
	// BPF_PSEUDO_BTF_ID is used in the SRC register to mark the imm value as BTF ID
	// https://elixir.bootlin.com/linux/v5.12.4/source/include/uapi/linux/bpf.h#L376
	BPF_PSEUDO_BTF_ID = 3
)

var _ Instruction = (*LoadConstant64bit)(nil)

type LoadConstant64bit struct {
	Dest Register
	Src  Register
	Val1 uint32
	Val2 uint32
}

func (lc *LoadConstant64bit) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{Op: BPF_LD | uint8(BPF_DW) | BPF_IMM, Reg: NewReg(lc.Src, lc.Dest), Imm: int32(lc.Val1)},
		{Op: 0, Reg: 0, Imm: int32(lc.Val2)},
	}, nil
}

func (lc *LoadConstant64bit) String() string {
	if lc.Src == BPF_PSEUDO_MAP_FD {
		return fmt.Sprintf("r%s = map fd#%d", lc.Dest, lc.Val1)
	}

	if lc.Src == BPF_PSEUDO_MAP_FD_VALUE {
		return fmt.Sprintf("r%s = map value#%d[%d]", lc.Dest, lc.Val1, lc.Val2)
	}

	return fmt.Sprintf("r%s = %d ll", lc.Dest, (uint64(lc.Val2)<<32)+uint64(lc.Val1))
}

var _ Instruction = (*LoadMemory)(nil)

type LoadMemory struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
}

func (lm *LoadMemory) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_LDX | uint8(lm.Size) | BPF_MEM,
			Reg: NewReg(lm.Src, lm.Dest),
			Off: lm.Offset,
		},
	}, nil
}

func (lm *LoadMemory) String() string {
	sign := "+"
	offset := lm.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}

	return fmt.Sprintf("r%s = *(%s *)(r%s %s %d)", lm.Dest, lm.Size, lm.Src, sign, offset)
}

var _ Instruction = (*LoadSocketBuf)(nil)

type LoadSocketBuf struct {
	Src    Register
	Size   Size
	Offset int32
}

func (lm *LoadSocketBuf) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_IND | uint8(lm.Size) | BPF_LD,
			Reg: NewReg(lm.Src, 0),
			Imm: lm.Offset,
		},
	}, nil
}

func (lm *LoadSocketBuf) String() string {
	sign := "+"
	off := lm.Offset
	if lm.Offset < 0 {
		sign = "-"
		off = -lm.Offset
	}

	return fmt.Sprintf("r0 = ntohl((%s) (((struct sk_buff *) r6)->data[r%s %s %d]))", lm.Size, lm.Src, sign, off)
}

var _ Instruction = (*LoadSocketBufConstant)(nil)

type LoadSocketBufConstant struct {
	Value int32
	Size  Size
}

func (lm *LoadSocketBufConstant) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_ABS | uint8(lm.Size) | BPF_LD,
			Imm: lm.Value,
		},
	}, nil
}

func (lm *LoadSocketBufConstant) String() string {
	return fmt.Sprintf("r0 = ntohl((%s) (((struct sk_buff *) r6)->data[%d]))", lm.Size, lm.Value)
}
