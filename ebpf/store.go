package ebpf

import "fmt"

var _ Instruction = (*StoreMemoryConstant)(nil)

type StoreMemoryConstant struct {
	Dest   Register
	Size   Size
	Offset int16
	Value  int32
}

func (sm *StoreMemoryConstant) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_ST | uint8(sm.Size) | BPF_MEM,
			Reg: NewReg(0, sm.Dest),
			Off: sm.Offset,
			Imm: sm.Value,
		},
	}, nil
}

func (sm *StoreMemoryConstant) String() string {
	sign := "+"
	offset := sm.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	return fmt.Sprintf("*(%s *)(r%s %s %d) = %d", sm.Size, sm.Dest, sign, offset, sm.Value)
}

var _ Instruction = (*StoreMemoryRegister)(nil)

type StoreMemoryRegister struct {
	Src    Register
	Dest   Register
	Offset int16
	Size   Size
}

func (sm *StoreMemoryRegister) Raw() ([]RawInstruction, error) {
	return []RawInstruction{
		{
			Op:  BPF_STX | uint8(sm.Size) | BPF_MEM,
			Reg: NewReg(sm.Src, sm.Dest),
			Off: sm.Offset,
		},
	}, nil
}

func (sm *StoreMemoryRegister) String() string {
	sign := "+"
	offset := sm.Offset
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	return fmt.Sprintf("*(%s *)(r%s %s %d) = r%s", sm.Size, sm.Dest, sign, offset, sm.Src)
}
