package ebpf

import (
	"fmt"
	"unsafe"
)

// Instruction is any struct that can be turned into a list of raw instruction.
// It returns a list since the LD IMM 64bit consists of 2 actual eBPF "instructions"
type Instruction interface {
	fmt.Stringer
	Raw() ([]RawInstruction, error)
}

// Nop does not exist in the eBPF definition, it is a filler instruction this package
// adds to decoded programs so the index numbers of the slice stay the same as
// the index numbers of the raw instructions, even when the LoadConstant64bit op is used.
// This is to avoid confusion when looking at jump commands or calculating offsets for
// FD relocation.
type Nop struct{}

func (n *Nop) String() string {
	return "nop"
}

func (n *Nop) Raw() ([]RawInstruction, error) {
	return nil, nil
}

const (
	// The size of a BPF VM instruction
	BPFInstSize = int(unsafe.Sizeof(RawInstruction{}))
)

// A RawInstruction is a BPF virtual machine instruction.
type RawInstruction struct {
	// Operation to execute.
	Op uint8
	// The operation register, split into source and destination register
	// The upper 4 bits are the destination register, the lower 4 bits the source
	Reg uint8
	//
	Off int16
	// Constant parameter. The meaning depends on the Op.
	Imm int32
}

func (i *RawInstruction) SetDestReg(v Register) {
	i.Reg = (i.Reg & 0xF0) | (uint8(v) & 0x0F)
}

func (i *RawInstruction) GetDestReg() Register {
	return Register(i.Reg & 0x0F)
}

func (i *RawInstruction) SetSourceReg(v Register) {
	i.Reg = (i.Reg & 0x0F) | (uint8(v) << 4 & 0xF0)
}

func (i *RawInstruction) GetSourceReg() Register {
	return Register((i.Reg & 0xF0) >> 4)
}

func NewReg(src Register, dest Register) uint8 {
	return (uint8(src) << 4 & 0xF0) | (uint8(dest) & 0x0F)
}

// MustEncode does the same as Encode but rather than returning an error it will panic
func MustEncode(raw []Instruction) []RawInstruction {
	inst, err := Encode(raw)
	if err != nil {
		panic(err)
	}

	return inst
}

// Encode turns a slice of instructions into raw instructions
func Encode(ins []Instruction) ([]RawInstruction, error) {
	// The output will be at least as big as the input
	instructions := make([]RawInstruction, 0, len(ins))
	for _, instruction := range ins {
		rawInstructions, err := instruction.Raw()
		if err != nil {
			return nil, err
		}

		instructions = append(instructions, rawInstructions...)
	}

	return instructions, nil
}

type Size uint8

const (
	// Word - 4 bytes
	BPF_W Size = 0x00
	// Half-Word - 2 bytes
	BPF_H Size = 0x08
	// Byte - 1 byte
	BPF_B Size = 0x10
	// Double-Word - 8 bytes
	BPF_DW Size = 0x18
)

func (s Size) String() string {
	switch s {
	case BPF_W:
		return "u32"
	case BPF_H:
		return "u16"
	case BPF_B:
		return "u8"
	case BPF_DW:
		return "u64"
	}

	return "invalid"
}

type Register uint8

const (
	BPF_REG_0 Register = iota
	BPF_REG_1
	BPF_REG_2
	BPF_REG_3
	BPF_REG_4
	BPF_REG_5
	BPF_REG_6
	BPF_REG_7
	BPF_REG_8
	BPF_REG_9
	BPF_REG_10
	BPF_REG_MAX
)

func (r Register) String() string {
	if r < BPF_REG_MAX {
		return fmt.Sprintf("r%d", r)
	}

	return "invalid"
}

const (
	BPF_IMM    uint8 = 0x00
	BPF_ABS    uint8 = 0x20
	BPF_IND    uint8 = 0x40
	BPF_MEM    uint8 = 0x60
	BPF_LEN    uint8 = 0x80
	BPF_MSH    uint8 = 0xa0
	BPF_ATOMIC uint8 = 0xc0
)

const (
	BPF_LD uint8 = iota
	BPF_LDX
	BPF_ST
	BPF_STX
	BPF_ALU
	BPF_JMP
	BPF_JMP32
	BPF_ALU64
)

const (
	BPF_K uint8 = 0x00
	BPF_X uint8 = 0x08
)

const (
	BPF_ADD  uint8 = 0x00
	BPF_SUB  uint8 = 0x10
	BPF_MUL  uint8 = 0x20
	BPF_DIV  uint8 = 0x30
	BPF_OR   uint8 = 0x40
	BPF_AND  uint8 = 0x50
	BPF_LSH  uint8 = 0x60
	BPF_RSH  uint8 = 0x70
	BPF_NEG  uint8 = 0x80
	BPF_MOD  uint8 = 0x90
	BPF_XOR  uint8 = 0xa0
	BPF_MOV  uint8 = 0xb0
	BPF_ARSH uint8 = 0xc0
	BPF_END  uint8 = 0xd0
)

const (
	BPF_JA   uint8 = 0x00
	BPF_JEQ  uint8 = 0x10
	BPF_JGT  uint8 = 0x20
	BPF_JGE  uint8 = 0x30
	BPF_JSET uint8 = 0x40
	BPF_JNE  uint8 = 0x50
	BPF_JSGT uint8 = 0x60
	BPF_JSGE uint8 = 0x70
	BPF_CALL uint8 = 0x80
	BPF_EXIT uint8 = 0x90
	BPF_JLT  uint8 = 0xa0
	BPF_JLE  uint8 = 0xb0
	BPF_JSLT uint8 = 0xc0
	BPF_JSLE uint8 = 0xd0
)

const (
	BPF_FETCH   uint8 = 0x01               /* not an opcode on its own, used to build others */
	BPF_XCHG    uint8 = (0xe0 | BPF_FETCH) /* atomic exchange */
	BPF_CMPXCHG uint8 = (0xf0 | BPF_FETCH) /* atomic compare-and-write */
)

const (
	BPF_TO_LE uint8 = 0x00 /* convert to little-endian */
	BPF_TO_BE uint8 = 0x08 /* convert to big-endian */
)

const (
	XDP_ABORTED  = 0
	XDP_DROP     = 1
	XDP_PASS     = 2
	XDP_TX       = 3
	XDP_REDIRECT = 4
)
