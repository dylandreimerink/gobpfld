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

// Jumper is any instruction that can jump to another piece of code using an 16-bit address
type Jumper interface {
	SetJumpTarget(relAddr int16)
}

// Valuer is any instruction for which a constant value can be set
type Valuer interface {
	SetValue(value int32)
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
	// BPFInstSize is the size of a BPF VM instruction
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
	// BPF_W Word - 4 bytes
	BPF_W Size = 0x00
	// BPF_H Half-Word - 2 bytes
	BPF_H Size = 0x08
	// BPF_B Byte - 1 byte
	BPF_B Size = 0x10
	// BPF_DW Double-Word - 8 bytes
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

// Register is a value used to indicate a source or destination register.
// Registers are used to pass arguments to variables and as scrach room for.
// See section 'BPF kernel internals' of https://www.kernel.org/doc/Documentation/networking/filter.rst
type Register uint8

const (
	// BPF_REG_0 aka R0 is the return value of the eBPF program, it is also used by helper functions and BPF to BPF
	// calls for return values.
	BPF_REG_0 Register = iota
	// BPF_REG_1 aka R1 is the first argument of a helper function or BPF to BPF call, it is set at the start of
	// a eBPF program to different values depending on the program type (typically a pointer to a struct).
	// After calling a helper function or BPF function one should assume the constents will be changed.
	BPF_REG_1
	// BPF_REG_2 aka R2 is the second argument of a helper function or BPF to BPF call, it can be set at the start
	// of the program depending on the program type but is typically not used.
	// After calling a helper function or BPF function one should assume the constents will be changed.
	BPF_REG_2
	// BPF_REG_3 aka R3 is the third argument of a helper function or BPF to BPF call, it can be set at the start
	// of the program depending on the program type but is typically not used.
	// After calling a helper function or BPF function one should assume the constents will be changed.
	BPF_REG_3
	// BPF_REG_4 aka R4 is the forth argument of a helper function or BPF to BPF call, it can be set at the start
	// of the program depending on the program type but is typically not used.
	// After calling a helper function or BPF function one should assume the constents will be changed.
	BPF_REG_4
	// BPF_REG_5 aka R5 is the fifth argument of a helper function or BPF to BPF call, it can be set at the start
	// of the program depending on the program type but is typically not used.
	// After calling a helper function or BPF function one should assume the constents will be changed.
	BPF_REG_5
	// BPF_REG_6 aka R6 is a callee saved register for helper functions, meaning the contents will not be changed
	// by the helper function.
	BPF_REG_6
	// BPF_REG_7 aka R7 is a callee saved register for helper functions, meaning the contents will not be changed
	// by the helper function.
	BPF_REG_7
	// BPF_REG_8 aka R8 is a callee saved register for helper functions, meaning the contents will not be changed
	// by the helper function.
	BPF_REG_8
	// BPF_REG_9 aka R9 is a callee saved register for helper functions, meaning the contents will not be changed
	// by the helper function.
	BPF_REG_9
	// BPF_REG_10 aka R10 is a read-only register containing the frame pointer. It is a pointer to the start of
	// the stack data reserved for this program. Each program/bpf to bpf function has its own stack.
	BPF_REG_10
	// BPF_REG_MAX is an invalid register, it is used for enumeration over registers.
	BPF_REG_MAX
)

// PSEUDO_CALL If the source register is 1, it is not a call to a helper function
// but to another bpf function(bpf to bpf call).
const PSEUDO_CALL Register = 0x01

func (r Register) String() string {
	if r < BPF_REG_MAX {
		return fmt.Sprintf("r%d", r)
	}

	return "invalid"
}

const (
	// BPF_IMM Load intermediate values into registers
	BPF_IMM uint8 = 0x00
	// BPF_ABS Load values at intermediate offsets from the socketbuffer into memory
	BPF_ABS uint8 = 0x20
	// BPF_IND Load values at variable offsets from the socketbuffer into memory
	BPF_IND uint8 = 0x40
	// BPF_MEM Load values from memory into registers visa versa.
	BPF_MEM uint8 = 0x60
	// BPF_LEN not used in eBPF, reserved
	BPF_LEN uint8 = 0x80
	// BPF_MSH not used in eBPF, reserved
	BPF_MSH uint8 = 0xa0
	// BPF_ATOMIC atomic operators (for multi processor synchronization)
	BPF_ATOMIC uint8 = 0xc0
)

const (
	// BPF_LD is used for specialized load operations
	BPF_LD uint8 = iota
	// BPF_LDX is used for generic load operations
	BPF_LDX
	// BPF_ST is used for specialized store operations
	BPF_ST
	// BPF_STX is used for generic store operations
	BPF_STX
	// BPF_ALU is used for 32bit arithmatic operations
	BPF_ALU
	// BPF_JMP is used for 64bit branching operations
	BPF_JMP
	// BPF_JMP32 is used for 32bit branching operations
	BPF_JMP32
	// BPF_ALU64 is used for 64bit arithmatic operations
	BPF_ALU64
)

const (
	// BPF_K indicates that the source argument of an operation is an immediate value
	BPF_K uint8 = 0x00
	// BPF_X indicates that the source argument of an operation is a register
	BPF_X uint8 = 0x08
)

const (
	// BPF_ADD add two numbers
	BPF_ADD uint8 = 0x00
	// BPF_SUB subtract two numbers
	BPF_SUB uint8 = 0x10
	// BPF_MUL multiply two numbers
	BPF_MUL uint8 = 0x20
	// BPF_DIV divide two numbers
	BPF_DIV uint8 = 0x30
	// BPF_OR binary or two numbers
	BPF_OR uint8 = 0x40
	// BPF_AND binary and two numbers
	BPF_AND uint8 = 0x50
	// BPF_LSH left shift a number
	BPF_LSH uint8 = 0x60
	// BPF_RSH right shift a number
	BPF_RSH uint8 = 0x70
	// BPF_NEG negate/invert a number
	BPF_NEG uint8 = 0x80
	// BPF_MOD get the modulo of two numbers
	BPF_MOD uint8 = 0x90
	// BPF_XOR binary XOR two numbers
	BPF_XOR uint8 = 0xa0
	// BPF_MOV move register into another register
	BPF_MOV uint8 = 0xb0
	// BPF_ARSH Signed shift right
	BPF_ARSH uint8 = 0xc0
	// BPF_END endianness conversion
	BPF_END uint8 = 0xd0
)

const (
	// BPF_JA jump always
	BPF_JA uint8 = 0x00
	// BPF_JEQ jump equal
	BPF_JEQ uint8 = 0x10
	// BPF_JGT jump greater than
	BPF_JGT uint8 = 0x20
	// BPF_JGE jump greater than or equal
	BPF_JGE uint8 = 0x30
	// BPF_JSET jump if A & B == 0
	BPF_JSET uint8 = 0x40
	// BPF_JNE jump not equal
	BPF_JNE uint8 = 0x50
	// BPF_JSGT jump signed greater than
	BPF_JSGT uint8 = 0x60
	// BPF_JSGE jump signed greater than or equal
	BPF_JSGE uint8 = 0x70
	// BPF_CALL call a helper function or BPF to BPF call
	BPF_CALL uint8 = 0x80
	// BPF_EXIT exit the program
	BPF_EXIT uint8 = 0x90
	// BPF_JLT jump less than
	BPF_JLT uint8 = 0xa0
	// BPF_JLE jump less than equal
	BPF_JLE uint8 = 0xb0
	// BPF_JSLT jump signed less than
	BPF_JSLT uint8 = 0xc0
	// BPF_JSLE jump signed less then equal
	BPF_JSLE uint8 = 0xd0
)

const (
	// BPF_FETCH not an opcode on its own, used to build others
	BPF_FETCH uint8 = 0x01
	// BPF_XCHG atomic exchange
	BPF_XCHG uint8 = (0xe0 | BPF_FETCH)
	// BPF_CMPXCHG atomic compare-and-write
	BPF_CMPXCHG uint8 = (0xf0 | BPF_FETCH)
)

const (
	// BPF_TO_LE convert to little-endian
	BPF_TO_LE uint8 = 0x00
	// BPF_TO_BE convert to big-endian
	BPF_TO_BE uint8 = 0x08
)

const (
	// XDP_ABORTED exit program with an error
	XDP_ABORTED = 0
	// XDP_DROP drop the packet
	XDP_DROP = 1
	// XDP_PASS send packet to OS
	XDP_PASS = 2
	// XDP_TX send packet to egress on same port
	XDP_TX = 3
	// XDP_REDIRECT redirect to a different port, CPU or userspace
	XDP_REDIRECT = 4
)

// TODO add other return consts like for TC
