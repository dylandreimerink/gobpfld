package ebpf

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer/stateful"
)

var (
	ebpfLexer = stateful.MustSimple([]stateful.Rule{
		{Name: "Comment", Pattern: `(?:#)[^\n]*`, Action: nil},
		{Name: "Register32", Pattern: `w[0-9]{1,2}`, Action: nil},
		{Name: "Register64", Pattern: `r[0-9]{1,2}`, Action: nil},
		{Name: "Number", Pattern: `(0x|0b)?\d+`, Action: nil},
		{Name: "Nop", Pattern: `nop`, Action: nil},
		{Name: "Ident", Pattern: `[a-zA-Z0-9_]+`, Action: nil},
		{Name: "LabelEnd", Pattern: `:`, Action: nil},
		{Name: "Punct", Pattern: `[-[!@#$%^&*()+_={}\\\|;'"<,>.?/]|]`, Action: nil},
		{Name: "Whitespace", Pattern: `[ \t\r]+`, Action: nil},
		{Name: "Newline", Pattern: `\n`, Action: nil},
	})
	ebpfParser = participle.MustBuild(&asmFile{},
		participle.Lexer(ebpfLexer),
		participle.Elide("Comment", "Whitespace", "Nop"),
		participle.UseLookahead(100),
	)
)

// TODO make a AssemblyToProgram function, since we can technically reconstruct the whole ELF(Program, Maps, license)
// from the assembly

// AssemblyToInstructions takes in a reader and the name of the file which is used in error messages. This function
// attempts to parse the contents of the file as a super set of clang/LLVM eBPF assembly code. Meaning that
// we support the output of clang with the -S option and some additional features since clang/LLVM doesn't
// generate or assemble all instructions in the eBPF specification.
func AssemblyToInstructions(filename string, reader io.Reader) ([]Instruction, error) {
	ast := &asmFile{}
	err := ebpfParser.Parse(filename, reader, ast)
	if err != nil {
		return nil, fmt.Errorf("error while parsing: %w", err)
	}

	var instructions []Instruction

	ctx := assembleContext{
		Labels: make(map[string]int),
		Maps:   make(map[string]struct{}),
	}

	instCnt := 0
	for _, entry := range ast.Entries {
		if entry.Label != "" {
			if _, found := ctx.Labels[entry.Label]; found {
				return nil, fmt.Errorf("duplicate label '%s' found, labels must be unique", entry.Label)
			}

			ctx.Labels[entry.Label] = instCnt
			continue
		}

		if entry.Instruction != nil {
			// Since the LoadConstant64bit is the only instruction to produce 2 instructions, we have to account for
			// that when counting
			if entry.Instruction.LoadConstant64bit != nil {
				instCnt++
			}

			instCnt++
			continue
		}

		if entry.Directive != nil {
			if typ := entry.Directive.Type; typ != nil {
				// object type declarations are maps(as far as I can tell, we may need to check size,
				// and section as well in future)
				if typ.Type == "object" {
					if _, found := ctx.Maps[typ.Name]; found {
						return nil, fmt.Errorf("duplicate map definition '%s'", typ.Name)
					}

					ctx.Maps[typ.Name] = struct{}{}
				}
			}

			continue
		}
	}

	instCnt = 0
	for _, entry := range ast.Entries {
		if entry.Instruction != nil {
			insts, err := entry.Instruction.ToInst(instCnt, &ctx)
			if err != nil {
				return nil, err
			}

			instructions = append(instructions, insts...)
			instCnt++

			// Since the LoadConstant64bit is the only instruction to produce 2 instructions, we have to account for
			// that when counting
			if entry.Instruction.LoadConstant64bit != nil {
				instCnt++
			}
		}
	}

	return instructions, nil
}

type assembleContext struct {
	Labels map[string]int
	Maps   map[string]struct{} // TODO add actual parsed map definition in the future?
}

type asmFile struct {
	Entries []*entry `parser:"@@*"`
}

type entry struct {
	Label       string       `parser:"( @(Ident|Number|Punct)+ LabelEnd"`
	Directive   *directive   `parser:"| @@"`
	Instruction *instruction `parser:"| @@ )? Newline*"`
}

func (r *Register) Capture(values []string) error {
	// Join all values, and strip the leading r
	i, err := strconv.Atoi(strings.Join(values, "")[1:])
	if err != nil {
		return err
	}

	*r = Register(i)

	return nil
}

func (s *Size) Capture(values []string) error {
	switch strings.Join(values, "") {
	case "u8", "w8":
		*s = BPF_B
	case "u16", "w16":
		*s = BPF_H
	case "u32", "w32":
		*s = BPF_W
	case "u64", "w64":
		*s = BPF_DW
	default:
		return fmt.Errorf("'%s' is not a valid variable Size", strings.Join(values, ""))
	}

	return nil
}

type directive struct {
	Type    *typeDirective    `parser:"  @@"`
	Generic *genericDirective `parser:"| @@"`
}

// https://sourceware.org/binutils/docs/as/Type.html
type typeDirective struct {
	Name string `parser:"'.' 'type' @Ident"`
	Type string `parser:"','? ('@'|'%')? @Ident"`
}

type genericDirective struct {
	Name  string `parser:"'.' @Ident"`
	Value string `parser:"(@Ident | @Number | @Punct)*"`
}

type instruction struct {
	ARSH32                                 *arsh32                                 `parser:"  @@"`
	ARSH32Register                         *arsh32Register                         `parser:"| @@"`
	ARSH64                                 *arsh64                                 `parser:"| @@"`
	ARSH64Register                         *arsh64Register                         `parser:"| @@"`
	Add32                                  *add32                                  `parser:"| @@"`
	Add32Register                          *add32Register                          `parser:"| @@"`
	Add64                                  *add64                                  `parser:"| @@"`
	Add64Register                          *add64Register                          `parser:"| @@"`
	And32                                  *and32                                  `parser:"| @@"`
	And32Register                          *and32Register                          `parser:"| @@"`
	And64                                  *and64                                  `parser:"| @@"`
	And64Register                          *and64Register                          `parser:"| @@"`
	AtomicAdd32                            *atomicAdd32                            `parser:"| @@"`
	AtomicAdd64                            *atomicAdd64                            `parser:"| @@"`
	AtomicSub32                            *atomicSub32                            `parser:"| @@"`
	AtomicSub64                            *atomicSub64                            `parser:"| @@"`
	AtomicAnd32                            *atomicAnd32                            `parser:"| @@"`
	AtomicAnd64                            *atomicAnd64                            `parser:"| @@"`
	AtomicCompareAndExchange32             *atomicCompareAndExchange32             `parser:"| @@"`
	AtomicCompareAndExchange64             *atomicCompareAndExchange64             `parser:"| @@"`
	AtomicExchange32                       *atomicExchange32                       `parser:"| @@"`
	AtomicExchange64                       *atomicExchange64                       `parser:"| @@"`
	AtomicOr32                             *atomicOr32                             `parser:"| @@"`
	AtomicOr64                             *atomicOr64                             `parser:"| @@"`
	AtomicXor32                            *atomicXor32                            `parser:"| @@"`
	AtomicXor64                            *atomicXor64                            `parser:"| @@"`
	Call                                   *call                                   `parser:"| @@"`
	Div32                                  *div32                                  `parser:"| @@"`
	Div32Register                          *div32Register                          `parser:"| @@"`
	Div64                                  *div64                                  `parser:"| @@"`
	Div64Register                          *div64Register                          `parser:"| @@"`
	End16ToBE                              *end16ToBE                              `parser:"| @@"`
	End16ToLE                              *end16ToLE                              `parser:"| @@"`
	End32ToBE                              *end32ToBE                              `parser:"| @@"`
	End32ToLE                              *end32ToLE                              `parser:"| @@"`
	End64ToBE                              *end64ToBE                              `parser:"| @@"`
	End64ToLE                              *end64ToLE                              `parser:"| @@"`
	Exit                                   *exit                                   `parser:"| @@"`
	Jump                                   *jump                                   `parser:"| @@"`
	JumpEqual                              *jumpEqual                              `parser:"| @@"`
	JumpEqual32                            *jumpEqual32                            `parser:"| @@"`
	JumpEqualRegister                      *jumpEqualRegister                      `parser:"| @@"`
	JumpEqualRegister32                    *jumpEqualRegister32                    `parser:"| @@"`
	JumpGreaterThan                        *jumpGreaterThan                        `parser:"| @@"`
	JumpGreaterThan32                      *jumpGreaterThan32                      `parser:"| @@"`
	JumpGreaterThanRegister                *jumpGreaterThanRegister                `parser:"| @@"`
	JumpGreaterThanRegister32              *jumpGreaterThanRegister32              `parser:"| @@"`
	JumpGreaterThanEqual                   *jumpGreaterThanEqual                   `parser:"| @@"`
	JumpGreaterThanEqual32                 *jumpGreaterThanEqual32                 `parser:"| @@"`
	JumpGreaterThanEqualRegister           *jumpGreaterThanEqualRegister           `parser:"| @@"`
	JumpGreaterThanEqualRegister32         *jumpGreaterThanEqualRegister32         `parser:"| @@"`
	JumpIfAnd                              *jumpIfAnd                              `parser:"| @@"`
	JumpIfAnd32                            *jumpIfAnd32                            `parser:"| @@"`
	JumpIfAndRegister                      *jumpIfAndRegister                      `parser:"| @@"`
	JumpIfAndRegister32                    *jumpIfAndRegister32                    `parser:"| @@"`
	JumpIfNotEqual                         *jumpIfNotEqual                         `parser:"| @@"`
	JumpIfNotEqual32                       *jumpIfNotEqual32                       `parser:"| @@"`
	JumpIfNotEqualRegister                 *jumpIfNotEqualRegister                 `parser:"| @@"`
	JumpIfNotEqualRegister32               *jumpIfNotEqualRegister32               `parser:"| @@"`
	JumpSignedGreaterThan                  *jumpSignedGreaterThan                  `parser:"| @@"`
	JumpSignedGreaterThan32                *jumpSignedGreaterThan32                `parser:"| @@"`
	JumpSignedGreaterThanRegister          *jumpSignedGreaterThanRegister          `parser:"| @@"`
	JumpSignedGreaterThanRegister32        *jumpSignedGreaterThanRegister32        `parser:"| @@"`
	JumpSignedGreaterThanOrEqual           *jumpSignedGreaterThanOrEqual           `parser:"| @@"`
	JumpSignedGreaterThanOrEqual32         *jumpSignedGreaterThanOrEqual32         `parser:"| @@"`
	JumpSignedGreaterThanOrEqualRegister   *jumpSignedGreaterThanOrEqualRegister   `parser:"| @@"`
	JumpSignedGreaterThanOrEqualRegister32 *jumpSignedGreaterThanOrEqualRegister32 `parser:"| @@"`
	JumpSignedSmallerThan                  *jumpSignedSmallerThan                  `parser:"| @@"`
	JumpSignedSmallerThan32                *jumpSignedSmallerThan32                `parser:"| @@"`
	JumpSignedSmallerThanRegister          *jumpSignedSmallerThanRegister          `parser:"| @@"`
	JumpSignedSmallerThanRegister32        *jumpSignedSmallerThanRegister32        `parser:"| @@"`
	JumpSignedSmallerThanOrEqual           *jumpSignedSmallerThanOrEqual           `parser:"| @@"`
	JumpSignedSmallerThanOrEqual32         *jumpSignedSmallerThanOrEqual32         `parser:"| @@"`
	JumpSignedSmallerThanOrEqualRegister   *jumpSignedSmallerThanOrEqualRegister   `parser:"| @@"`
	JumpSignedSmallerThanOrEqualRegister32 *jumpSignedSmallerThanOrEqualRegister32 `parser:"| @@"`
	JumpSmallerThan                        *jumpSmallerThan                        `parser:"| @@"`
	JumpSmallerThan32                      *jumpSmallerThan32                      `parser:"| @@"`
	JumpSmallerThanRegister                *jumpSmallerThanRegister                `parser:"| @@"`
	JumpSmallerThanRegister32              *jumpSmallerThanRegister32              `parser:"| @@"`
	JumpSmallerThanEqual                   *jumpSmallerThanEqual                   `parser:"| @@"`
	JumpSmallerThanEqual32                 *jumpSmallerThanEqual32                 `parser:"| @@"`
	JumpSmallerThanEqualRegister           *jumpSmallerThanEqualRegister           `parser:"| @@"`
	JumpSmallerThanEqualRegister32         *jumpSmallerThanEqualRegister32         `parser:"| @@"`
	LoadConstant64bit                      *loadConstant64bit                      `parser:"| @@"`
	LoadMemory                             *loadMemory                             `parser:"| @@"`
	LoadSocketBuf                          *loadSocketBuf                          `parser:"| @@"`
	LoadSocketBufConstant                  *loadSocketBufConstant                  `parser:"| @@"`
	Lsh32                                  *lsh32                                  `parser:"| @@"`
	Lsh32Register                          *lsh32Register                          `parser:"| @@"`
	Lsh64                                  *lsh64                                  `parser:"| @@"`
	Lsh64Register                          *lsh64Register                          `parser:"| @@"`
	Mod32                                  *mod32                                  `parser:"| @@"`
	Mod32Register                          *mod32Register                          `parser:"| @@"`
	Mod64                                  *mod64                                  `parser:"| @@"`
	Mod64Register                          *mod64Register                          `parser:"| @@"`
	Mov32                                  *mov32                                  `parser:"| @@"`
	Mov32Register                          *mov32Register                          `parser:"| @@"`
	Mov64                                  *mov64                                  `parser:"| @@"`
	Mov64Register                          *mov64Register                          `parser:"| @@"`
	Mul32                                  *mul32                                  `parser:"| @@"`
	Mul32Register                          *mul32Register                          `parser:"| @@"`
	Mul64                                  *mul64                                  `parser:"| @@"`
	Mul64Register                          *mul64Register                          `parser:"| @@"`
	Neg32                                  *neg32                                  `parser:"| @@"`
	Neg64                                  *neg64                                  `parser:"| @@"`
	Or32                                   *or32                                   `parser:"| @@"`
	Or32Register                           *or32Register                           `parser:"| @@"`
	Or64                                   *or64                                   `parser:"| @@"`
	Or64Register                           *or64Register                           `parser:"| @@"`
	Rsh32                                  *rsh32                                  `parser:"| @@"`
	Rsh32Register                          *rsh32Register                          `parser:"| @@"`
	Rsh64                                  *rsh64                                  `parser:"| @@"`
	Rsh64Register                          *rsh64Register                          `parser:"| @@"`
	StoreMemoryConstant                    *storeMemoryConstant                    `parser:"| @@"`
	StoreMemoryRegister                    *storeMemoryRegister                    `parser:"| @@"`
	Sub32                                  *sub32                                  `parser:"| @@"`
	Sub32Register                          *sub32Register                          `parser:"| @@"`
	Sub64                                  *sub64                                  `parser:"| @@"`
	Sub64Register                          *sub64Register                          `parser:"| @@"`
	Xor32                                  *xor32                                  `parser:"| @@"`
	Xor32Register                          *xor32Register                          `parser:"| @@"`
	Xor64                                  *xor64                                  `parser:"| @@"`
	Xor64Register                          *xor64Register                          `parser:"| @@"`
}

func (i *instruction) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	if i.ARSH32 != nil {
		return i.ARSH32.ToInst(index, ctx)
	}

	if i.ARSH32Register != nil {
		return i.ARSH32Register.ToInst(index, ctx)
	}

	if i.ARSH64 != nil {
		return i.ARSH64.ToInst(index, ctx)
	}

	if i.ARSH64Register != nil {
		return i.ARSH64Register.ToInst(index, ctx)
	}

	if i.Add32 != nil {
		return i.Add32.ToInst(index, ctx)
	}

	if i.Add32Register != nil {
		return i.Add32Register.ToInst(index, ctx)
	}

	if i.Add64 != nil {
		return i.Add64.ToInst(index, ctx)
	}

	if i.Add64Register != nil {
		return i.Add64Register.ToInst(index, ctx)
	}

	if i.And32 != nil {
		return i.And32.ToInst(index, ctx)
	}

	if i.And32Register != nil {
		return i.And32Register.ToInst(index, ctx)
	}

	if i.And64 != nil {
		return i.And64.ToInst(index, ctx)
	}

	if i.And64Register != nil {
		return i.And64Register.ToInst(index, ctx)
	}

	if i.AtomicAdd32 != nil {
		return i.AtomicAdd32.ToInst(index, ctx)
	}

	if i.AtomicAdd64 != nil {
		return i.AtomicAdd64.ToInst(index, ctx)
	}

	if i.AtomicSub32 != nil {
		return i.AtomicSub32.ToInst(index, ctx)
	}

	if i.AtomicSub64 != nil {
		return i.AtomicSub64.ToInst(index, ctx)
	}

	if i.AtomicAnd32 != nil {
		return i.AtomicAnd32.ToInst(index, ctx)
	}

	if i.AtomicAnd64 != nil {
		return i.AtomicAnd64.ToInst(index, ctx)
	}

	if i.AtomicCompareAndExchange32 != nil {
		return i.AtomicCompareAndExchange32.ToInst(index, ctx)
	}

	if i.AtomicCompareAndExchange64 != nil {
		return i.AtomicCompareAndExchange64.ToInst(index, ctx)
	}

	if i.AtomicExchange32 != nil {
		return i.AtomicExchange32.ToInst(index, ctx)
	}

	if i.AtomicExchange64 != nil {
		return i.AtomicExchange64.ToInst(index, ctx)
	}

	if i.AtomicOr32 != nil {
		return i.AtomicOr32.ToInst(index, ctx)
	}

	if i.AtomicOr64 != nil {
		return i.AtomicOr64.ToInst(index, ctx)
	}

	if i.AtomicXor32 != nil {
		return i.AtomicXor32.ToInst(index, ctx)
	}

	if i.AtomicXor64 != nil {
		return i.AtomicXor64.ToInst(index, ctx)
	}

	if i.Call != nil {
		return i.Call.ToInst(index, ctx)
	}

	if i.Div32 != nil {
		return i.Div32.ToInst(index, ctx)
	}

	if i.Div32Register != nil {
		return i.Div32Register.ToInst(index, ctx)
	}

	if i.Div64 != nil {
		return i.Div64.ToInst(index, ctx)
	}

	if i.Div64Register != nil {
		return i.Div64Register.ToInst(index, ctx)
	}

	if i.End16ToBE != nil {
		return i.End16ToBE.ToInst(index, ctx)
	}

	if i.End16ToLE != nil {
		return i.End16ToLE.ToInst(index, ctx)
	}

	if i.End32ToBE != nil {
		return i.End32ToBE.ToInst(index, ctx)
	}

	if i.End32ToLE != nil {
		return i.End32ToLE.ToInst(index, ctx)
	}

	if i.End64ToBE != nil {
		return i.End64ToBE.ToInst(index, ctx)
	}

	if i.End64ToLE != nil {
		return i.End64ToLE.ToInst(index, ctx)
	}

	if i.Exit != nil {
		return i.Exit.ToInst(index, ctx)
	}

	if i.Jump != nil {
		return i.Jump.ToInst(index, ctx)
	}

	if i.JumpEqual != nil {
		return i.JumpEqual.ToInst(index, ctx)
	}

	if i.JumpEqual32 != nil {
		return i.JumpEqual32.ToInst(index, ctx)
	}

	if i.JumpEqualRegister != nil {
		return i.JumpEqualRegister.ToInst(index, ctx)
	}

	if i.JumpEqualRegister32 != nil {
		return i.JumpEqualRegister32.ToInst(index, ctx)
	}

	if i.JumpGreaterThan != nil {
		return i.JumpGreaterThan.ToInst(index, ctx)
	}

	if i.JumpGreaterThan32 != nil {
		return i.JumpGreaterThan32.ToInst(index, ctx)
	}

	if i.JumpGreaterThanRegister != nil {
		return i.JumpGreaterThanRegister.ToInst(index, ctx)
	}

	if i.JumpGreaterThanRegister32 != nil {
		return i.JumpGreaterThanRegister32.ToInst(index, ctx)
	}

	if i.JumpGreaterThanEqual != nil {
		return i.JumpGreaterThanEqual.ToInst(index, ctx)
	}

	if i.JumpGreaterThanEqual32 != nil {
		return i.JumpGreaterThanEqual32.ToInst(index, ctx)
	}

	if i.JumpGreaterThanEqualRegister != nil {
		return i.JumpGreaterThanEqualRegister.ToInst(index, ctx)
	}

	if i.JumpGreaterThanEqualRegister32 != nil {
		return i.JumpGreaterThanEqualRegister32.ToInst(index, ctx)
	}

	if i.JumpIfAnd != nil {
		return i.JumpIfAnd.ToInst(index, ctx)
	}

	if i.JumpIfAnd32 != nil {
		return i.JumpIfAnd32.ToInst(index, ctx)
	}

	if i.JumpIfAndRegister != nil {
		return i.JumpIfAndRegister.ToInst(index, ctx)
	}

	if i.JumpIfAndRegister32 != nil {
		return i.JumpIfAndRegister32.ToInst(index, ctx)
	}

	if i.JumpIfNotEqual != nil {
		return i.JumpIfNotEqual.ToInst(index, ctx)
	}

	if i.JumpIfNotEqual32 != nil {
		return i.JumpIfNotEqual32.ToInst(index, ctx)
	}

	if i.JumpIfNotEqualRegister != nil {
		return i.JumpIfNotEqualRegister.ToInst(index, ctx)
	}

	if i.JumpIfNotEqualRegister32 != nil {
		return i.JumpIfNotEqualRegister32.ToInst(index, ctx)
	}

	if i.JumpSignedGreaterThan != nil {
		return i.JumpSignedGreaterThan.ToInst(index, ctx)
	}

	if i.JumpSignedGreaterThan32 != nil {
		return i.JumpSignedGreaterThan32.ToInst(index, ctx)
	}

	if i.JumpSignedGreaterThanRegister != nil {
		return i.JumpSignedGreaterThanRegister.ToInst(index, ctx)
	}

	if i.JumpSignedGreaterThanRegister32 != nil {
		return i.JumpSignedGreaterThanRegister32.ToInst(index, ctx)
	}

	if i.JumpSignedGreaterThanOrEqual != nil {
		return i.JumpSignedGreaterThanOrEqual.ToInst(index, ctx)
	}

	if i.JumpSignedGreaterThanOrEqual32 != nil {
		return i.JumpSignedGreaterThanOrEqual32.ToInst(index, ctx)
	}

	if i.JumpSignedGreaterThanOrEqualRegister != nil {
		return i.JumpSignedGreaterThanOrEqualRegister.ToInst(index, ctx)
	}

	if i.JumpSignedGreaterThanOrEqualRegister32 != nil {
		return i.JumpSignedGreaterThanOrEqualRegister32.ToInst(index, ctx)
	}

	if i.JumpSignedSmallerThan != nil {
		return i.JumpSignedSmallerThan.ToInst(index, ctx)
	}

	if i.JumpSignedSmallerThan32 != nil {
		return i.JumpSignedSmallerThan32.ToInst(index, ctx)
	}

	if i.JumpSignedSmallerThanRegister != nil {
		return i.JumpSignedSmallerThanRegister.ToInst(index, ctx)
	}

	if i.JumpSignedSmallerThanRegister32 != nil {
		return i.JumpSignedSmallerThanRegister32.ToInst(index, ctx)
	}

	if i.JumpSignedSmallerThanOrEqual != nil {
		return i.JumpSignedSmallerThanOrEqual.ToInst(index, ctx)
	}

	if i.JumpSignedSmallerThanOrEqual32 != nil {
		return i.JumpSignedSmallerThanOrEqual32.ToInst(index, ctx)
	}

	if i.JumpSignedSmallerThanOrEqualRegister != nil {
		return i.JumpSignedSmallerThanOrEqualRegister.ToInst(index, ctx)
	}

	if i.JumpSignedSmallerThanOrEqualRegister32 != nil {
		return i.JumpSignedSmallerThanOrEqualRegister32.ToInst(index, ctx)
	}

	if i.JumpSmallerThan != nil {
		return i.JumpSmallerThan.ToInst(index, ctx)
	}

	if i.JumpSmallerThan32 != nil {
		return i.JumpSmallerThan32.ToInst(index, ctx)
	}

	if i.JumpSmallerThanRegister != nil {
		return i.JumpSmallerThanRegister.ToInst(index, ctx)
	}

	if i.JumpSmallerThanRegister32 != nil {
		return i.JumpSmallerThanRegister32.ToInst(index, ctx)
	}

	if i.JumpSmallerThanEqual != nil {
		return i.JumpSmallerThanEqual.ToInst(index, ctx)
	}

	if i.JumpSmallerThanEqual32 != nil {
		return i.JumpSmallerThanEqual32.ToInst(index, ctx)
	}

	if i.JumpSmallerThanEqualRegister != nil {
		return i.JumpSmallerThanEqualRegister.ToInst(index, ctx)
	}

	if i.JumpSmallerThanEqualRegister32 != nil {
		return i.JumpSmallerThanEqualRegister32.ToInst(index, ctx)
	}

	if i.LoadConstant64bit != nil {
		return i.LoadConstant64bit.ToInst(index, ctx)
	}

	if i.LoadMemory != nil {
		return i.LoadMemory.ToInst(index, ctx)
	}

	if i.LoadSocketBuf != nil {
		return i.LoadSocketBuf.ToInst(index, ctx)
	}

	if i.LoadSocketBufConstant != nil {
		return i.LoadSocketBufConstant.ToInst(index, ctx)
	}

	if i.Lsh32 != nil {
		return i.Lsh32.ToInst(index, ctx)
	}

	if i.Lsh32Register != nil {
		return i.Lsh32Register.ToInst(index, ctx)
	}

	if i.Lsh64 != nil {
		return i.Lsh64.ToInst(index, ctx)
	}

	if i.Lsh64Register != nil {
		return i.Lsh64Register.ToInst(index, ctx)
	}

	if i.Mod32 != nil {
		return i.Mod32.ToInst(index, ctx)
	}

	if i.Mod32Register != nil {
		return i.Mod32Register.ToInst(index, ctx)
	}

	if i.Mod64 != nil {
		return i.Mod64.ToInst(index, ctx)
	}

	if i.Mod64Register != nil {
		return i.Mod64Register.ToInst(index, ctx)
	}

	if i.Mov32 != nil {
		return i.Mov32.ToInst(index, ctx)
	}

	if i.Mov32Register != nil {
		return i.Mov32Register.ToInst(index, ctx)
	}

	if i.Mov64 != nil {
		return i.Mov64.ToInst(index, ctx)
	}

	if i.Mov64Register != nil {
		return i.Mov64Register.ToInst(index, ctx)
	}

	if i.Mul32 != nil {
		return i.Mul32.ToInst(index, ctx)
	}

	if i.Mul32Register != nil {
		return i.Mul32Register.ToInst(index, ctx)
	}

	if i.Mul64 != nil {
		return i.Mul64.ToInst(index, ctx)
	}

	if i.Mul64Register != nil {
		return i.Mul64Register.ToInst(index, ctx)
	}

	if i.Neg32 != nil {
		return i.Neg32.ToInst(index, ctx)
	}

	if i.Neg64 != nil {
		return i.Neg64.ToInst(index, ctx)
	}

	if i.Or32 != nil {
		return i.Or32.ToInst(index, ctx)
	}

	if i.Or32Register != nil {
		return i.Or32Register.ToInst(index, ctx)
	}

	if i.Or64 != nil {
		return i.Or64.ToInst(index, ctx)
	}

	if i.Or64Register != nil {
		return i.Or64Register.ToInst(index, ctx)
	}

	if i.Rsh32 != nil {
		return i.Rsh32.ToInst(index, ctx)
	}

	if i.Rsh32Register != nil {
		return i.Rsh32Register.ToInst(index, ctx)
	}

	if i.Rsh64 != nil {
		return i.Rsh64.ToInst(index, ctx)
	}

	if i.Rsh64Register != nil {
		return i.Rsh64Register.ToInst(index, ctx)
	}

	if i.StoreMemoryConstant != nil {
		return i.StoreMemoryConstant.ToInst(index, ctx)
	}

	if i.StoreMemoryRegister != nil {
		return i.StoreMemoryRegister.ToInst(index, ctx)
	}

	if i.Sub32 != nil {
		return i.Sub32.ToInst(index, ctx)
	}

	if i.Sub32Register != nil {
		return i.Sub32Register.ToInst(index, ctx)
	}

	if i.Sub64 != nil {
		return i.Sub64.ToInst(index, ctx)
	}

	if i.Sub64Register != nil {
		return i.Sub64Register.ToInst(index, ctx)
	}

	if i.Xor32 != nil {
		return i.Xor32.ToInst(index, ctx)
	}

	if i.Xor32Register != nil {
		return i.Xor32Register.ToInst(index, ctx)
	}

	if i.Xor64 != nil {
		return i.Xor64.ToInst(index, ctx)
	}

	if i.Xor64Register != nil {
		return i.Xor64Register.ToInst(index, ctx)
	}

	return nil, nil
}

type arsh32 struct {
	Dst   Register `parser:"@Register32 's' '>' '>' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *arsh32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&ARSH32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type arsh32Register struct {
	Dst Register `parser:"@Register32 's' '>' '>' '='"`
	Src Register `parser:"@Register32"`
}

func (i *arsh32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{
		&ARSH32Register{
			Dest: i.Dst,
			Src:  i.Src,
		},
	}, nil
}

type arsh64 struct {
	Dst   Register `parser:"@Register64 's' '>' '>' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *arsh64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&ARSH64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type arsh64Register struct {
	Dst Register `parser:"@Register64 's' '>' '>' '='"`
	Src Register `parser:"@Register64"`
}

func (i *arsh64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&ARSH64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type add32 struct {
	Dst   Register `parser:"@Register32 '+' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *add32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Add32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type add32Register struct {
	Dst Register `parser:"@Register32 '+' '='"`
	Src Register `parser:"@Register32"`
}

func (i *add32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Add32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type add64 struct {
	Dst   Register `parser:"@Register64 '+' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *add64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Add64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type add64Register struct {
	Dst Register `parser:"@Register64 '+' '='"`
	Src Register `parser:"@Register64"`
}

func (i *add64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Add64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type and32 struct {
	Dst   Register `parser:"@Register32 '&' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *and32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&And32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type and32Register struct {
	Dst Register `parser:"@Register32 '&' '='"`
	Src Register `parser:"@Register32"`
}

func (i *and32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&And32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type and64 struct {
	Dst   Register `parser:"@Register64 '&' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *and64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&And64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type and64Register struct {
	Dst Register `parser:"@Register64 '&' '='"`
	Src Register `parser:"@Register64"`
}

func (i *and64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&And64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type atomicAdd32 struct {
	Dst    Register `parser:"'lock' '*' '(' 'u32' '*' ')' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ')' '+' '='"`
	Src    Register `parser:"@Register32"`
}

func (i *atomicAdd32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicAdd{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_W,
		Offset: int16(i.Offset),
		Fetch:  false, // TODO make a special instruction for the fetch flag?
	}}, nil
}

type atomicAdd64 struct {
	Dst    Register `parser:"'lock' '*' '(' 'u64' '*' ')' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ')' '+' '='"`
	Src    Register `parser:"@Register64"`
}

func (i *atomicAdd64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicAdd{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_DW,
		Offset: int16(i.Offset),
		Fetch:  false, // TODO make a special instruction for the fetch flag?
	}}, nil
}

type atomicSub32 struct {
	Dst    Register `parser:"'lock' '*' '(' 'u32' '*' ')' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ')' '-' '='"`
	Src    Register `parser:"@Register32"`
}

func (i *atomicSub32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicSub{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_W,
		Offset: int16(i.Offset),
		Fetch:  false, // TODO make a special instruction for the fetch flag?
	}}, nil
}

type atomicSub64 struct {
	Dst    Register `parser:"'lock' '*' '(' 'u64' '*' ')' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ')' '-' '='"`
	Src    Register `parser:"@Register64"`
}

func (i *atomicSub64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicSub{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_DW,
		Offset: int16(i.Offset),
		Fetch:  false, // TODO make a special instruction for the fetch flag?
	}}, nil
}

type atomicAnd32 struct {
	Dst    Register `parser:"'lock' '*' '(' 'u32' '*' ')' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ')' '&' '='"`
	Src    Register `parser:"@Register32"`
}

func (i *atomicAnd32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicAnd{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_W,
		Offset: int16(i.Offset),
		Fetch:  false, // TODO make a special instruction for the fetch flag?
	}}, nil
}

type atomicAnd64 struct {
	Dst    Register `parser:"'lock' '*' '(' 'u64' '*' ')' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ')' '&' '='"`
	Src    Register `parser:"@Register64"`
}

func (i *atomicAnd64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicAnd{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_DW,
		Offset: int16(i.Offset),
		Fetch:  false, // TODO make a special instruction for the fetch flag?
	}}, nil
}

// w0 = cmpxchg(r3 + 456, w0, w2)
type atomicCompareAndExchange32 struct {
	Dst    Register `parser:"'w0' '=' 'cmpxchg' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ',' 'w0' ','"`
	Src    Register `parser:"@Register32 ')'"`
}

func (i *atomicCompareAndExchange32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicCompareAndExchange{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_W,
		Offset: int16(i.Offset),
	}}, nil
}

// r0 = cmpxchg(r3 + 456, r0, r2)
type atomicCompareAndExchange64 struct {
	Dst    Register `parser:"'r0' '=' 'cmpxchg' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ',' 'r0' ','"`
	Src    Register `parser:"@Register64 ')'"`
}

func (i *atomicCompareAndExchange64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicCompareAndExchange{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_DW,
		Offset: int16(i.Offset),
	}}, nil
}

// w1 = xchg(r3 + 456, w1)
type atomicExchange32 struct {
	Src    Register `parser:"@Register32 '=' 'xchg' '('"`
	Dst    Register `parser:"@Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ',' Register32 ')'"`
}

func (i *atomicExchange32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicExchange{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_W,
		Offset: int16(i.Offset),
	}}, nil
}

// r1 = xchg(r3 + 456, r1)
type atomicExchange64 struct {
	Src    Register `parser:"@Register64 '=' 'xchg' '('"`
	Dst    Register `parser:"@Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ',' Register64 ')'"`
}

func (i *atomicExchange64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicExchange{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_DW,
		Offset: int16(i.Offset),
	}}, nil
}

type atomicOr32 struct {
	Dst    Register `parser:"'lock' '*' '(' 'u32' '*' ')' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ')' '|' '='"`
	Src    Register `parser:"@Register32"`
}

func (i *atomicOr32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicOr{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_W,
		Offset: int16(i.Offset),
		Fetch:  false, // TODO make a special instruction for the fetch flag?
	}}, nil
}

type atomicOr64 struct {
	Dst    Register `parser:"'lock' '*' '(' 'u64' '*' ')' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ')' '|' '='"`
	Src    Register `parser:"@Register64"`
}

func (i *atomicOr64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicOr{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_DW,
		Offset: int16(i.Offset),
		Fetch:  false, // TODO make a special instruction for the fetch flag?
	}}, nil
}

type atomicXor32 struct {
	Dst    Register `parser:"'lock' '*' '(' 'u32' '*' ')' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ')' '^' '='"`
	Src    Register `parser:"@Register32"`
}

func (i *atomicXor32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicXor{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_W,
		Offset: int16(i.Offset),
		Fetch:  false, // TODO make a special instruction for the fetch flag?
	}}, nil
}

type atomicXor64 struct {
	Dst    Register `parser:"'lock' '*' '(' 'u64' '*' ')' '(' @Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ')' '^' '='"`
	Src    Register `parser:"@Register64"`
}

func (i *atomicXor64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&AtomicXor{
		Dest:   i.Dst,
		Src:    i.Src,
		Size:   BPF_DW,
		Offset: int16(i.Offset),
		Fetch:  false, // TODO make a special instruction for the fetch flag?
	}}, nil
}

// Call is both for BPF-to-BPF and helper funcs, but since
type call struct {
	Ident     *string `parser:"'call' (@Ident |"`
	Offset    *int32  `parser:"@(('+'|'-') Number) |"`
	HelperNum *int32  `parser:"@Number)"`
}

func (i *call) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	if i.Ident != nil {
		pos, found := ctx.Labels[*i.Ident]
		if !found {
			// TODO check if the ident matches a known helper function

			return nil, fmt.Errorf("undefined label '%s'", *i.Ident)
		}

		off := int32(pos-index) - 1
		i.Offset = &off
	}

	if i.Offset != nil {
		return []Instruction{&CallBPF{
			Offset: *i.Offset,
		}}, nil
	}

	if i.HelperNum != nil {
		return []Instruction{&CallHelper{
			Function: *i.HelperNum,
		}}, nil
	}

	return nil, nil
}

type div32 struct {
	Dst   Register `parser:"@Register32 '/' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *div32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Div32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type div32Register struct {
	Dst Register `parser:"@Register32 '/' '='"`
	Src Register `parser:"@Register32"`
}

func (i *div32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Div32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type div64 struct {
	Dst   Register `parser:"@Register64 '/' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *div64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Div64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type div64Register struct {
	Dst Register `parser:"@Register64 '/' '='"`
	Src Register `parser:"@Register64"`
}

func (i *div64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Div64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type end16ToBE struct {
	Dst Register `parser:"@Register64 '=' 'be16' Register64"`
}

func (i *end16ToBE) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&End16ToBE{
		Dest: i.Dst,
	}}, nil
}

type end16ToLE struct {
	Dst Register `parser:"@Register64 '=' 'le16' Register64"`
}

func (i *end16ToLE) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&End16ToLE{
		Dest: i.Dst,
	}}, nil
}

type end32ToBE struct {
	Dst Register `parser:"@Register64 '=' 'be32' Register64"`
}

func (i *end32ToBE) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&End32ToBE{
		Dest: i.Dst,
	}}, nil
}

type end32ToLE struct {
	Dst Register `parser:"@Register64 '=' 'le32' Register64"`
}

func (i *end32ToLE) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&End32ToLE{
		Dest: i.Dst,
	}}, nil
}

type end64ToBE struct {
	Dst Register `parser:"@Register64 '=' 'be64' Register64"`
}

func (i *end64ToBE) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&End64ToBE{
		Dest: i.Dst,
	}}, nil
}

type end64ToLE struct {
	Dst Register `parser:"@Register64 '=' 'le64' Register64"`
}

func (i *end64ToLE) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&End64ToLE{
		Dest: i.Dst,
	}}, nil
}

type exit struct {
	Exit struct{} `parser:"'exit'"`
}

func (i *exit) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Exit{}}, nil
}

type jump struct {
	Offset *int16  `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string `parser:"@Ident )"`
}

func (i *jump) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &Jump{}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target, -1 since a offset of 0 will jump
		// to the next instruction (inherent pc+1)
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpEqual struct {
	Dest   Register `parser:"'if' @Register64 '=' '=' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpEqual) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpEqual{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpEqual32 struct {
	Dest   Register `parser:"'if' @Register32 '=' '=' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpEqual32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpEqual32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpEqualRegister struct {
	Dest   Register `parser:"'if' @Register64 '=' '=' "`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpEqualRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpEqualRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpEqualRegister32 struct {
	Dest   Register `parser:"'if' @Register32 '=' '=' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpEqualRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpEqualRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpGreaterThan struct {
	Dest   Register `parser:"'if' @Register64 '>' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpGreaterThan) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpGreaterThan{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpGreaterThan32 struct {
	Dest   Register `parser:"'if' @Register32 '>' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpGreaterThan32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpGreaterThan32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpGreaterThanRegister struct {
	Dest   Register `parser:"'if' @Register64 '>' "`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpGreaterThanRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpGreaterThanRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpGreaterThanRegister32 struct {
	Dest   Register `parser:"'if' @Register32 '>' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpGreaterThanRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpGreaterThanRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpGreaterThanEqual struct {
	Dest   Register `parser:"'if' @Register64 '>' '='"`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpGreaterThanEqual) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpGreaterThanEqual{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpGreaterThanEqual32 struct {
	Dest   Register `parser:"'if' @Register32 '>' '='"`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpGreaterThanEqual32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpGreaterThanEqual32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpGreaterThanEqualRegister struct {
	Dest   Register `parser:"'if' @Register64 '>' '='"`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpGreaterThanEqualRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpGreaterThanEqualRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpGreaterThanEqualRegister32 struct {
	Dest   Register `parser:"'if' @Register32 '>' '=' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpGreaterThanEqualRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpGreaterThanEqualRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpIfAnd struct {
	Dest   Register `parser:"'if' @Register64 '&' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpIfAnd) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpAnd{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpIfAnd32 struct {
	Dest   Register `parser:"'if' @Register32 '&' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpIfAnd32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpAnd32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpIfAndRegister struct {
	Dest   Register `parser:"'if' @Register64 '&' "`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpIfAndRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpAndRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpIfAndRegister32 struct {
	Dest   Register `parser:"'if' @Register32 '&' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpIfAndRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpAndRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpIfNotEqual struct {
	Dest   Register `parser:"'if' @Register64 '!' '=' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpIfNotEqual) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpNotEqual{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpIfNotEqual32 struct {
	Dest   Register `parser:"'if' @Register32 '!' '=' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpIfNotEqual32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpNotEqual32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpIfNotEqualRegister struct {
	Dest   Register `parser:"'if' @Register64 '!' '=' "`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpIfNotEqualRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpNotEqualRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpIfNotEqualRegister32 struct {
	Dest   Register `parser:"'if' @Register32 '!' '=' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpIfNotEqualRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpNotEqualRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedGreaterThan struct {
	Dest   Register `parser:"'if' @Register64 's' '>' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedGreaterThan) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedGreaterThan{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedGreaterThan32 struct {
	Dest   Register `parser:"'if' @Register32 's' '>' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedGreaterThan32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedGreaterThan32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedGreaterThanRegister struct {
	Dest   Register `parser:"'if' @Register64 's' '>' "`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedGreaterThanRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedGreaterThanRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedGreaterThanRegister32 struct {
	Dest   Register `parser:"'if' @Register32 's' '>' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedGreaterThanRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedGreaterThanRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedGreaterThanOrEqual struct {
	Dest   Register `parser:"'if' @Register64 's' '>' '='"`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedGreaterThanOrEqual) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedGreaterThanOrEqual{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedGreaterThanOrEqual32 struct {
	Dest   Register `parser:"'if' @Register32 's' '>' '='"`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedGreaterThanOrEqual32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedGreaterThanOrEqual32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedGreaterThanOrEqualRegister struct {
	Dest   Register `parser:"'if' @Register64 's' '>' '='"`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedGreaterThanOrEqualRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedGreaterThanOrEqualRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedGreaterThanOrEqualRegister32 struct {
	Dest   Register `parser:"'if' @Register32 's' '>' '=' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedGreaterThanOrEqualRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedGreaterThanOrEqualRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedSmallerThan struct {
	Dest   Register `parser:"'if' @Register64 's' '<' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedSmallerThan) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedSmallerThan{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedSmallerThan32 struct {
	Dest   Register `parser:"'if' @Register32 's' '<' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedSmallerThan32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedSmallerThan32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedSmallerThanRegister struct {
	Dest   Register `parser:"'if' @Register64 's' '<' "`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedSmallerThanRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedSmallerThanRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedSmallerThanRegister32 struct {
	Dest   Register `parser:"'if' @Register32 's' '<' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedSmallerThanRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedSmallerThanRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedSmallerThanOrEqual struct {
	Dest   Register `parser:"'if' @Register64 's' '<' '='"`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedSmallerThanOrEqual) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedSmallerThanOrEqual{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedSmallerThanOrEqual32 struct {
	Dest   Register `parser:"'if' @Register32 's' '<' '='"`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedSmallerThanOrEqual32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedSmallerThanOrEqual32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedSmallerThanOrEqualRegister struct {
	Dest   Register `parser:"'if' @Register64 's' '<' '='"`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedSmallerThanOrEqualRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedSmallerThanOrEqualRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSignedSmallerThanOrEqualRegister32 struct {
	Dest   Register `parser:"'if' @Register32 's' '<' '=' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSignedSmallerThanOrEqualRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSignedSmallerThanOrEqualRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSmallerThan struct {
	Dest   Register `parser:"'if' @Register64 '<' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSmallerThan) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSmallerThan{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSmallerThan32 struct {
	Dest   Register `parser:"'if' @Register32 '<' "`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSmallerThan32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSmallerThan32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSmallerThanRegister struct {
	Dest   Register `parser:"'if' @Register64 '<' "`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSmallerThanRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSmallerThanRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSmallerThanRegister32 struct {
	Dest   Register `parser:"'if' @Register32 '<' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSmallerThanRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSmallerThanRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSmallerThanEqual struct {
	Dest   Register `parser:"'if' @Register64 '<' '='"`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSmallerThanEqual) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSmallerThanEqual{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSmallerThanEqual32 struct {
	Dest   Register `parser:"'if' @Register32 '<' '='"`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSmallerThanEqual32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSmallerThanEqual32{
		Dest:  i.Dest,
		Value: i.Value,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSmallerThanEqualRegister struct {
	Dest   Register `parser:"'if' @Register64 '<' '='"`
	Src    Register `parser:"@Register64"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSmallerThanEqualRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSmallerThanEqualRegister{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type jumpSmallerThanEqualRegister32 struct {
	Dest   Register `parser:"'if' @Register32 '<' '=' "`
	Src    Register `parser:"@Register32"`
	Offset *int16   `parser:"'goto' (@(('+'|'-')? Number) |"`
	Label  *string  `parser:"@Ident )"`
}

func (i *jumpSmallerThanEqualRegister32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	inst := &JumpSmallerThanEqualRegister32{
		Dest: i.Dest,
		Src:  i.Src,
	}

	if i.Label != nil {
		target, found := ctx.Labels[*i.Label]
		if !found {
			return nil, fmt.Errorf("invalid label '%s' at instruction %d", *i.Label, index)
		}

		// Get diff between current instruction and the target
		inst.Offset = int16(target-index) - 1
	}

	if i.Offset != nil {
		inst.Offset = *i.Offset
	}

	return []Instruction{inst}, nil
}

type loadConstant64bit struct {
	Dest  Register `parser:"@Register64 '='"`
	Label *string  `parser:"(@Ident |"`
	Value *int64   `parser:"@Number) 'll'"`
}

func (i *loadConstant64bit) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	ld := &LoadConstant64bit{
		Dest: i.Dest,
	}

	if i.Value != nil {
		val := uint64(*i.Value)
		ld.Val2 = uint32((val >> 32) & 0xFFFFFFFF)
		ld.Val1 = uint32(val & 0xFFFFFFFF)
	}

	// Since the LD instruction will generate 2 eBPF instructions, we also create the Nop instructions
	// which will generate no eBPF instructions. So the amount of Instructions and eBPF instructions
	// stay the same, makes live easier while calclulating offsets and such.
	return []Instruction{ld, &Nop{}}, nil
}

type loadMemory struct {
	Dst    Register `parser:"@Register64 '='"`
	Size   Size     `parser:"'*' '(' @Ident '*' ')' '('"`
	Src    Register `parser:"@Register64"`
	Offset int16    `parser:"@(('+'|'-') Number) ')'"`
}

func (i *loadMemory) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&LoadMemory{
		Dest:   i.Dst,
		Size:   i.Size,
		Src:    i.Src,
		Offset: i.Offset,
	}}, nil
}

// r0 = ntohl((u8) (((struct sk_buff *) r6)->data[r1]))
type loadSocketBuf struct {
	// nolint:lll // can't multi-line struct tags
	Size   Size     `parser:"'r0' '=' 'ntohl' '(' '(' @Ident ')' '(' '(' '(' 'struct' 'sk_buff' '*' ')' 'r6' ')' '-' '>' 'data' '['"`
	Src    Register `parser:"@Register64"`
	Offset int32    `parser:"@(('+'|'-') Number) ']' ')' ')'"`
}

func (i *loadSocketBuf) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&LoadSocketBuf{
		Size:   i.Size,
		Src:    i.Src,
		Offset: i.Offset,
	}}, nil
}

// r0 = ntohl((u8) (((struct sk_buff *) r6)->data[456]))
type loadSocketBufConstant struct {
	// nolint:lll // can't multi-line struct tags
	Size  Size  `parser:"'r0' '=' 'ntohl' '(' '(' @Ident ')' '(' '(' '(' 'struct' 'sk_buff' '*' ')' 'r6' ')' '-' '>' 'data' '['"`
	Value int32 `parser:"@Number ']' ')' ')'"`
}

func (i *loadSocketBufConstant) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&LoadSocketBufConstant{
		Size:  i.Size,
		Value: i.Value,
	}}, nil
}

type lsh32 struct {
	Dst   Register `parser:"@Register32 '<' '<' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *lsh32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Lsh32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type lsh32Register struct {
	Dst Register `parser:"@Register32 '<' '<' '='"`
	Src Register `parser:"@Register32"`
}

func (i *lsh32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Lsh32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type lsh64 struct {
	Dst   Register `parser:"@Register64 '<' '<' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *lsh64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Lsh64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type lsh64Register struct {
	Dst Register `parser:"@Register64 '<' '<' '='"`
	Src Register `parser:"@Register64"`
}

func (i *lsh64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Lsh64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type mod32 struct {
	Dst   Register `parser:"@Register32 '%' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *mod32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mod32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type mod32Register struct {
	Dst Register `parser:"@Register32 '%' '='"`
	Src Register `parser:"@Register32"`
}

func (i *mod32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mod32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type mod64 struct {
	Dst   Register `parser:"@Register64 '%' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *mod64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mod64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type mod64Register struct {
	Dst Register `parser:"@Register64 '%' '='"`
	Src Register `parser:"@Register64"`
}

func (i *mod64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mod64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type mov32 struct {
	Dst   Register `parser:"@Register32 '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *mov32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mov32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type mov32Register struct {
	Dst Register `parser:"@Register32 '='"`
	Src Register `parser:"@Register32"`
}

func (i *mov32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mov32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type mov64 struct {
	Dst   Register `parser:"@Register64 '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *mov64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mov64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type mov64Register struct {
	Dst Register `parser:"@Register64 '='"`
	Src Register `parser:"@Register64"`
}

func (i *mov64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mov64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type mul32 struct {
	Dst   Register `parser:"@Register32 '*' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *mul32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mul32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type mul32Register struct {
	Dst Register `parser:"@Register32 '*' '='"`
	Src Register `parser:"@Register32"`
}

func (i *mul32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mul32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type mul64 struct {
	Dst   Register `parser:"@Register64 '*' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *mul64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mul64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type mul64Register struct {
	Dst Register `parser:"@Register64 '*' '='"`
	Src Register `parser:"@Register64"`
}

func (i *mul64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Mul64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type neg32 struct {
	Dst Register `parser:"@Register32 '=' '-' Register32"`
}

func (i *neg32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Neg32{
		Dest: i.Dst,
	}}, nil
}

type neg64 struct {
	Dst Register `parser:"@Register64 '=' '-' Register64"`
}

func (i *neg64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Neg64{
		Dest: i.Dst,
	}}, nil
}

type or32 struct {
	Dst   Register `parser:"@Register32 '|' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *or32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Or32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type or32Register struct {
	Dst Register `parser:"@Register32 '|' '='"`
	Src Register `parser:"@Register32"`
}

func (i *or32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Or32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type or64 struct {
	Dst   Register `parser:"@Register64 '|' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *or64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Or64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type or64Register struct {
	Dst Register `parser:"@Register64 '|' '='"`
	Src Register `parser:"@Register64"`
}

func (i *or64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Or64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type rsh32 struct {
	Dst   Register `parser:"@Register32 '>' '>' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *rsh32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Rsh32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type rsh32Register struct {
	Dst Register `parser:"@Register32 '>' '>' '='"`
	Src Register `parser:"@Register32"`
}

func (i *rsh32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Rsh32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type rsh64 struct {
	Dst   Register `parser:"@Register64 '>' '>' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *rsh64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Rsh64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type rsh64Register struct {
	Dst Register `parser:"@Register64 '>' '>' '='"`
	Src Register `parser:"@Register64"`
}

func (i *rsh64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Rsh64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

// *(u8 *)(r3 + 456) = 123
type storeMemoryConstant struct {
	Size   Size     `parser:"'*' '(' @Ident '*' ')' '('"`
	Dst    Register `parser:"@Register64"`
	Offset int16    `parser:"@(('+'|'-') Number) ')' '='"`
	Value  int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *storeMemoryConstant) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&StoreMemoryConstant{
		Size:   i.Size,
		Dest:   i.Dst,
		Offset: i.Offset,
		Value:  i.Value,
	}}, nil
}

// *(u8 *)(r3 + 456) = r1
type storeMemoryRegister struct {
	Size   Size     `parser:"'*' '(' @Ident '*' ')' '('"`
	Dst    Register `parser:"@Register64"`
	Offset int16    `parser:"@(('+'|'-') Number) ')' '='"`
	Src    Register `parser:"@Register64"`
}

func (i *storeMemoryRegister) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&StoreMemoryRegister{
		Size:   i.Size,
		Dest:   i.Dst,
		Offset: i.Offset,
		Src:    i.Src,
	}}, nil
}

type sub32 struct {
	Dst   Register `parser:"@Register32 '-' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *sub32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Sub32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type sub32Register struct {
	Dst Register `parser:"@Register32 '-' '='"`
	Src Register `parser:"@Register32"`
}

func (i *sub32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Sub32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type sub64 struct {
	Dst   Register `parser:"@Register64 '-' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *sub64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Sub64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type sub64Register struct {
	Dst Register `parser:"@Register64 '-' '='"`
	Src Register `parser:"@Register64"`
}

func (i *sub64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Sub64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type xor32 struct {
	Dst   Register `parser:"@Register32 '^' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *xor32) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Xor32{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type xor32Register struct {
	Dst Register `parser:"@Register32 '^' '='"`
	Src Register `parser:"@Register32"`
}

func (i *xor32Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Xor32Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}

type xor64 struct {
	Dst   Register `parser:"@Register64 '^' '='"`
	Value int32    `parser:"@(('+'|'-')? Number)"`
}

func (i *xor64) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Xor64{
		Dest:  i.Dst,
		Value: i.Value,
	}}, nil
}

type xor64Register struct {
	Dst Register `parser:"@Register64 '^' '='"`
	Src Register `parser:"@Register64"`
}

func (i *xor64Register) ToInst(index int, ctx *assembleContext) ([]Instruction, error) {
	return []Instruction{&Xor64Register{
		Dest: i.Dst,
		Src:  i.Src,
	}}, nil
}
