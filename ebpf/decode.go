package ebpf

import "fmt"

// Decode decodes a slice of raw instructions into interpreted instructions
func Decode(rawIns []RawInstruction) ([]Instruction, error) {
	instructions := make([]Instruction, 0, len(rawIns))
	for i := 0; i < len(rawIns); i++ {
		raw := rawIns[i]
		op := raw.Op
		imm := raw.Imm
		dst := raw.GetDestReg()
		src := raw.GetSourceReg()
		off := raw.Off

		var inst Instruction

		switch op {
		case BPF_LD | BPF_IMM:
			inst = &LoadConstant{
				Dest: dst,
				Val:  imm,
			}

		case BPF_LD | uint8(BPF_DW) | BPF_IMM:
			if i+1 >= len(rawIns) {
				return nil, fmt.Errorf("%d: load double word imm op code found but not enough instructions available"+
					" for full decoding", i)
			}

			instructions = append(instructions, &LoadConstant64bit{
				Dest: dst,
				Src:  src,
				Val1: imm,
				Val2: rawIns[i+1].Imm,
			})

			inst = &Nop{}

			i++

		case BPF_LD | BPF_ABS | uint8(BPF_W):
			inst = &LoadSocketBufConstant{
				Val:  imm,
				Size: BPF_W,
			}

		case BPF_LD | BPF_ABS | uint8(BPF_H):
			inst = &LoadSocketBufConstant{
				Val:  imm,
				Size: BPF_H,
			}

		case BPF_LD | BPF_ABS | uint8(BPF_B):
			inst = &LoadSocketBufConstant{
				Val:  imm,
				Size: BPF_B,
			}

		case BPF_LD | BPF_ABS | uint8(BPF_DW):
			inst = &LoadSocketBufConstant{
				Val:  imm,
				Size: BPF_DW,
			}

		case BPF_LD | BPF_IND | uint8(BPF_W):
			inst = &LoadSocketBuf{
				Src:    src,
				Offset: imm,
				Size:   BPF_W,
			}

		case BPF_LD | BPF_IND | uint8(BPF_H):
			inst = &LoadSocketBuf{
				Src:    src,
				Offset: imm,
				Size:   BPF_H,
			}

		case BPF_LD | BPF_IND | uint8(BPF_B):
			inst = &LoadSocketBuf{
				Src:    src,
				Offset: imm,
				Size:   BPF_B,
			}

		case BPF_LD | BPF_IND | uint8(BPF_DW):
			inst = &LoadSocketBuf{
				Src:    src,
				Offset: imm,
				Size:   BPF_DW,
			}

		case BPF_LDX | BPF_IMM:
			inst = &LoadRegister{
				Dest: dst,
				Src:  src,
			}

		case BPF_LDX | BPF_MEM | uint8(BPF_W),
			BPF_LDX | BPF_MEM | uint8(BPF_H),
			BPF_LDX | BPF_MEM | uint8(BPF_B),
			BPF_LDX | BPF_MEM | uint8(BPF_DW):

			inst = &LoadMemory{
				Src:    src,
				Dest:   dst,
				Offset: off,
				Size:   Size(op ^ (BPF_LDX | BPF_MEM)),
			}

		case BPF_ST | BPF_MEM | uint8(BPF_W),
			BPF_ST | BPF_MEM | uint8(BPF_H),
			BPF_ST | BPF_MEM | uint8(BPF_B),
			BPF_ST | BPF_MEM | uint8(BPF_DW):
			inst = &StoreMemoryConstant{
				Dest:   dst,
				Offset: off,
				Size:   Size(op ^ (BPF_ST | BPF_MEM)),
				Val:    imm,
			}

		case BPF_STX | BPF_MEM | uint8(BPF_W),
			BPF_STX | BPF_MEM | uint8(BPF_H),
			BPF_STX | BPF_MEM | uint8(BPF_B),
			BPF_STX | BPF_MEM | uint8(BPF_DW):
			inst = &StoreMemoryRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
				Size:   Size(op ^ (BPF_STX | BPF_MEM)),
			}

		case BPF_STX | BPF_ATOMIC | uint8(BPF_W),
			BPF_STX | BPF_ATOMIC | uint8(BPF_H),
			BPF_STX | BPF_ATOMIC | uint8(BPF_B),
			BPF_STX | BPF_ATOMIC | uint8(BPF_DW):

			switch imm {
			case int32(BPF_ADD), int32(BPF_ADD | BPF_FETCH):
				inst = &AtomicAdd{
					Src:    src,
					Dest:   dst,
					Offset: off,
					Size:   Size(op ^ (BPF_STX | BPF_ATOMIC)),
					Fetch:  imm == int32(BPF_ADD|BPF_FETCH),
				}
			case int32(BPF_AND), int32(BPF_AND | BPF_FETCH):
				inst = &AtomicAnd{
					Src:    src,
					Dest:   dst,
					Offset: off,
					Size:   Size(op ^ (BPF_STX | BPF_ATOMIC)),
					Fetch:  imm == int32(BPF_AND|BPF_FETCH),
				}
			case int32(BPF_OR), int32(BPF_OR | BPF_FETCH):
				inst = &AtomicOr{
					Src:    src,
					Dest:   dst,
					Offset: off,
					Size:   Size(op ^ (BPF_STX | BPF_ATOMIC)),
					Fetch:  imm == int32(BPF_OR|BPF_FETCH),
				}
			case int32(BPF_XOR), int32(BPF_XOR | BPF_FETCH):
				inst = &AtomicXor{
					Src:    src,
					Dest:   dst,
					Offset: off,
					Size:   Size(op ^ (BPF_STX | BPF_ATOMIC)),
					Fetch:  imm == int32(BPF_XOR|BPF_FETCH),
				}
			case int32(BPF_XCHG):
				inst = &AtomicExchange{
					Src:    src,
					Dest:   dst,
					Offset: off,
					Size:   Size(op ^ (BPF_STX | BPF_ATOMIC)),
				}
			case int32(BPF_CMPXCHG):
				inst = &AtomicCompareAndWrite{
					Src:    src,
					Dest:   dst,
					Offset: off,
					Size:   Size(op ^ (BPF_STX | BPF_ATOMIC)),
				}
			}

		case BPF_ALU | BPF_K | BPF_ADD:
			inst = &Add32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_ADD:
			inst = &Add64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_ADD:
			inst = &Add32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_ADD:
			inst = &Add64Register{
				Dest: dst,
				Src:  src,
			}

		//

		case BPF_ALU | BPF_K | BPF_SUB:
			inst = &Sub32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_SUB:
			inst = &Sub64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_SUB:
			inst = &Sub32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_SUB:
			inst = &Sub64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_K | BPF_MUL:
			inst = &Mul32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_MUL:
			inst = &Mul64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_MUL:
			inst = &Mul32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_MUL:
			inst = &Mul64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_K | BPF_DIV:
			inst = &Div32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_DIV:
			inst = &Div64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_DIV:
			inst = &Div32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_DIV:
			inst = &Div64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_K | BPF_OR:
			inst = &Or32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_OR:
			inst = &Or64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_OR:
			inst = &Or32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_OR:
			inst = &Or64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_K | BPF_AND:
			inst = &And32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_AND:
			inst = &And64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_AND:
			inst = &And32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_AND:
			inst = &And64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_K | BPF_LSH:
			inst = &Lsh32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_LSH:
			inst = &Lsh64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_LSH:
			inst = &Lsh32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_LSH:
			inst = &Lsh64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_K | BPF_RSH:
			inst = &Rsh32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_RSH:
			inst = &Rsh64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_RSH:
			inst = &Rsh32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_RSH:
			inst = &Rsh64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_NEG:
			inst = &Neg32{
				Dest: dst,
			}

		case BPF_ALU64 | BPF_NEG:
			inst = &Neg32{
				Dest: dst,
			}

			//

		case BPF_ALU | BPF_K | BPF_MOD:
			inst = &Mod32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_MOD:
			inst = &Mod64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_MOD:
			inst = &Mod32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_MOD:
			inst = &Mod64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_K | BPF_XOR:
			inst = &Xor32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_XOR:
			inst = &Xor64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_XOR:
			inst = &Xor32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_XOR:
			inst = &Xor64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_K | BPF_MOV:
			inst = &Mov32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_MOV:
			inst = &Mov64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_MOV:
			inst = &Mov32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_MOV:
			inst = &Mov64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_K | BPF_ARSH:
			inst = &ARSH32{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU64 | BPF_K | BPF_ARSH:
			inst = &ARSH64{
				Dest: dst,
				Val:  imm,
			}

		case BPF_ALU | BPF_X | BPF_ARSH:
			inst = &ARSH32Register{
				Dest: dst,
				Src:  src,
			}

		case BPF_ALU64 | BPF_X | BPF_ARSH:
			inst = &ARSH64Register{
				Dest: dst,
				Src:  src,
			}

			//

		case BPF_ALU | BPF_END | BPF_TO_LE:
			inst = &End32ToLE{
				Dest: dst,
			}

		case BPF_ALU64 | BPF_END | BPF_TO_LE:
			inst = &End64ToLE{
				Dest: dst,
			}

		case BPF_ALU | BPF_END | BPF_TO_BE:
			inst = &End32ToBE{
				Dest: dst,
			}

		case BPF_ALU64 | BPF_END | BPF_TO_BE:
			inst = &End64ToBE{
				Dest: dst,
			}

			//

		case BPF_JMP | BPF_JA:
			inst = &Jump{
				Offset: off,
			}

			//

		case BPF_JMP | BPF_K | BPF_JEQ:
			inst = &JumpEqual{
				Dest:   dst,
				Offset: off,
				Value:  imm,
			}

		case BPF_JMP32 | BPF_K | BPF_JEQ:
			inst = &JumpEqual32{
				Dest:   dst,
				Offset: off,
				Value:  imm,
			}

		case BPF_JMP | BPF_X | BPF_JEQ:
			inst = &JumpEqualRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JEQ:
			inst = &JumpEqualRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

			//

		case BPF_JMP | BPF_K | BPF_JGT:
			inst = &JumpGreaterThan{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP32 | BPF_K | BPF_JGT:
			inst = &JumpGreaterThan32{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP | BPF_X | BPF_JGT:
			inst = &JumpGreaterThanRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JGT:
			inst = &JumpGreaterThanRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

			//

		case BPF_JMP | BPF_K | BPF_JGE:
			inst = &JumpGreaterThanEqual{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP32 | BPF_K | BPF_JGE:
			inst = &JumpGreaterThanEqual32{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP | BPF_X | BPF_JGE:
			inst = &JumpGreaterThanEqualRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JGE:
			inst = &JumpGreaterThanEqualRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

			//

		case BPF_JMP | BPF_K | BPF_JSET:
			inst = &JumpIfAnd{
				Dest:   dst,
				Offset: off,
				Value:  imm,
			}

		case BPF_JMP32 | BPF_K | BPF_JSET:
			inst = &JumpIfAnd32{
				Dest:   dst,
				Offset: off,
				Value:  imm,
			}

		case BPF_JMP | BPF_X | BPF_JSET:
			inst = &JumpIfAndRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JSET:
			inst = &JumpIfAndRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

			//

		case BPF_JMP | BPF_K | BPF_JNE:
			inst = &JumpIfNotEqual{
				Dest:   dst,
				Offset: off,
				Value:  imm,
			}

		case BPF_JMP32 | BPF_K | BPF_JNE:
			inst = &JumpIfNotEqual32{
				Dest:   dst,
				Offset: off,
				Value:  imm,
			}

		case BPF_JMP | BPF_X | BPF_JNE:
			inst = &JumpIfNotEqualRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JNE:
			inst = &JumpIfNotEqualRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

			//

		case BPF_JMP | BPF_K | BPF_JSGT:
			inst = &JumpSignedGreaterThan{
				Dest:   dst,
				Offset: off,
				Value:  imm,
			}

		case BPF_JMP32 | BPF_K | BPF_JSGT:
			inst = &JumpSignedGreaterThan32{
				Dest:   dst,
				Offset: off,
				Value:  imm,
			}

		case BPF_JMP | BPF_X | BPF_JSGT:
			inst = &JumpSignedGreaterThanRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JSGT:
			inst = &JumpSignedGreaterThanRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

			//

		case BPF_JMP | BPF_K | BPF_JSGE:
			inst = &JumpSignedGreaterThanOrEqual{
				Dest:   dst,
				Offset: off,
				Value:  imm,
			}

		case BPF_JMP32 | BPF_K | BPF_JSGE:
			inst = &JumpSignedGreaterThanOrEqual32{
				Dest:   dst,
				Offset: off,
				Value:  imm,
			}

		case BPF_JMP | BPF_X | BPF_JSGE:
			inst = &JumpSignedGreaterThanOrEqualRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JSGE:
			inst = &JumpSignedGreaterThanOrEqualRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

			//

		case BPF_JMP | BPF_CALL:

			if src == PSEUDO_CALL {
				inst = &CallBPF{
					Offset: imm,
				}
			} else {
				inst = &CallHelper{
					Function: imm,
				}
			}

			//

		case BPF_JMP | BPF_EXIT:
			inst = &Exit{}

		//

		case BPF_JMP | BPF_K | BPF_JLT:
			inst = &JumpSmallerThan{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP32 | BPF_K | BPF_JLT:
			inst = &JumpSmallerThan32{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP | BPF_X | BPF_JLT:
			inst = &JumpSmallerThanRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JLT:
			inst = &JumpSmallerThanRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

			//

		case BPF_JMP | BPF_K | BPF_JLE:
			inst = &JumpSmallerThanEqual{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP32 | BPF_K | BPF_JLE:
			inst = &JumpSmallerThanEqual32{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP | BPF_X | BPF_JLE:
			inst = &JumpSmallerThanEqualRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JLE:
			inst = &JumpSmallerThanEqualRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

			//

		case BPF_JMP | BPF_K | BPF_JSLT:
			inst = &JumpSignedSmallerThan{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP32 | BPF_K | BPF_JSLT:
			inst = &JumpSignedSmallerThan32{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP | BPF_X | BPF_JSLT:
			inst = &JumpSignedSmallerThanRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JSLT:
			inst = &JumpSignedSmallerThanRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

			//

		case BPF_JMP | BPF_K | BPF_JSLE:
			inst = &JumpSignedSmallerThanOrEqual{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP32 | BPF_K | BPF_JSLE:
			inst = &JumpSignedSmallerThanOrEqual32{
				Dest:   dst,
				Offset: off,
				Value:  uint32(imm),
			}

		case BPF_JMP | BPF_X | BPF_JSLE:
			inst = &JumpSignedSmallerThanOrEqualRegister{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}

		case BPF_JMP32 | BPF_X | BPF_JSLE:
			inst = &JumpSignedSmallerThanOrEqualRegister32{
				Dest:   dst,
				Src:    src,
				Offset: off,
			}
		}

		if inst != nil {
			instructions = append(instructions, inst)
			continue
		}

		return nil, fmt.Errorf(
			"unable to decode raw instruction, inst: %d, op: %2x, src: %s, dst: %s, off: %4x, imm: %8x",
			i, op, src, dst, off, imm,
		)
	}

	return instructions, nil
}
