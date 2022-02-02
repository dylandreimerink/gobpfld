package emulator

import (
	"fmt"
	"reflect"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

// Instruction represents an eBPF instruction, as apposed to the ebpf.Instruction interface, these instruction can
// actually be executed by an emulator VM.
type Instruction interface {
	ebpf.Instruction

	Clone() Instruction
	Execute(vm *VM) error
}

// Translate translates the High level instructions of the ebpf package and embeds them into instructions defined
// by the emulator package. The emulator instructions contain the logic to actually execute them.
func Translate(prog []ebpf.Instruction) ([]Instruction, error) {
	vmProg := make([]Instruction, len(prog))

	for i, intInst := range prog {
		var newInst Instruction

		switch inst := intInst.(type) {
		case *ebpf.Add32:
			newInst = &Add32{Add32: *inst}
		case *ebpf.Add64:
			newInst = &Add64{Add64: *inst}
		case *ebpf.Add32Register:
			newInst = &Add32Register{Add32Register: *inst}
		case *ebpf.Add64Register:
			newInst = &Add64Register{Add64Register: *inst}
		case *ebpf.And32:
			newInst = &And32{And32: *inst}
		case *ebpf.And64:
			newInst = &And64{And64: *inst}
		case *ebpf.And32Register:
			newInst = &And32Register{And32Register: *inst}
		case *ebpf.And64Register:
			newInst = &And64Register{And64Register: *inst}
		case *ebpf.ARSH32:
			newInst = &ARSH32{ARSH32: *inst}
		case *ebpf.ARSH64:
			newInst = &ARSH64{ARSH64: *inst}
		case *ebpf.ARSH32Register:
			newInst = &ARSH32Register{ARSH32Register: *inst}
		case *ebpf.ARSH64Register:
			newInst = &ARSH64Register{ARSH64Register: *inst}
		case *ebpf.AtomicAdd:
			newInst = &AtomicAdd{AtomicAdd: *inst}
		case *ebpf.CallBPF:
			newInst = &CallBPF{CallBPF: *inst}
		case *ebpf.CallHelper:
			newInst = &CallHelper{CallHelper: *inst}
		case *ebpf.CallHelperIndirect:
			newInst = &CallHelperIndirect{CallHelperIndirect: *inst}
		case *ebpf.Div32:
			newInst = &Div32{Div32: *inst}
		case *ebpf.Div64:
			newInst = &Div64{Div64: *inst}
		case *ebpf.Div32Register:
			newInst = &Div32Register{Div32Register: *inst}
		case *ebpf.Div64Register:
			newInst = &Div64Register{Div64Register: *inst}
		case *ebpf.End16ToLE:
			newInst = &End16ToLE{End16ToLE: *inst}
		case *ebpf.End32ToLE:
			newInst = &End32ToLE{End32ToLE: *inst}
		case *ebpf.End64ToLE:
			newInst = &End64ToLE{End64ToLE: *inst}
		case *ebpf.End16ToBE:
			newInst = &End16ToBE{End16ToBE: *inst}
		case *ebpf.End32ToBE:
			newInst = &End32ToBE{End32ToBE: *inst}
		case *ebpf.End64ToBE:
			newInst = &End64ToBE{End64ToBE: *inst}
		case *ebpf.Exit:
			newInst = &Exit{Exit: *inst}
		case *ebpf.Jump:
			newInst = &Jump{Jump: *inst}
		case *ebpf.JumpEqual:
			newInst = &JumpEqual{JumpEqual: *inst}
		case *ebpf.JumpEqual32:
			newInst = &JumpEqual32{JumpEqual32: *inst}
		case *ebpf.JumpEqualRegister:
			newInst = &JumpEqualRegister{JumpEqualRegister: *inst}
		case *ebpf.JumpEqualRegister32:
			newInst = &JumpEqualRegister32{JumpEqualRegister32: *inst}
		case *ebpf.JumpNotEqual:
			newInst = &JumpNotEqual{JumpNotEqual: *inst}
		case *ebpf.JumpNotEqual32:
			newInst = &JumpNotEqual32{JumpNotEqual32: *inst}
		case *ebpf.JumpNotEqualRegister:
			newInst = &JumpNotEqualRegister{JumpNotEqualRegister: *inst}
		case *ebpf.JumpNotEqualRegister32:
			newInst = &JumpNotEqualRegister32{JumpNotEqualRegister32: *inst}
		case *ebpf.JumpGreaterThanEqual:
			newInst = &JumpGreaterThanEqual{JumpGreaterThanEqual: *inst}
		case *ebpf.JumpGreaterThanEqual32:
			newInst = &JumpGreaterThanEqual32{JumpGreaterThanEqual32: *inst}
		case *ebpf.JumpGreaterThanEqualRegister:
			newInst = &JumpGreaterThanEqualRegister{JumpGreaterThanEqualRegister: *inst}
		case *ebpf.JumpGreaterThanEqualRegister32:
			newInst = &JumpGreaterThanEqualRegister32{JumpGreaterThanEqualRegister32: *inst}
		case *ebpf.JumpGreaterThan:
			newInst = &JumpGreaterThan{JumpGreaterThan: *inst}
		case *ebpf.JumpGreaterThan32:
			newInst = &JumpGreaterThan32{JumpGreaterThan32: *inst}
		case *ebpf.JumpGreaterThanRegister:
			newInst = &JumpGreaterThanRegister{JumpGreaterThanRegister: *inst}
		case *ebpf.JumpGreaterThanRegister32:
			newInst = &JumpGreaterThanRegister32{JumpGreaterThanRegister32: *inst}
		case *ebpf.JumpSignedGreaterThanOrEqual:
			newInst = &JumpSignedGreaterThanOrEqual{JumpSignedGreaterThanOrEqual: *inst}
		case *ebpf.JumpSignedGreaterThanOrEqual32:
			newInst = &JumpSignedGreaterThanOrEqual32{JumpSignedGreaterThanOrEqual32: *inst}
		case *ebpf.JumpSignedGreaterThanOrEqualRegister:
			newInst = &JumpSignedGreaterThanOrEqualRegister{JumpSignedGreaterThanOrEqualRegister: *inst}
		case *ebpf.JumpSignedGreaterThanOrEqualRegister32:
			newInst = &JumpSignedGreaterThanOrEqualRegister32{JumpSignedGreaterThanOrEqualRegister32: *inst}
		case *ebpf.JumpSignedGreaterThan:
			newInst = &JumpSignedGreaterThan{JumpSignedGreaterThan: *inst}
		case *ebpf.JumpSignedGreaterThan32:
			newInst = &JumpSignedGreaterThan32{JumpSignedGreaterThan32: *inst}
		case *ebpf.JumpSignedGreaterThanRegister:
			newInst = &JumpSignedGreaterThanRegister{JumpSignedGreaterThanRegister: *inst}
		case *ebpf.JumpSignedGreaterThanRegister32:
			newInst = &JumpSignedGreaterThanRegister32{JumpSignedGreaterThanRegister32: *inst}
		case *ebpf.JumpSignedSmallerThanOrEqual:
			newInst = &JumpSignedSmallerThanOrEqual{JumpSignedSmallerThanOrEqual: *inst}
		case *ebpf.JumpSignedSmallerThanOrEqual32:
			newInst = &JumpSignedSmallerThanOrEqual32{JumpSignedSmallerThanOrEqual32: *inst}
		case *ebpf.JumpSignedSmallerThanOrEqualRegister:
			newInst = &JumpSignedSmallerThanOrEqualRegister{JumpSignedSmallerThanOrEqualRegister: *inst}
		case *ebpf.JumpSignedSmallerThanOrEqualRegister32:
			newInst = &JumpSignedSmallerThanOrEqualRegister32{JumpSignedSmallerThanOrEqualRegister32: *inst}
		case *ebpf.JumpSignedSmallerThan:
			newInst = &JumpSignedSmallerThan{JumpSignedSmallerThan: *inst}
		case *ebpf.JumpSignedSmallerThan32:
			newInst = &JumpSignedSmallerThan32{JumpSignedSmallerThan32: *inst}
		case *ebpf.JumpSignedSmallerThanRegister:
			newInst = &JumpSignedSmallerThanRegister{JumpSignedSmallerThanRegister: *inst}
		case *ebpf.JumpSignedSmallerThanRegister32:
			newInst = &JumpSignedSmallerThanRegister32{JumpSignedSmallerThanRegister32: *inst}
		case *ebpf.LoadConstant64bit:
			newInst = &LoadConstant64bit{LoadConstant64bit: *inst}
		case *ebpf.LoadMemory:
			newInst = &LoadMemory{LoadMemory: *inst}
		case *ebpf.LoadSocketBuf:
			newInst = &LoadSocketBuf{LoadSocketBuf: *inst}
		case *ebpf.LoadSocketBufConstant:
			newInst = &LoadSocketBufConstant{LoadSocketBufConstant: *inst}
		case *ebpf.Lsh32:
			newInst = &Lsh32{Lsh32: *inst}
		case *ebpf.Lsh64:
			newInst = &Lsh64{Lsh64: *inst}
		case *ebpf.Lsh32Register:
			newInst = &Lsh32Register{Lsh32Register: *inst}
		case *ebpf.Lsh64Register:
			newInst = &Lsh64Register{Lsh64Register: *inst}
		case *ebpf.Mod32:
			newInst = &Mod32{Mod32: *inst}
		case *ebpf.Mod64:
			newInst = &Mod64{Mod64: *inst}
		case *ebpf.Mod32Register:
			newInst = &Mod32Register{Mod32Register: *inst}
		case *ebpf.Mod64Register:
			newInst = &Mod64Register{Mod64Register: *inst}
		case *ebpf.Mov32:
			newInst = &Mov32{Mov32: *inst}
		case *ebpf.Mov64:
			newInst = &Mov64{Mov64: *inst}
		case *ebpf.Mov32Register:
			newInst = &Mov32Register{Mov32Register: *inst}
		case *ebpf.Mov64Register:
			newInst = &Mov64Register{Mov64Register: *inst}
		case *ebpf.Mul32:
			newInst = &Mul32{Mul32: *inst}
		case *ebpf.Mul64:
			newInst = &Mul64{Mul64: *inst}
		case *ebpf.Mul32Register:
			newInst = &Mul32Register{Mul32Register: *inst}
		case *ebpf.Mul64Register:
			newInst = &Mul64Register{Mul64Register: *inst}
		case *ebpf.Neg32:
			newInst = &Neg32{Neg32: *inst}
		case *ebpf.Neg64:
			newInst = &Neg64{Neg64: *inst}
		case *ebpf.Nop:
			newInst = &Nop{Nop: *inst}
		case *ebpf.Or32:
			newInst = &Or32{Or32: *inst}
		case *ebpf.Or64:
			newInst = &Or64{Or64: *inst}
		case *ebpf.Or32Register:
			newInst = &Or32Register{Or32Register: *inst}
		case *ebpf.Or64Register:
			newInst = &Or64Register{Or64Register: *inst}
		case *ebpf.Rsh32:
			newInst = &Rsh32{Rsh32: *inst}
		case *ebpf.Rsh64:
			newInst = &Rsh64{Rsh64: *inst}
		case *ebpf.Rsh32Register:
			newInst = &Rsh32Register{Rsh32Register: *inst}
		case *ebpf.Rsh64Register:
			newInst = &Rsh64Register{Rsh64Register: *inst}
		case *ebpf.StoreMemoryConstant:
			newInst = &StoreMemoryConstant{StoreMemoryConstant: *inst}
		case *ebpf.StoreMemoryRegister:
			newInst = &StoreMemoryRegister{StoreMemoryRegister: *inst}
		case *ebpf.Sub32:
			newInst = &Sub32{Sub32: *inst}
		case *ebpf.Sub64:
			newInst = &Sub64{Sub64: *inst}
		case *ebpf.Sub32Register:
			newInst = &Sub32Register{Sub32Register: *inst}
		case *ebpf.Sub64Register:
			newInst = &Sub64Register{Sub64Register: *inst}
		case *ebpf.Xor32:
			newInst = &Xor32{Xor32: *inst}
		case *ebpf.Xor64:
			newInst = &Xor64{Xor64: *inst}
		case *ebpf.Xor32Register:
			newInst = &Xor32Register{Xor32Register: *inst}
		case *ebpf.Xor64Register:
			newInst = &Xor64Register{Xor64Register: *inst}
		default:
			return nil, fmt.Errorf("can't translate instruction at %d of type %T", i, inst)
		}

		vmProg[i] = newInst
	}

	return vmProg, nil
}

func readReg(vm *VM, reg ebpf.Register) (int64, RegisterValue, error) {
	r, err := vm.Registers.Get(reg)
	if err != nil {
		return 0, r, fmt.Errorf("get %s: %w", reg.String(), err)
	}

	return r.Value(), r, err
}

func isIMM(r RegisterValue) bool {
	_, ok := r.(*IMMValue)
	return ok
}

func sameRVType(a, b RegisterValue) bool {
	at := reflect.TypeOf(a)
	bt := reflect.TypeOf(b)
	return at == bt
}
