package emulator

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dylandreimerink/gobpfld/ebpf"
)

// VM is a virtual machine which can run eBPF code.
type VM struct {
	settings VMSettings

	Registers Registers
	// A slice of frames, each frame is represented by a byte slice
	StackFrames [][]byte

	// A slice of eBPF programs
	Programs [][]Instruction
}

func NewVM(settings VMSettings) (*VM, error) {
	// TODO settings validation

	vm := &VM{
		settings: settings,
	}

	// Reset will make the VM ready to start execution of a program
	vm.Reset()

	return vm, nil
}

func (vm *VM) AddProgram(prog []ebpf.Instruction) error {
	vmProg, err := Translate(prog)
	if err != nil {
		return fmt.Errorf("translate: %w", err)
	}

	vm.Programs = append(vm.Programs, vmProg)

	return nil
}

func (vm *VM) AddRawProgram(prog []ebpf.RawInstruction) error {
	inst, err := ebpf.Decode(prog)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	err = vm.AddProgram(inst)
	if err != nil {
		return fmt.Errorf("add program: %w", err)
	}

	return nil
}

func (vm *VM) SetEntrypoint(index int) error {
	if len(vm.Programs) <= index {
		return fmt.Errorf("program index out of bounds")
	}

	vm.Registers.PI = index

	return nil
}

func (vm *VM) Run() error {
	return vm.RunContext(context.Background())
}

var errInvalidProgramCount = errors.New("program counter points to non-existent instruction, bad jump of missing " +
	"exit instruction")

func (vm *VM) RunContext(ctx context.Context) error {
	for {
		stop, err := vm.Step()
		if err != nil {
			return err
		}
		if stop {
			break
		}

		// If context was canceled or deadline exceeded, stop execution
		if err = ctx.Err(); err != nil {
			return vm.err(err)
		}
	}

	return nil
}

// Step executes a single instruction, allowing us to "step" through the program
func (vm *VM) Step() (stop bool, err error) {
	program := vm.Programs[vm.Registers.PI]
	inst := program[vm.Registers.PC]
	// Store the program count of the current instruction
	pc := vm.Registers.PC
	err = inst.Execute(vm)
	if err != nil {
		// If not errExit, it is a runtime error
		if err != errExit {
			return true, vm.err(err)
		}

		// TODO return from bpf-to-bpf

		return true, nil
	}

	if len(program) <= vm.Registers.PC+1 {
		// reset PC so it points to the offending instruction.
		vm.Registers.PC = pc

		return true, vm.err(errInvalidProgramCount)
	}

	// Increment the program counter
	vm.Registers.PC++

	return false, nil
}

func (vm *VM) err(err error) *VMError {
	return &VMError{
		VMSnapshot: vm.Clone(),
		Original:   err,
	}
}

// Clone clones the whole VM, this includes the current state of the VM. This feature can be used to create snapshots
// of the VM.
func (vm *VM) Clone() *VM {
	clone := &VM{
		settings: vm.settings,
		Programs: make([][]Instruction, len(vm.Programs)),
	}
	// Reset will make new stack frames
	clone.Reset()

	clone.Registers = vm.Registers.Clone()

	// Copy the stack frames
	for i := range clone.StackFrames {
		copy(clone.StackFrames[i], vm.StackFrames[i])
	}

	// Copy the programs
	for i := range clone.Programs {
		clone.Programs[i] = make([]Instruction, len(vm.Programs[i]))
		for j := range clone.Programs[i] {
			clone.Programs[i][j] = vm.Programs[i][j].Clone()
		}
	}

	return clone
}

func (vm *VM) Reset() {
	vm.Registers.PC = 0
	vm.Registers.SF = 0
	vm.Registers.R0 = newIMM(0)
	vm.Registers.R1 = newIMM(0)
	vm.Registers.R2 = newIMM(0)
	vm.Registers.R3 = newIMM(0)
	vm.Registers.R4 = newIMM(0)
	vm.Registers.R5 = newIMM(0)
	vm.Registers.R6 = newIMM(0)
	vm.Registers.R7 = newIMM(0)
	vm.Registers.R8 = newIMM(0)
	vm.Registers.R9 = newIMM(0)

	if vm.StackFrames == nil {
		vm.StackFrames = make([][]byte, vm.settings.MaxStackFrames)
	}

	for i := range vm.StackFrames {
		if vm.StackFrames[i] == nil {
			vm.StackFrames[i] = make([]byte, vm.settings.StackFrameSize)
			continue
		}
		// Zero out the stack frames
		for j := range vm.StackFrames[i] {
			vm.StackFrames[i][j] = 0
		}
	}

	vm.Registers.R10 = FramePointer{
		Memory:   vm.StackFrames[0],
		Offset:   0,
		Readonly: true,
	}
}

func (vm *VM) String() string {
	var sb strings.Builder
	sb.WriteString("Registers:\n")

	r := vm.Registers
	sb.WriteString(fmt.Sprintf(" PC: %d -> %s\n", r.PC, vm.Programs[r.PI][r.PC].String()))
	// TODO add program name, as soon as we have that available
	sb.WriteString(fmt.Sprintf(" PI: %d\n", r.PI))
	sb.WriteString(fmt.Sprintf(" SF: %d\n", r.SF))
	sb.WriteString(fmt.Sprintf(" r0: %s\n", r.R0))
	sb.WriteString(fmt.Sprintf(" r1: %s\n", r.R1))
	sb.WriteString(fmt.Sprintf(" r2: %s\n", r.R2))
	sb.WriteString(fmt.Sprintf(" r3: %s\n", r.R3))
	sb.WriteString(fmt.Sprintf(" r4: %s\n", r.R4))
	sb.WriteString(fmt.Sprintf(" r5: %s\n", r.R5))
	sb.WriteString(fmt.Sprintf(" r6: %s\n", r.R6))
	sb.WriteString(fmt.Sprintf(" r7: %s\n", r.R7))
	sb.WriteString(fmt.Sprintf(" r8: %s\n", r.R8))
	sb.WriteString(fmt.Sprintf(" r9: %s\n", r.R9))
	sb.WriteString(fmt.Sprintf("r10: %s\n", &r.R10))

	return sb.String()
}

// A VMError is thrown by the VM and contain a copy of the state of the VM at the time of the error
type VMError struct {
	VMSnapshot *VM
	Original   error
}

func (e *VMError) Error() string {
	return fmt.Sprintf("vm error: %s", e.Original)
}

type VMSettings struct {
	// StackFrameSize is the allocated size of a single stack frame
	StackFrameSize int
	// MaxStackFrames is the maximum number of stack frames
	MaxStackFrames int
}

// DefaultVMSettings returns good default settings for the VM, they are based on the limitations of the Linux eBPF
// implementation
func DefaultVMSettings() VMSettings {
	return VMSettings{
		StackFrameSize: 256,
		MaxStackFrames: 8,
	}
}
