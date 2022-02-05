package emulator

import (
	"errors"
	"fmt"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/ebpf"
)

// HelperFunc are functions in go space which can be called from the eBPF VM. They are used expand eBPF capabilities
// without giving the VM direct access, much like a syscall in an OS context.
// A helper function by convention will return a single value in R0, is passed R1-R5 as arguments and should never
// touch R6-R9. A helper can gracefully return an error via R0, returning an error from the Go function means there
// is no graceful way to handle the error and will cause the VM to abort execution.
type HelperFunc func(vm *VM) error

// LinuxHelperFunctions returns a helper function array of helper functions which are compatible with the linux
// helper functions as defined in https://github.com/libbpf/libbpf/blob/master/src/bpf_helper_defs.h
func LinuxHelperFunctions() []HelperFunc {
	const maxLinuxHelperNum = 191
	funcs := make([]HelperFunc, maxLinuxHelperNum+1)

	// Helper func 0 doesn't exist
	funcs[0] = nil
	funcs[1] = MapLookupElement
	funcs[2] = MapUpdateElement
	funcs[3] = MapDeleteElement
	funcs[12] = TailCall
	funcs[14] = GetCurrentPidTgid
	funcs[25] = PerfEventOutput
	// ...191

	return funcs
}

// MapLookupElement implements the bpf_map_lookup_element helper
func MapLookupElement(vm *VM) error {
	// R1 = id/fd of the map, R2 = pointer to key value
	m, err := regToMap(vm, vm.Registers.R1)
	if err != nil {
		return err
	}
	if m == nil {
		return nil
	}

	val, err := m.Lookup(vm.Registers.R2)
	if err != nil {
		switch err {
		case errMapKeyNoPtr, errMapValNoPtr:
			val = efault()
		case errMapOutOfMemory:
			val = e2big()
		case errMapNotImplemented:
			val = eperm()
		default:
			return fmt.Errorf("lookup: %w", err)
		}
	}

	vm.Registers.R0 = val

	return nil
}

// MapUpdateElement implements the bpf_map_update_element helper
func MapUpdateElement(vm *VM) error {
	m, err := regToMap(vm, vm.Registers.R1)
	if err != nil {
		return err
	}
	if m == nil {
		return nil
	}

	val, err := m.Update(vm.Registers.R2, vm.Registers.R3, bpfsys.BPFAttrMapElemFlags(vm.Registers.R4.Value()))
	if err != nil {
		switch err {
		case errMapKeyNoPtr, errMapValNoPtr:
			val = efault()
		case errMapOutOfMemory:
			val = e2big()
		case errMapNotImplemented:
			val = eperm()
		default:
			return fmt.Errorf("update: %w", err)
		}
	}

	vm.Registers.R0 = val
	return nil
}

// MapDeleteElement implements the bpf_map_delete_element helper
func MapDeleteElement(vm *VM) error {
	return errors.New("not yet implemented")
}

// Convert a register values passed into a helper to the actual map
func regToMap(vm *VM, reg RegisterValue) (Map, error) {
	mapIdx := reg.Value()

	// If R1 is a pointer, not a value, we should dereference it.
	// Pointers can still be valid, usually they are passed when the id/fd comes from a map-in-map type map.
	if ptr, ok := reg.(*MemoryPtr); ok {
		// Deref as 32 bit, which is always the size of an id/fd
		mapIdxVal, err := ptr.Deref(0, ebpf.BPF_W)
		if err != nil {
			return nil, fmt.Errorf("deref ptr to map idx: %w", err)
		}

		mapIdx = mapIdxVal.Value()
	}

	if mapIdx < 1 || int(mapIdx) >= len(vm.Maps) {
		vm.Registers.R0 = newIMM(0)
		return nil, nil
	}

	return vm.Maps[mapIdx], nil
}

// TailCall implements the bpf_tail_call helper
func TailCall(vm *VM) error {
	// R1 = ctx, R2 = map fd(of prog_array), R3 = index in map (key for the program to execute)
	mapIdx := vm.Registers.R2.Value()
	if mapIdx < 1 || int(mapIdx) >= len(vm.Maps) {
		vm.Registers.R0 = efault()
		return nil
	}

	// This helper only works for PROG arrays
	m := vm.Maps[mapIdx]
	if m.GetDef().Type != bpftypes.BPF_MAP_TYPE_PROG_ARRAY {
		vm.Registers.R0 = efault()
		return nil
	}

	k := &MemoryPtr{
		Memory: &ValueMemory{
			Mapping: []RegisterValue{
				vm.Registers.R3,
				vm.Registers.R3,
				vm.Registers.R3,
				vm.Registers.R3,
			},
		},
	}

	// Lookup the value
	val := newIMM(0)
	valReg, err := m.Lookup(k)
	if err != nil {
		switch err {
		case errMapKeyNoPtr, errMapValNoPtr:
			val = efault()
		case errMapOutOfMemory:
			val = e2big()
		case errMapNotImplemented:
			val = eperm()
		default:
			return fmt.Errorf("lookup: %w", err)
		}

		vm.Registers.R0 = val
		return nil
	}

	valPtr, ok := valReg.(PointerValue)
	if !ok {
		return fmt.Errorf("lookup didn't return a pointer")
	}

	valVar, err := valPtr.Deref(0, ebpf.BPF_W)
	if err != nil {
		return fmt.Errorf("deref value pointer: %w", err)
	}

	progIdx := valVar.Value()
	if len(vm.Programs) < int(progIdx) {
		vm.Registers.R0 = efault()
		return nil
	}

	if progIdx == 0 {
		return fmt.Errorf("no program loaded at index 0")
	}

	// On success, change the current program index
	vm.Registers.PI = int(progIdx)
	// Change the instruction pointer to -1, since after this helper call the PC will be incremented so we will end
	// up at a PC of 0
	vm.Registers.PC = -1
	// Don't reset the VM since we want to preserve the memory and register state.
	// Not that, because the ctx was passed as the first argument to this function it lives in the R1 register
	// where the next program will expect it to be, this is free, no need to manually set the correct ctx.

	// Set the return value to 0, for success
	vm.Registers.R0 = val
	return nil
}

// GetCurrentPidTgid implements the bpf_get_current_pid_tgid helper
func GetCurrentPidTgid(vm *VM) error {
	// TODO replace const value with value gotten from dynamic context of VM as soon as this feature is added.
	return vm.Registers.Assign(ebpf.BPF_REG_0, newIMM(1234<<32+5678))
}

// PerfEventOutput implements the bpf_perf_event_output helper
func PerfEventOutput(vm *VM) error {
	// R1 = ctx, R2 = map index, R3 = flags, R4 = data, R5 = size
	mapIdx := vm.Registers.R2.Value()
	if mapIdx < 1 || int(mapIdx) >= len(vm.Maps) {
		vm.Registers.R0 = efault()
		return nil
	}

	m := vm.Maps[mapIdx]
	pa, ok := m.(*PerfEventArray)
	if !ok {
		vm.Registers.R0 = efault()
		return nil
	}

	val := newIMM(0)
	err := pa.Push(vm.Registers.R4, vm.Registers.R5.Value())
	if err != nil {
		switch err {
		case errMapKeyNoPtr, errMapValNoPtr:
			val = efault()
		case errMapOutOfMemory:
			val = e2big()
		case errMapNotImplemented:
			val = eperm()
		default:
			return fmt.Errorf("push: %w", err)
		}
	}

	vm.Registers.R0 = val

	return nil
}
