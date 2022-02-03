package emulator

import (
	"errors"
	"fmt"

	"github.com/dylandreimerink/gobpfld/bpfsys"
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
	// 4...13
	funcs[14] = GetCurrentPidTgid
	// 15...24
	funcs[25] = PerfEventOutput
	// 26...191

	return funcs
}

// MapLookupElement implements the bpf_map_lookup_element helper
func MapLookupElement(vm *VM) error {
	mapIdx := vm.Registers.R1.Value()
	if int(mapIdx) >= len(vm.Maps) {
		vm.Registers.R0 = newIMM(0)
		return nil
	}

	m := vm.Maps[mapIdx]
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
	mapIdx := vm.Registers.R1.Value()
	if int(mapIdx) >= len(vm.Maps) {
		vm.Registers.R0 = efault()
		return nil
	}

	m := vm.Maps[mapIdx]
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

// GetCurrentPidTgid implements the bpf_get_current_pid_tgid helper
func GetCurrentPidTgid(vm *VM) error {
	// TODO replace const value with value gotten from dynamic context of VM as soon as this feature is added.
	return vm.Registers.Assign(ebpf.BPF_REG_0, newIMM(1234<<32+5678))
}

// PerfEventOutput implements the bpf_perf_event_output helper
func PerfEventOutput(vm *VM) error {
	// R1 = ctx, R2 = map index, R3 = flags, R4 = data, R5 = size
	mapIdx := vm.Registers.R2.Value()
	if int(mapIdx) >= len(vm.Maps) {
		vm.Registers.R0 = efault()
		return nil
	}

	m := vm.Maps[mapIdx]
	pa, ok := m.(*PerfEventArray)
	if !ok {
		vm.Registers.R0 = efault()
		return nil
	}

	var val RegisterValue
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
