package emulator

import (
	"errors"
	"fmt"
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
	return []HelperFunc{
		nil,              // Helper func 0 doesn't exist
		MapLookupElement, // 1
		MapUpdateElement, // 2
		MapDeleteElement, // 3
	}
}

// MapLookupElement implements the bpf_map_lookup_element helper
func MapLookupElement(vm *VM) error {
	mapIdx := vm.Registers.R1.Value()
	if int(mapIdx) >= len(vm.Maps) {
		vm.Registers.R0 = newIMM(0)
	}

	m := vm.Maps[mapIdx]
	val, err := m.Lookup(vm.Registers.R2)
	if err != nil {
		return fmt.Errorf("lookup: %w", err)
	}

	vm.Registers.R0 = val

	return nil
}

// MapUpdateElement implements the bpf_map_update_element helper
func MapUpdateElement(vm *VM) error {
	return errors.New("not yet implemented")
}

// MapDeleteElement implements the bpf_map_delete_element helper
func MapDeleteElement(vm *VM) error {
	return errors.New("not yet implemented")
}
