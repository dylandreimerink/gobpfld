package perf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
)

// This file contains debugfs (/sys/kernel/debug) related code.

const (
	debugfs    = "/sys/kernel/debug"
	eventsPath = "tracing/events"
)

// getTracepointID returns the ID of a tracepoint.
// If the function returns permission errors the program is not being run a user with the correct permissions.
// If the function returns os.ErrNotExist the given tracepoint doesn't exist
func getTracepointID(category, name string) (int, error) {
	file, err := os.OpenFile(path.Join(debugfs, eventsPath, category, name, "id"), os.O_RDONLY, 0)
	if err != nil {
		return -1, fmt.Errorf("open file: %w", err)
	}

	contents, err := io.ReadAll(file)
	if err != nil {
		return -1, fmt.Errorf("read file: %w", err)
	}

	return strconv.Atoi(strings.TrimSpace(string(contents)))
}

type ProbeType int

const (
	// TypeUnknown is the default value for the KProbeType
	TypeUnknown ProbeType = iota
	// TypeKProbe means a kprobe triggers on the beginning of a function/symbol
	TypeKProbe
	// TypeKRetprobe means a krprobe trigger on the end/return of a function/symbol
	TypeKRetprobe
	// TypeUProbe means a uprobe triggers on the beginning of a function/symbol
	TypeUProbe
	// TypeURetProbe means a uprobe trigger on the end/return of a function/symbol
	TypeURetProbe
)

type KProbeOpts struct {
	Type ProbeType
	// Group name. If omitted, use "kprobes" for it.
	Group string
	// Event name. If omitted, the event name is generated
	// based on SYM+offs or MEMADDR.
	Event string

	// Module name which has given Symbol.
	Module string
	// Symbol+Offset where the probe is inserted.
	Symbol string
}

func (opts KProbeOpts) kprobeConfig() string {
	probeConfig := "p"
	if opts.Type == TypeKRetprobe {
		probeConfig = "r"
	}

	if opts.Event != "" {
		probeConfig = probeConfig + ":"
		if opts.Group != "" {
			probeConfig = opts.Group + "/"
		}
		probeConfig = probeConfig + opts.Event + " "
	}

	if opts.Module != "" {
		probeConfig += opts.Module + ":"
	}
	probeConfig += opts.Symbol

	return probeConfig
}

type KProbe struct {
	Name string
	ID   int
}

func (kp KProbe) Clear() error {
	probeEvents, err := openKProbeEvents()
	if err != nil {
		return fmt.Errorf("open kprobe_events: %w", err)
	}
	defer probeEvents.Close()

	_, err = probeEvents.Write([]byte("-:" + kp.Name))
	if err != nil {
		return fmt.Errorf("write kprobe_events: %w", err)
	}

	return nil
}

func openKProbeEvents() (*os.File, error) {
	return os.OpenFile(path.Join(debugfs, "tracing/kprobe_events"), os.O_WRONLY|os.O_APPEND, 0)
}

// newKProbe creates a new kprobe event, if successful the ID of the new kprobe is returned
func newKProbe(opts KProbeOpts) (*KProbe, error) {
	if opts.Event == "" || opts.Symbol == "" {
		return nil, errors.New("'Event' and 'Symbol' options are required")
	}

	probeEvents, err := openKProbeEvents()
	if err != nil {
		return nil, fmt.Errorf("open kprobe_events: %w", err)
	}
	defer probeEvents.Close()

	_, err = probeEvents.Write([]byte(opts.kprobeConfig()))
	if err != nil {
		// TODO handle event naming conflicts
		return nil, fmt.Errorf("write kprobe_events: %w", err)
	}

	idBytes, err := os.ReadFile(path.Join(debugfs, eventsPath, "kprobes", opts.Event, "id"))
	if err != nil {
		return nil, fmt.Errorf("unable to find created kprobe: %w", err)
	}

	id, err := strconv.Atoi(strings.TrimSpace(string(idBytes)))
	if err != nil {
		return nil, fmt.Errorf("atoi: %w", err)
	}

	return &KProbe{
		Name: opts.Event,
		ID:   id,
	}, nil
}

type UProbeOpts struct {
	Type ProbeType
	// Group name. If omitted, use "kprobes" for it.
	Group string
	// Event name. If omitted, the event name is generated
	// based on SYM+offs or MEMADDR.
	Event string

	// Path is the path to the executable to be probed.
	Path string
	// Offset of the address to be be probed.
	Offset int
}

func (opts UProbeOpts) uprobeConfig() string {
	probeConfig := "p"
	if opts.Type == TypeURetProbe {
		probeConfig = "r"
	}

	if opts.Event != "" {
		probeConfig = probeConfig + ":"
		if opts.Group != "" {
			probeConfig = opts.Group + "/"
		}
		probeConfig = probeConfig + opts.Event + " "
	}

	probeConfig += fmt.Sprintf("%s:0x%x", opts.Path, opts.Offset)

	return probeConfig
}

type UProbe struct {
	Name string
	ID   int
}

func (kp UProbe) Clear() error {
	probeEvents, err := openUProbeEvents()
	if err != nil {
		return fmt.Errorf("open uprobe_events: %w", err)
	}
	defer probeEvents.Close()

	_, err = probeEvents.Write([]byte("-:" + kp.Name))
	if err != nil {
		return fmt.Errorf("write uprobe_events: %w", err)
	}

	return nil
}

func openUProbeEvents() (*os.File, error) {
	return os.OpenFile(path.Join(debugfs, "tracing/uprobe_events"), os.O_WRONLY|os.O_APPEND, 0)
}

// newUProbe creates a new uprobe event, if successful the ID of the new uprobe is returned
func newUProbe(opts UProbeOpts) (*UProbe, error) {
	if opts.Event == "" || opts.Path == "" {
		return nil, errors.New("'Event' and 'Path' options are required")
	}

	probeEvents, err := openUProbeEvents()
	if err != nil {
		return nil, fmt.Errorf("open uprobe_events: %w", err)
	}
	defer probeEvents.Close()

	_, err = probeEvents.Write([]byte(opts.uprobeConfig()))
	if err != nil {
		// TODO handle event naming conflicts
		return nil, fmt.Errorf("write uprobe_events: %w", err)
	}

	idBytes, err := os.ReadFile(path.Join(debugfs, eventsPath, "uprobes", opts.Event, "id"))
	if err != nil {
		return nil, fmt.Errorf("unable to find created uprobe: %w", err)
	}

	id, err := strconv.Atoi(strings.TrimSpace(string(idBytes)))
	if err != nil {
		return nil, fmt.Errorf("atoi: %w", err)
	}

	return &UProbe{
		Name: opts.Event,
		ID:   id,
	}, nil
}
