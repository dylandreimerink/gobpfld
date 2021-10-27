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

type KprobeOpts struct {
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

func (opts KprobeOpts) kprobeConfig() string {
	probeConfig := "p"

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
	probeEvents, err := openEvents()
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

func (kp KProbe) openEnable() (*os.File, error) {
	return os.OpenFile(path.Join(debugfs, eventsPath, "kprobes", kp.Name, "enable"), os.O_WRONLY|os.O_APPEND, 0)
}

func (kp KProbe) Enable() error {
	kprobeEnable, err := kp.openEnable()
	if err != nil {
		return fmt.Errorf("unable to open kprobe enable: %w", err)
	}
	defer kprobeEnable.Close()

	_, err = kprobeEnable.Write([]byte("1"))
	if err != nil {
		return fmt.Errorf("enable kprobe: %w", err)
	}

	return nil
}

func (kp KProbe) Disable() error {
	kprobeEnable, err := kp.openEnable()
	if err != nil {
		return fmt.Errorf("unable to open kprobe enable: %w", err)
	}
	defer kprobeEnable.Close()

	_, err = kprobeEnable.Write([]byte("0"))
	if err != nil {
		return fmt.Errorf("enable kprobe: %w", err)
	}

	return nil
}

func openEvents() (*os.File, error) {
	return os.OpenFile(path.Join(debugfs, "tracing/kprobe_events"), os.O_WRONLY|os.O_APPEND, 0)
}

// newKProbe creates a new kprobe event, if successful the ID of the new kprobe is returned
func newKProbe(opts KprobeOpts) (*KProbe, error) {
	if opts.Event == "" || opts.Symbol == "" {
		return nil, errors.New("'Event' and 'Symbol' options are required")
	}

	probeEvents, err := openEvents()
	if err != nil {
		return nil, fmt.Errorf("open kprobe_events: %w", err)
	}
	defer probeEvents.Close()

	_, err = probeEvents.Write([]byte(opts.kprobeConfig()))
	if err != nil {
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

// TODO create kprobe struct which holds the ID
//   TODO create enable/disable method
//   TODO create remove method
