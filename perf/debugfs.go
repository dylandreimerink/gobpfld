package perf

import (
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
)

// This file contains debugfs (/sys/kernel/debug) related code.

const (
	debugfs     = "/sys/kernel/debug"
	tracingPath = "tracing/events"
)

// getTracepointID returns the ID of a tracepoint.
// If the function returns permission errors the program is not being run a user with the correct permissions.
// If the function returns os.ErrNotExist the given tracepoint doesn't exist
func getTracepointID(category, name string) (int, error) {
	file, err := os.OpenFile(path.Join(debugfs, tracingPath, category, name, "id"), os.O_RDONLY, 0)
	if err != nil {
		return -1, fmt.Errorf("open file: %w", err)
	}

	contents, err := io.ReadAll(file)
	if err != nil {
		return -1, fmt.Errorf("read file: %w", err)
	}

	return strconv.Atoi(strings.TrimSpace(string(contents)))
}

// TODO create kprobe struct which holds the ID
//   TODO create enable/disable method
//   TODO create remove method
