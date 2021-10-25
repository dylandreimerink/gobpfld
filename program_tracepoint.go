package gobpfld

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/perf"
)

var _ BPFProgram = (*ProgramTracepoint)(nil)

type ProgramTracepoint struct {
	AbstractBPFProgram

	// DefaultCategory is the tracepoint category used if no category is specified during attaching.
	// It can be set when loading from ELF file.
	DefaultCategory string
	// DefaultName is the tracepoint name used if no name is specified during attaching.
	// It can be set when loading from ELF file.
	DefaultName string

	attachedEvent *perf.Event
}

type ProgTPLoadOpts struct {
	VerifierLogLevel bpftypes.BPFLogLevel
	VerifierLogSize  int
}

func (p *ProgramTracepoint) Load(opts ProgTPLoadOpts) (log string, err error) {
	return p.load(bpfsys.BPFAttrProgramLoad{
		LogLevel: opts.VerifierLogLevel,
		LogSize:  uint32(opts.VerifierLogSize),
	})
}

// Unpin captures the file descriptor of the program at the given 'relativePath' from the kernel.
// If 'deletePin' is true the bpf FS pin will be removed after successfully loading the program, thus transferring
// ownership of the program in a scenario where the program is not shared between multiple userspace programs.
// Otherwise the pin will keep existing which will cause the map to not be deleted when this program exits.
func (p *ProgramTracepoint) Unpin(relativePath string, deletePin bool) error {
	return p.unpin(relativePath, deletePin)
}

type ProgTPAttachOpts struct {
	Category string
	Name     string
}

func (p *ProgramTracepoint) Attach(opts ProgTPAttachOpts) error {
	category := p.DefaultCategory
	if opts.Category != "" {
		category = opts.Category
	}

	name := p.DefaultName
	if opts.Category != "" {
		name = opts.Name
	}

	var err error
	p.attachedEvent, err = perf.OpenTracepointEvent(category, name)
	if err != nil {
		return fmt.Errorf("open tracepoint: %w", err)
	}

	err = p.attachedEvent.AttachBPFProgram(p.fd)
	if err != nil {
		return fmt.Errorf("attach program: %w", err)
	}

	return nil
}

func (p *ProgramTracepoint) Detach() error {
	return p.attachedEvent.DetachBPFProgram()
}
