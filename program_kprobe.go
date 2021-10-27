package gobpfld

import (
	"fmt"

	"github.com/dylandreimerink/gobpfld/bpfsys"
	"github.com/dylandreimerink/gobpfld/bpftypes"
	"github.com/dylandreimerink/gobpfld/perf"
)

var _ BPFProgram = (*ProgramKProbe)(nil)

type ProgramKProbe struct {
	AbstractBPFProgram

	// DefaultCategory is the kprobe group used if no group is specified during attaching.
	// It can be set when loading from ELF file.
	DefaultGroup string
	// DefaultName is the kprobe event used if no event is specified during attaching.
	// It can be set when loading from ELF file.
	DefaultEvent  string
	DefaultModule string
	DefaultSymbol string

	attachedEvent *perf.Event
}

type ProgKPLoadOpts struct {
	VerifierLogLevel bpftypes.BPFLogLevel
	VerifierLogSize  int
}

func (p *ProgramKProbe) Load(opts ProgKPLoadOpts) (log string, err error) {
	return p.load(bpfsys.BPFAttrProgramLoad{
		LogLevel: opts.VerifierLogLevel,
		LogSize:  uint32(opts.VerifierLogSize),
	})
}

// Unpin captures the file descriptor of the program at the given 'relativePath' from the kernel.
// If 'deletePin' is true the bpf FS pin will be removed after successfully loading the program, thus transferring
// ownership of the program in a scenario where the program is not shared between multiple userspace programs.
// Otherwise the pin will keep existing which will cause the map to not be deleted when this program exits.
func (p *ProgramKProbe) Unpin(relativePath string, deletePin bool) error {
	return p.unpin(relativePath, deletePin)
}

type ProgKPAttachOpts struct {
	perf.KprobeOpts
}

func (p *ProgramKProbe) Attach(opts ProgKPAttachOpts) error {
	kprobeOpts := perf.KprobeOpts{
		Group:  p.DefaultGroup,
		Event:  p.DefaultEvent,
		Module: p.DefaultModule,
		Symbol: p.DefaultSymbol,
	}

	if opts.Group != "" {
		kprobeOpts.Group = opts.Group
	}

	if opts.Event != "" {
		kprobeOpts.Event = opts.Event
	}

	if opts.Module != "" {
		kprobeOpts.Module = opts.Module
	}

	if opts.Symbol != "" {
		kprobeOpts.Symbol = opts.Symbol
	}

	var err error
	p.attachedEvent, err = perf.OpenKProbeEvent(kprobeOpts)
	if err != nil {
		return fmt.Errorf("open tracepoint: %w", err)
	}

	err = p.attachedEvent.AttachBPFProgram(p.fd)
	if err != nil {
		return fmt.Errorf("attach program: %w", err)
	}

	return nil
}

func (p *ProgramKProbe) Detach() error {
	return p.attachedEvent.DetachBPFProgram()
}
