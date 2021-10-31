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

	DefaultType perf.ProbeType
	// DefaultCategory is the kprobe group used if no group is specified during attaching.
	// It can be set when loading from ELF file.
	DefaultGroup string
	// DefaultName is the kprobe event used if no event is specified during attaching.
	// It can be set when loading from ELF file.
	DefaultEvent  string
	DefaultModule string
	DefaultSymbol string
	DefaultPath   string
	DefaultOffset int

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
	Type perf.ProbeType
	// Group name. If omitted, use "kprobes" for it.
	Group string
	// Event name. If omitted, the event name is generated
	// based on SYM+offs or MEMADDR.
	Event string

	// Module name which has given Symbol.
	Module string
	// Symbol+Offset where the probe is inserted.
	Symbol string
	// Path is the path to the executable to be probed.
	Path string
	// Offset of the address to be be probed.
	Offset int
}

func (p *ProgramKProbe) Attach(opts ProgKPAttachOpts) error {
	t := p.DefaultType
	if opts.Type != perf.TypeUnknown {
		t = opts.Type
	}

	if t == perf.TypeUnknown {
		return fmt.Errorf("unknown probe type")
	}

	switch t {
	case perf.TypeKProbe, perf.TypeKRetprobe:
		kprobeOpts := perf.KProbeOpts{
			Type:   t,
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
			return fmt.Errorf("open kprobe: %w", err)
		}

	case perf.TypeUProbe, perf.TypeURetProbe:
		uprobeOpts := perf.UProbeOpts{
			Type:   t,
			Group:  p.DefaultGroup,
			Event:  p.DefaultEvent,
			Path:   p.DefaultPath,
			Offset: p.DefaultOffset,
		}

		if opts.Group != "" {
			uprobeOpts.Group = opts.Group
		}

		if opts.Event != "" {
			uprobeOpts.Event = opts.Event
		}

		if opts.Path != "" {
			uprobeOpts.Path = opts.Path
		}

		if opts.Offset != 0 {
			uprobeOpts.Offset = opts.Offset
		}

		var err error
		p.attachedEvent, err = perf.OpenUProbeEvent(uprobeOpts)
		if err != nil {
			return fmt.Errorf("open uprobe: %w", err)
		}
	}

	err := p.attachedEvent.AttachBPFProgram(p.fd)
	if err != nil {
		return fmt.Errorf("attach program: %w", err)
	}

	return nil
}

func (p *ProgramKProbe) Detach() error {
	return p.attachedEvent.DetachBPFProgram()
}
