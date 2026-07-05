package loader

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/fevzisahinler/probe/internal/cgroup"
	"github.com/fevzisahinler/probe/internal/event"
)

// Loader attaches probe's tracepoints and reads events from the ring buffer.
// Read must not be called concurrently.
type Loader struct {
	objs      probeObjects
	links     []link.Link
	reader    *ringbuf.Reader
	closeOnce sync.Once
}

// New loads the eBPF objects for the given cgroup mode, attaches every
// tracepoint, and opens the ring buffer. The caller must Close the result.
func New(mode cgroup.Mode) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := loadProbe()
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}

	v := spec.Variables["cgroup_mode"]
	if v == nil {
		return nil, errors.New("bpf variable cgroup_mode not found")
	}
	if err := v.Set(uint32(mode)); err != nil {
		return nil, fmt.Errorf("set cgroup_mode: %w", err)
	}

	l := &Loader{}
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	hooks := []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"sched", "sched_process_exec", l.objs.HandleExec},
		{"syscalls", "sys_enter_openat", l.objs.HandleOpenat},
	}
	for _, h := range hooks {
		lnk, err := link.Tracepoint(h.group, h.name, h.prog, nil)
		if err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", h.group, h.name, err)
		}
		l.links = append(l.links, lnk)
	}

	reader, err := ringbuf.NewReader(l.objs.Events)
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	l.reader = reader

	return l, nil
}

// Read blocks until the next event arrives. It returns ringbuf.ErrClosed
// after Close.
func (l *Loader) Read() (event.Event, error) {
	record, err := l.reader.Read()
	if err != nil {
		return event.Event{}, err
	}

	var raw probeEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
		return event.Event{}, fmt.Errorf("decode event: %w", err)
	}

	return event.Event{
		Type:        event.Type(raw.Type),
		TimestampNs: raw.TimestampNs,
		PID:         raw.Pid,
		PPID:        raw.Ppid,
		UID:         raw.Uid,
		Comm:        cString(raw.Comm[:]),
		Filename:    cString(raw.Filename[:]),
		Cgroup:      cString(raw.Cgroup[:]),
	}, nil
}

// Close detaches the tracepoints and releases all resources, joining any errors.
func (l *Loader) Close() error {
	var errs []error
	l.closeOnce.Do(func() {
		if l.reader != nil {
			errs = append(errs, l.reader.Close())
		}
		for _, lnk := range l.links {
			errs = append(errs, lnk.Close())
		}
		errs = append(errs, l.objs.Close())
	})
	return errors.Join(errs...)
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
