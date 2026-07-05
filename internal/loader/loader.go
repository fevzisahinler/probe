package loader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/fevzisahinler/probe/internal/event"
)

// Loader attaches the exec tracepoint and reads events from its ring buffer.
// Read must not be called concurrently.
type Loader struct {
	objs      probeObjects
	link      link.Link
	reader    *ringbuf.Reader
	closeOnce sync.Once
}

// New loads the eBPF objects, attaches the tracepoint, and opens the ring
// buffer. The caller must Close the result.
func New() (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var objs probeObjects
	if err := loadProbeObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.HandleExec, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint sched_process_exec: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	return &Loader{objs: objs, link: tp, reader: reader}, nil
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
		Type:        event.Exec,
		TimestampNs: raw.TimestampNs,
		PID:         raw.Pid,
		PPID:        raw.Ppid,
		UID:         raw.Uid,
		Comm:        cString(raw.Comm[:]),
		Filename:    cString(raw.Filename[:]),
	}, nil
}

// Close releases the reader, link, and objects.
func (l *Loader) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.reader.Close()
		l.link.Close()
		err = l.objs.Close()
	})
	return err
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
