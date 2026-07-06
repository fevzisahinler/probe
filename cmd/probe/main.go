// Command probe is a Falco-style eBPF runtime security agent.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/fevzisahinler/probe/internal/cgroup"
	"github.com/fevzisahinler/probe/internal/enrich"
	"github.com/fevzisahinler/probe/internal/event"
	"github.com/fevzisahinler/probe/internal/loader"
)

var version = "dev"

func main() {
	log.SetFlags(log.Ltime)

	mode, err := cgroup.Detect()
	if err != nil {
		log.Printf("cgroup detect failed, defaulting to v2: %v", err)
		mode = cgroup.ModeV2
	}

	l, err := loader.New(mode)
	if err != nil {
		log.Fatalf("startup: %v", err)
	}
	defer func() { _ = l.Close() }()

	log.Printf("probe %s — cgroup %s, streaming events", version, mode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		if err := l.Close(); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()

	for {
		ev, err := l.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("read: %v", err)
			continue
		}

		info := enrich.FromCgroup(ev.Cgroup)
		detail := ev.Filename
		if ev.Type == event.Chmod {
			detail = fmt.Sprintf("%s mode=%04o", ev.Filename, ev.Mode)
		}
		fmt.Printf("%-6s %-24s uid=%-5d pid=%-7d comm=%-12s %s\n",
			ev.Type, info.Source(), ev.UID, ev.PID, ev.Comm, detail)
	}
}
