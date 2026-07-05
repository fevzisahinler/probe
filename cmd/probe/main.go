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
	"github.com/fevzisahinler/probe/internal/loader"
	"github.com/fevzisahinler/probe/internal/rules"
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

	defaultRules := rules.Default()
	engine := rules.NewEngine(defaultRules)
	log.Printf("probe %s — cgroup %s, %d rule(s), watching", version, mode, len(defaultRules))

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
		for _, m := range engine.Eval(ev, info) {
			fmt.Printf("[%s] %-20s %-24s pid=%-7d comm=%-12s %s\n",
				m.Rule.Priority, m.Rule.Name, info.Source(), ev.PID, ev.Comm, ev.Filename)
		}
	}
}
