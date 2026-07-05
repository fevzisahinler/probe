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

	"github.com/fevzisahinler/probe/internal/enrich"
	"github.com/fevzisahinler/probe/internal/loader"
	"github.com/fevzisahinler/probe/internal/rules"
)

var version = "dev"

func main() {
	log.SetFlags(log.Ltime)

	l, err := loader.New()
	if err != nil {
		log.Fatalf("startup: %v", err)
	}
	defer l.Close()

	engine := rules.NewEngine(rules.Default())
	log.Printf("probe %s — %d rule(s), watching", version, len(rules.Default()))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		l.Close()
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
		info := enrich.Enrich(ev.PID)
		for _, m := range engine.Eval(ev, info) {
			fmt.Printf("[%s] %-20s %-24s pid=%-7d comm=%-12s %s\n",
				m.Rule.Priority, m.Rule.Name, info.Source(), ev.PID, ev.Comm, ev.Filename)
		}
	}
}
