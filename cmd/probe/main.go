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

	"github.com/fevzisahinler/probe/internal/loader"
)

var version = "dev"

func main() {
	log.SetFlags(log.Ltime)
	log.Printf("probe %s — watching process execution", version)

	l, err := loader.New()
	if err != nil {
		log.Fatalf("startup: %v", err)
	}
	defer l.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		l.Close() // unblock Read
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
		fmt.Printf("EXEC uid=%-5d pid=%-7d ppid=%-7d comm=%-16s %s\n",
			ev.UID, ev.PID, ev.PPID, ev.Comm, ev.Filename)
	}
}
