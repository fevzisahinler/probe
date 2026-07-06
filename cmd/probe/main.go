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
	"github.com/fevzisahinler/probe/internal/detect"
	"github.com/fevzisahinler/probe/internal/enrich"
	"github.com/fevzisahinler/probe/internal/event"
	"github.com/fevzisahinler/probe/internal/loader"
)

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

// defaultRulesDir is where probe reads detection rules from unless the
// PROBE_RULES_DIR environment variable overrides it.
const defaultRulesDir = "/etc/probe/rules.d"

func main() {
	log.SetFlags(log.Ltime)

	dir := rulesDir()
	loaded, err := detect.LoadDir(dir)
	if err != nil {
		log.Fatalf("load rules from %s: %v", dir, err)
	}
	if len(loaded) == 0 {
		log.Fatalf("no rules found in %s", dir)
	}
	engine := detect.NewEngine(loaded)

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

	log.Printf("probe %s — cgroup %s, %d rules (%s), watching", version, mode, engine.Len(), dir)

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
		for _, d := range engine.Eval(ev, info) {
			fmt.Printf("[%-8s] %-28s %-24s pid=%-7d comm=%-12s %s  %s\n",
				d.Rule.Priority, d.Rule.Name, info.Source(), ev.PID, ev.Comm, detail(ev), d.Rule.MITRE)
		}
	}
}

// rulesDir returns PROBE_RULES_DIR when set, otherwise the default location.
func rulesDir() string {
	if d := os.Getenv("PROBE_RULES_DIR"); d != "" {
		return d
	}
	return defaultRulesDir
}

// detail renders the event-specific field for display.
func detail(ev event.Event) string {
	switch ev.Type {
	case event.Chmod:
		return fmt.Sprintf("%s mode=%04o", ev.Filename, ev.Mode)
	case event.Connect:
		return fmt.Sprintf("%s:%d", ev.DestIP, ev.DestPort)
	case event.Exit:
		if sig := ev.ExitCode & 0x7f; sig != 0 {
			return fmt.Sprintf("killed by signal %d", sig)
		}
		return fmt.Sprintf("exit=%d", (ev.ExitCode>>8)&0xff)
	default:
		return ev.Filename
	}
}
