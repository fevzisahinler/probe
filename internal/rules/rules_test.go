package rules

import (
	"testing"

	"github.com/fevzisahinler/probe/internal/enrich"
	"github.com/fevzisahinler/probe/internal/event"
)

func TestShellInContainer(t *testing.T) {
	engine := NewEngine(Default())

	tests := []struct {
		name string
		ev   event.Event
		info enrich.Info
		want bool
	}{
		{"shell in container", event.Event{Type: event.Exec, Comm: "sh"}, enrich.Info{ContainerID: "c7b63ba593b4"}, true},
		{"bash in container", event.Event{Type: event.Exec, Comm: "bash"}, enrich.Info{ContainerID: "c7b63ba593b4"}, true},
		{"shell on host", event.Event{Type: event.Exec, Comm: "sh"}, enrich.Info{}, false},
		{"non-shell in container", event.Event{Type: event.Exec, Comm: "ls"}, enrich.Info{ContainerID: "c7b63ba593b4"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fired(engine.Eval(tt.ev, tt.info), "shell_in_container"); got != tt.want {
				t.Errorf("shell_in_container fired = %v, want %v", got, tt.want)
			}
		})
	}
}

func fired(matches []Match, name string) bool {
	for _, m := range matches {
		if m.Rule.Name == name {
			return true
		}
	}
	return false
}
