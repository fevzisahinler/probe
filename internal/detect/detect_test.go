package detect

import (
	"testing"
	"testing/fstest"

	"github.com/fevzisahinler/probe/internal/enrich"
	"github.com/fevzisahinler/probe/internal/event"
)

func TestLoadAndEval(t *testing.T) {
	doc := `
- name: shell_in_container
  event: exec
  priority: critical
  mitre: T1059.004
  match:
    comm_in: [sh, bash]
    workload: container
- name: shadow_read
  event: open
  priority: high
  match:
    path_prefix: [/etc/shadow]
- name: setuid_set
  event: chmod
  priority: high
  match:
    mode_setuid: true
- name: metadata_connect
  event: connect
  priority: critical
  match:
    dest_ip: [169.254.169.254]
`
	loaded, err := Load([]byte(doc))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 4 {
		t.Fatalf("loaded %d rules, want 4", len(loaded))
	}
	eng := NewEngine(loaded)

	tests := []struct {
		name string
		ev   event.Event
		info enrich.Info
		want string
	}{
		{"shell in container", event.Event{Type: event.Exec, Comm: "sh"}, enrich.Info{ContainerID: "abc"}, "shell_in_container"},
		{"shell on host", event.Event{Type: event.Exec, Comm: "sh"}, enrich.Info{}, ""},
		{"shadow read", event.Event{Type: event.Open, Filename: "/etc/shadow"}, enrich.Info{}, "shadow_read"},
		{"other file read", event.Event{Type: event.Open, Filename: "/tmp/x"}, enrich.Info{}, ""},
		{"setuid chmod", event.Event{Type: event.Chmod, Mode: 0o4755}, enrich.Info{}, "setuid_set"},
		{"plain chmod", event.Event{Type: event.Chmod, Mode: 0o0644}, enrich.Info{}, ""},
		{"metadata connect", event.Event{Type: event.Connect, DestIP: "169.254.169.254"}, enrich.Info{}, "metadata_connect"},
		{"other connect", event.Event{Type: event.Connect, DestIP: "8.8.8.8"}, enrich.Info{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ""
			for _, d := range eng.Eval(tt.ev, tt.info) {
				got = d.Rule.Name
			}
			if got != tt.want {
				t.Errorf("matched %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoadRejectsUnknownEvent(t *testing.T) {
	if _, err := Load([]byte("- name: bad\n  event: nope\n")); err == nil {
		t.Fatal("expected error for unknown event type")
	}
}

func TestLoadFS(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yaml":     {Data: []byte("- name: r1\n  event: exec\n")},
		"b.yaml":     {Data: []byte("- name: r2\n  event: open\n")},
		"readme.txt": {Data: []byte("not a rule")},
	}
	loaded, err := LoadFS(fsys)
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d rules, want 2 (non-yaml ignored)", len(loaded))
	}
}

// TestShippedRulesValid ensures every rule in the repo's rules/ directory
// parses and validates.
func TestShippedRulesValid(t *testing.T) {
	loaded, err := LoadDir("../../rules")
	if err != nil {
		t.Fatalf("shipped rules failed to load: %v", err)
	}
	if len(loaded) == 0 {
		t.Fatal("no shipped rules found")
	}
}
