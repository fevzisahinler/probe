package detect

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/fevzisahinler/probe/internal/enrich"
	"github.com/fevzisahinler/probe/internal/event"
)

const rulesDoc = `
- name: shell_in_container
  event: exec
  priority: critical
  match:
    comm_in: [sh, bash]
    workload: container
- name: host_shell
  event: exec
  priority: low
  match:
    comm_in: [zsh]
    workload: host
- name: shadow_read
  event: open
  priority: high
  match:
    access: read
    path_exact: [/etc/shadow]
- name: bindir_write
  event: open
  priority: high
  match:
    access: write
    path_prefix: [/usr/bin/]
- name: ssh_key_read
  event: open
  priority: high
  match:
    path_contains: [/.ssh/id_]
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
- name: db_connect
  event: connect
  priority: medium
  match:
    dest_port: [5432]
`

func names(ds []Detection) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Rule.Name)
	}
	return out
}

func TestEngineEval(t *testing.T) {
	loaded, err := Load([]byte(rulesDoc))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	eng := NewEngine(loaded)

	const write = 1 // O_WRONLY

	tests := []struct {
		name string
		ev   event.Event
		info enrich.Info
		want []string
	}{
		{"shell in container", event.Event{Type: event.Exec, Comm: "sh"}, enrich.Info{ContainerID: "abc"}, []string{"shell_in_container"}},
		{"shell on host no match", event.Event{Type: event.Exec, Comm: "sh"}, enrich.Info{}, nil},
		{"host zsh", event.Event{Type: event.Exec, Comm: "zsh"}, enrich.Info{}, []string{"host_shell"}},
		{"zsh in container not host_shell", event.Event{Type: event.Exec, Comm: "zsh"}, enrich.Info{ContainerID: "abc"}, nil},
		{"shadow read", event.Event{Type: event.Open, Filename: "/etc/shadow"}, enrich.Info{}, []string{"shadow_read"}},
		{"shadow write not read rule", event.Event{Type: event.Open, Filename: "/etc/shadow", Flags: write}, enrich.Info{}, nil},
		{"shadow backup not matched", event.Event{Type: event.Open, Filename: "/etc/shadow.bak"}, enrich.Info{}, nil},
		{"bindir read not write rule", event.Event{Type: event.Open, Filename: "/usr/bin/x"}, enrich.Info{}, nil},
		{"bindir write", event.Event{Type: event.Open, Filename: "/usr/bin/x", Flags: write}, enrich.Info{}, []string{"bindir_write"}},
		{"ssh key substring", event.Event{Type: event.Open, Filename: "/home/u/.ssh/id_rsa"}, enrich.Info{}, []string{"ssh_key_read"}},
		{"setuid chmod", event.Event{Type: event.Chmod, Mode: 0o4755}, enrich.Info{}, []string{"setuid_set"}},
		{"plain chmod no match", event.Event{Type: event.Chmod, Mode: 0o0644}, enrich.Info{}, nil},
		{"metadata ip", event.Event{Type: event.Connect, DestIP: "169.254.169.254"}, enrich.Info{}, []string{"metadata_connect"}},
		{"db port", event.Event{Type: event.Connect, DestPort: 5432}, enrich.Info{}, []string{"db_connect"}},
		{"other connect no match", event.Event{Type: event.Connect, DestIP: "8.8.8.8", DestPort: 53}, enrich.Info{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := names(eng.Eval(tt.ev, tt.info))
			if !slices.Equal(got, tt.want) {
				t.Errorf("matched %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadValidation(t *testing.T) {
	bad := map[string]string{
		"unknown event":    "- name: r\n  event: nope\n  priority: low\n  match:\n    comm_in: [sh]\n",
		"invalid priority": "- name: r\n  event: exec\n  priority: urgent\n  match:\n    comm_in: [sh]\n",
		"missing priority": "- name: r\n  event: exec\n  match:\n    comm_in: [sh]\n",
		"invalid workload": "- name: r\n  event: exec\n  priority: low\n  match:\n    workload: contaner\n    comm_in: [sh]\n",
		"invalid access":   "- name: r\n  event: open\n  priority: low\n  match:\n    access: sideways\n    path_exact: [/x]\n",
		"access on exec":   "- name: r\n  event: exec\n  priority: low\n  match:\n    access: read\n    comm_in: [sh]\n",
		"empty match":      "- name: r\n  event: exec\n  priority: low\n",
		"long comm":        "- name: r\n  event: exec\n  priority: low\n  match:\n    comm_in: [this_process_name_is_far_too_long]\n",
		"missing name":     "- event: exec\n  priority: low\n  match:\n    comm_in: [sh]\n",
		"malformed yaml":   "- name: r\n  event: [oops\n",
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := Load([]byte(doc)); err == nil {
				t.Errorf("expected error for %q", name)
			}
		})
	}
}

func TestLoadFS(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yaml":          {Data: []byte("- name: r1\n  event: exec\n  priority: low\n  match:\n    comm_in: [sh]\n")},
		"b.yaml":          {Data: []byte("- name: r2\n  event: open\n  priority: low\n  match:\n    path_exact: [/etc/x]\n")},
		"notes.txt":       {Data: []byte("not a rule")},
		"disabled/c.yaml": {Data: []byte("- name: r3\n  event: exec\n  priority: low\n  match:\n    comm_in: [sh]\n")},
	}
	loaded, err := LoadFS(fsys)
	if err != nil {
		t.Fatalf("LoadFS: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d rules, want 2 (non-yaml and subdirs ignored)", len(loaded))
	}
}

// TestShippedRulesValid ensures every rule in the repo's rules/ directory
// parses and passes validation.
func TestShippedRulesValid(t *testing.T) {
	loaded, err := LoadDir("../../rules")
	if err != nil {
		t.Fatalf("shipped rules failed to load: %v", err)
	}
	if len(loaded) == 0 {
		t.Fatal("no shipped rules found")
	}
}
