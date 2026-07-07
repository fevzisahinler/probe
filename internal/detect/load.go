package detect

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/fevzisahinler/probe/internal/event"
)

// maxCommLen is the kernel's process-name limit (TASK_COMM_LEN - 1). A comm_in
// entry longer than this can never match an event.
const maxCommLen = 15

// Load parses a YAML rule document and validates each rule.
func Load(data []byte) ([]Rule, error) {
	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	for i := range rules {
		if err := compile(&rules[i]); err != nil {
			return nil, err
		}
	}
	return rules, nil
}

// LoadDir loads and validates every top-level *.yaml rule file in dir.
func LoadDir(dir string) ([]Rule, error) {
	rules, err := LoadFS(os.DirFS(dir))
	if err != nil {
		return nil, fmt.Errorf("rules dir %s: %w", dir, err)
	}
	return rules, nil
}

// LoadFS loads and validates every top-level *.yaml rule file in fsys.
// Subdirectories are ignored, so a "disabled/" folder is not loaded.
func LoadFS(fsys fs.FS) ([]Rule, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	var all []Rule
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		rules, err := Load(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		all = append(all, rules...)
	}
	return all, nil
}

func compile(r *Rule) error {
	if r.Name == "" {
		return fmt.Errorf("rule missing a name")
	}

	t, ok := event.TypeOf(r.Event)
	if !ok {
		return fmt.Errorf("rule %q: unknown event %q", r.Name, r.Event)
	}
	r.eventType = t

	switch r.Priority {
	case Critical, High, Medium, Low, Info:
	default:
		return fmt.Errorf("rule %q: invalid priority %q", r.Name, r.Priority)
	}

	switch r.Match.Workload {
	case WorkloadAny, WorkloadContainer, WorkloadHost:
	default:
		return fmt.Errorf("rule %q: invalid workload %q", r.Name, r.Match.Workload)
	}

	for _, c := range r.Match.CommIn {
		if len(c) > maxCommLen {
			return fmt.Errorf("rule %q: comm_in %q exceeds the %d-byte kernel limit", r.Name, c, maxCommLen)
		}
	}

	if r.Match.empty() {
		return fmt.Errorf("rule %q: match has no conditions (would fire on every event)", r.Name)
	}
	return nil
}
