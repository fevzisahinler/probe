package detect

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/fevzisahinler/probe/internal/event"
)

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

// LoadDir loads and validates every *.yaml rule file in dir.
func LoadDir(dir string) ([]Rule, error) {
	return LoadFS(os.DirFS(dir))
}

// LoadFS loads and validates every *.yaml rule file in fsys.
func LoadFS(fsys fs.FS) ([]Rule, error) {
	var all []Rule
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		rules, err := Load(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		all = append(all, rules...)
		return nil
	})
	return all, err
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
	return nil
}
