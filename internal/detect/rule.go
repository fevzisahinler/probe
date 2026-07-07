// Package detect loads YAML detection rules and evaluates events against them.
package detect

import (
	"slices"
	"strings"

	"github.com/fevzisahinler/probe/internal/enrich"
	"github.com/fevzisahinler/probe/internal/event"
)

// Priority ranks how serious a detection is.
type Priority string

// Priority levels, most severe first.
const (
	Critical Priority = "critical"
	High     Priority = "high"
	Medium   Priority = "medium"
	Low      Priority = "low"
	Info     Priority = "info"
)

// Workload constrains a rule to a process context.
type Workload string

// Workload values a rule Condition can require.
const (
	WorkloadAny       Workload = ""
	WorkloadContainer Workload = "container"
	WorkloadHost      Workload = "host"
)

// Access constrains an open rule to reads or writes.
type Access string

// Access values an open Condition can require.
const (
	AccessAny   Access = ""
	AccessRead  Access = "read"
	AccessWrite Access = "write"
)

// setuidBits are the setuid and setgid mode bits.
const setuidBits = 0o6000

// Condition is a rule's match criteria. Every non-empty field must hold (AND).
type Condition struct {
	CommIn       []string `yaml:"comm_in"`
	Workload     Workload `yaml:"workload"`
	Access       Access   `yaml:"access"`
	PathExact    []string `yaml:"path_exact"`
	PathPrefix   []string `yaml:"path_prefix"`
	PathContains []string `yaml:"path_contains"`
	ModeSetuid   bool     `yaml:"mode_setuid"`
	DestIP       []string `yaml:"dest_ip"`
	DestPort     []uint16 `yaml:"dest_port"`
	ArgsContains []string `yaml:"args_contains"`
}

func (c Condition) matches(ev event.Event, info enrich.Info) bool {
	if len(c.CommIn) > 0 && !slices.Contains(c.CommIn, ev.Comm) {
		return false
	}
	switch c.Workload {
	case WorkloadContainer:
		if !info.InContainer() {
			return false
		}
	case WorkloadHost:
		if info.InContainer() {
			return false
		}
	}
	switch c.Access {
	case AccessRead:
		if ev.IsWrite() {
			return false
		}
	case AccessWrite:
		if !ev.IsWrite() {
			return false
		}
	}
	if len(c.PathExact) > 0 && !slices.Contains(c.PathExact, ev.Filename) {
		return false
	}
	if len(c.PathPrefix) > 0 && !hasAnyPrefix(ev.Filename, c.PathPrefix) {
		return false
	}
	if len(c.PathContains) > 0 && !hasAnySubstr(ev.Filename, c.PathContains) {
		return false
	}
	if c.ModeSetuid && ev.Mode&setuidBits == 0 {
		return false
	}
	if len(c.DestIP) > 0 && !slices.Contains(c.DestIP, ev.DestIP) {
		return false
	}
	if len(c.DestPort) > 0 && !slices.Contains(c.DestPort, ev.DestPort) {
		return false
	}
	if len(c.ArgsContains) > 0 && !hasAnySubstr(ev.Args, c.ArgsContains) {
		return false
	}
	return true
}

// empty reports whether the condition has no criteria, which would make the
// rule fire on every event of its type. Access alone is not enough — it would
// still match every read (or every write), so it is not counted here.
func (c Condition) empty() bool {
	return len(c.CommIn) == 0 && c.Workload == WorkloadAny &&
		len(c.PathExact) == 0 && len(c.PathPrefix) == 0 && len(c.PathContains) == 0 &&
		!c.ModeSetuid && len(c.DestIP) == 0 && len(c.DestPort) == 0 && len(c.ArgsContains) == 0
}

// Rule is a single detection loaded from YAML.
type Rule struct {
	Name      string    `yaml:"name"`
	Desc      string    `yaml:"desc"`
	Event     string    `yaml:"event"`
	Priority  Priority  `yaml:"priority"`
	MITRE     string    `yaml:"mitre"`
	Match     Condition `yaml:"match"`
	eventType event.Type
}

// Detection is a rule that fired for an event.
type Detection struct {
	Rule  Rule
	Event event.Event
	Info  enrich.Info
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func hasAnySubstr(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
