// Package rules evaluates events against detection rules.
package rules

import (
	"slices"

	"github.com/fevzisahinler/probe/internal/enrich"
	"github.com/fevzisahinler/probe/internal/event"
)

// Priority ranks how serious a detection is.
type Priority string

const (
	Critical Priority = "CRITICAL"
	High     Priority = "HIGH"
	Medium   Priority = "MEDIUM"
)

// Workload constrains a rule to processes running in a given context.
type Workload string

const (
	WorkloadAny       Workload = ""
	WorkloadContainer Workload = "container"
	WorkloadHost      Workload = "host"
)

// Condition is the data-driven predicate of a rule.
type Condition struct {
	Type     event.Type
	CommIn   []string
	Workload Workload
}

func (c Condition) matches(ev event.Event, info enrich.Info) bool {
	if c.Type != event.TypeAny && ev.Type != c.Type {
		return false
	}
	if len(c.CommIn) > 0 && !slices.Contains(c.CommIn, ev.Comm) {
		return false
	}
	switch c.Workload {
	case WorkloadContainer:
		return info.InContainer()
	case WorkloadHost:
		return !info.InContainer()
	default:
		return true
	}
}

// Rule is a single named detection.
type Rule struct {
	Name      string
	Priority  Priority
	MITRE     string
	Condition Condition
}

// Match is a rule that fired for an event.
type Match struct {
	Rule  Rule
	Event event.Event
	Info  enrich.Info
}

// Engine evaluates events against its rules.
type Engine struct {
	rules []Rule
}

// NewEngine returns an Engine backed by the given rules.
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// Eval returns every rule that matches the event.
func (e *Engine) Eval(ev event.Event, info enrich.Info) []Match {
	matches := make([]Match, 0, len(e.rules))
	for _, r := range e.rules {
		if r.Condition.matches(ev, info) {
			matches = append(matches, Match{Rule: r, Event: ev, Info: info})
		}
	}
	return matches
}

// Default returns the built-in rule set; YAML loading replaces this later.
func Default() []Rule {
	return []Rule{
		{
			Name:     "shell_in_container",
			Priority: Critical,
			MITRE:    "T1059.004",
			Condition: Condition{
				Type:     event.Exec,
				CommIn:   []string{"sh", "bash", "zsh", "ash", "dash", "ksh"},
				Workload: WorkloadContainer,
			},
		},
	}
}
