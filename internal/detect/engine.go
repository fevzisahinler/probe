package detect

import (
	"github.com/fevzisahinler/probe/internal/enrich"
	"github.com/fevzisahinler/probe/internal/event"
)

// Engine evaluates events against a set of rules.
type Engine struct {
	rules []Rule
}

// NewEngine returns an Engine backed by the given rules.
func NewEngine(rules []Rule) *Engine {
	return &Engine{rules: rules}
}

// Len reports how many rules are loaded.
func (e *Engine) Len() int { return len(e.rules) }

// Eval returns every rule that matches the event.
func (e *Engine) Eval(ev event.Event, info enrich.Info) []Detection {
	var out []Detection
	for _, r := range e.rules {
		if r.eventType == ev.Type && r.Match.matches(ev, info) {
			out = append(out, Detection{Rule: r, Event: ev, Info: info})
		}
	}
	return out
}
