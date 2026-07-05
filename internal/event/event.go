// Package event defines the process events probe observes.
package event

// Type identifies which syscall produced an event.
type Type uint8

const (
	// TypeAny is the zero value; rule conditions use it to match any type.
	TypeAny Type = iota
	// Exec is a process-execution (execve) event.
	Exec
)

// Event is a decoded kernel event.
type Event struct {
	Type        Type
	TimestampNs uint64
	PID         uint32
	PPID        uint32
	UID         uint32
	Comm        string
	Filename    string
	Cgroup      string
}
