// Package event defines the process events probe observes.
package event

// Type identifies which syscall produced an event.
type Type uint8

const (
	// Exec is a process-execution (execve) event.
	Exec Type = iota + 1
	// Open is a file-open (openat) event.
	Open
)

// String returns the event type's short label.
func (t Type) String() string {
	switch t {
	case Exec:
		return "EXEC"
	case Open:
		return "OPEN"
	default:
		return "UNKNOWN"
	}
}

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
