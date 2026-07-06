// Package event defines the process events probe observes.
package event

// Type identifies which syscall produced an event.
type Type uint8

const (
	// Exec is a process-execution (execve) event.
	Exec Type = iota + 1
	// Open is a file-open (open/openat/openat2) event.
	Open
	// Chmod is a permission-change (chmod/fchmodat) event.
	Chmod
)

// String returns the event type's short label.
func (t Type) String() string {
	switch t {
	case Exec:
		return "EXEC"
	case Open:
		return "OPEN"
	case Chmod:
		return "CHMOD"
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
	Mode        uint32 // file mode for Chmod events, else 0
	Comm        string
	Filename    string
	Cgroup      string
}
