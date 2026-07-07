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
	// Connect is an outbound network connection (connect) event.
	Connect
	// Exit is a process-exit event.
	Exit
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
	case Connect:
		return "CONN"
	case Exit:
		return "EXIT"
	default:
		return "UNKNOWN"
	}
}

// TypeOf maps a rule's event name to a Type, reporting whether it is known.
func TypeOf(name string) (Type, bool) {
	switch name {
	case "exec":
		return Exec, true
	case "open":
		return Open, true
	case "chmod":
		return Chmod, true
	case "connect":
		return Connect, true
	case "exit":
		return Exit, true
	default:
		return 0, false
	}
}

// accMode masks the access-mode bits (O_ACCMODE) of open flags.
const accMode = 0o3

// Event is a decoded kernel event.
type Event struct {
	Type        Type
	TimestampNs uint64
	PID         uint32
	PPID        uint32
	UID         uint32
	Mode        uint32 // file mode for Chmod events, else 0
	ExitCode    uint32 // raw kernel exit code for Exit events, else 0
	Flags       uint32 // open flags for Open events, else 0
	DestPort    uint16 // destination port for Connect events, else 0
	Comm        string
	Filename    string
	Cgroup      string
	Args        string // process arguments for Exec events, else ""
	DestIP      string // destination IP for Connect events, else ""
}

// IsWrite reports whether an Open event opened the file for writing
// (O_WRONLY or O_RDWR).
func (e Event) IsWrite() bool {
	return e.Flags&accMode != 0
}
