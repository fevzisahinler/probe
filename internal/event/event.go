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

// Open access-mode bits. O_RDONLY is 0, so a mode permits writing unless it is
// exactly O_RDONLY, and permits reading unless it is exactly O_WRONLY. O_RDWR
// (2) therefore counts as both a read and a write.
const (
	accMode = 0o3 // O_ACCMODE, masks the access-mode bits of open flags
	oWrOnly = 0o1 // O_WRONLY
)

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

// IsWrite reports whether an Open event opened the file with write access
// (O_WRONLY or O_RDWR). O_RDONLY is the only mode that denies writing.
func (e Event) IsWrite() bool {
	return e.Flags&accMode != 0
}

// IsRead reports whether an Open event opened the file with read access
// (O_RDONLY or O_RDWR). O_WRONLY is the only mode that denies reading, so an
// O_RDWR open — which can still read the file — is correctly counted as a read.
func (e Event) IsRead() bool {
	return e.Flags&accMode != oWrOnly
}
