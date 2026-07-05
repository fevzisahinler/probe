// Package event defines the process events probe observes.
package event

// Type identifies which syscall produced an event.
type Type uint8

const (
	Exec Type = iota + 1
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
}
