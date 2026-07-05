// Package cgroup detects the host's cgroup hierarchy version.
package cgroup

// Mode is the cgroup hierarchy version in use on the host.
type Mode uint8

const (
	// ModeV1 is the legacy multi-hierarchy layout (one hierarchy per controller).
	ModeV1 Mode = iota + 1
	// ModeV2 is the unified hierarchy.
	ModeV2
)

// cgroup2Magic is CGROUP2_SUPER_MAGIC ("cgrp"), the statfs type reported by a
// unified cgroup mount.
const cgroup2Magic = 0x63677270

// String returns "v1", "v2", or "unknown".
func (m Mode) String() string {
	switch m {
	case ModeV1:
		return "v1"
	case ModeV2:
		return "v2"
	default:
		return "unknown"
	}
}

func modeFromMagic(magic int64) Mode {
	if magic == cgroup2Magic {
		return ModeV2
	}
	return ModeV1
}
