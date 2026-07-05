//go:build linux

package cgroup

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const cgroupRoot = "/sys/fs/cgroup"

// Detect reports whether the host uses cgroup v1 or v2.
func Detect() (Mode, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(cgroupRoot, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", cgroupRoot, err)
	}
	return modeFromMagic(int64(st.Type)), nil
}
