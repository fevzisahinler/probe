// Package enrich resolves the workload a process belongs to.
package enrich

import (
	"fmt"
	"os"
	"regexp"
)

// shortIDLen is how many container-ID characters Source displays.
const shortIDLen = 12

// Info identifies the workload a process belongs to.
type Info struct {
	ContainerID string
	Service     string
}

// InContainer reports whether the process runs inside a container.
func (i Info) InContainer() bool { return i.ContainerID != "" }

// Source is a short label describing where the process runs.
func (i Info) Source() string {
	switch {
	case i.ContainerID != "":
		id := i.ContainerID
		if len(id) > shortIDLen {
			id = id[:shortIDLen]
		}
		return "container:" + id
	case i.Service != "":
		return "service:" + i.Service
	default:
		return "host"
	}
}

// Container runtimes embed a 64-hex ID in the cgroup path; systemd services end
// their cgroup in <unit>.service.
var (
	containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)
	serviceRe     = regexp.MustCompile(`[0-9A-Za-z_.@\-]+\.service`)
)

// Enrich reads the cgroup of pid and returns its workload info. It returns an
// error when the cgroup cannot be read (e.g. the process already exited) so the
// caller can distinguish that from a confirmed host process.
func Enrich(pid uint32) (Info, error) {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(path) //nolint:gosec // path is /proc/<numeric pid>/cgroup; no traversal
	if err != nil {
		return Info{}, fmt.Errorf("read %s: %w", path, err)
	}
	return parseCgroup(string(data)), nil
}

func parseCgroup(cgroup string) Info {
	if id := containerIDRe.FindString(cgroup); id != "" {
		return Info{ContainerID: id}
	}
	return Info{Service: serviceRe.FindString(cgroup)}
}
