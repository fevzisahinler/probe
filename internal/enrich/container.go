// Package enrich resolves the workload a process belongs to.
package enrich

import (
	"fmt"
	"os"
	"regexp"
)

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
		return "container:" + i.ContainerID[:12]
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

// Enrich reads the cgroup of pid and returns its workload info. A process with
// no readable cgroup yields a zero Info.
func Enrich(pid uint32) Info {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return Info{}
	}
	return parseCgroup(string(data))
}

func parseCgroup(cgroup string) Info {
	if id := containerIDRe.FindString(cgroup); id != "" {
		return Info{ContainerID: id}
	}
	return Info{Service: serviceRe.FindString(cgroup)}
}
