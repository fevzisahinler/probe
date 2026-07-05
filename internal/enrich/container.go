// Package enrich resolves the workload a process belongs to.
package enrich

import "regexp"

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

// Container runtimes embed a 64-hex ID in the cgroup name; systemd services
// name their cgroup <unit>.service.
var (
	containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)
	serviceRe     = regexp.MustCompile(`[0-9A-Za-z_.@\-]+\.service`)
)

// FromCgroup derives workload info from a process's leaf cgroup name, as
// captured in the kernel (e.g. "docker-<id>.scope" or "nginx.service").
func FromCgroup(cgroup string) Info {
	if id := containerIDRe.FindString(cgroup); id != "" {
		return Info{ContainerID: id}
	}
	return Info{Service: serviceRe.FindString(cgroup)}
}
