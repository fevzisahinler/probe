package enrich

import "testing"

const (
	id1 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	id2 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestParseCgroup(t *testing.T) {
	tests := []struct {
		name   string
		cgroup string
		want   Info
	}{
		{"docker cgroup v2", "0::/system.slice/docker-" + id1 + ".scope\n", Info{ContainerID: id1}},
		{"docker cgroup v1", "12:pids:/docker/" + id1 + "\n", Info{ContainerID: id1}},
		{"containerd on k8s", "0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-" + id2 + ".scope\n", Info{ContainerID: id2}},
		{"host systemd service", "0::/system.slice/nginx.service\n", Info{Service: "nginx.service"}},
		{"host user session", "0::/user.slice/user-1000.slice/session-3.scope\n", Info{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseCgroup(tt.cgroup); got != tt.want {
				t.Errorf("parseCgroup() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestInfoSource(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want string
	}{
		{"container", Info{ContainerID: id1}, "container:" + id1[:12]},
		{"service", Info{Service: "nginx.service"}, "service:nginx.service"},
		{"host", Info{}, "host"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.Source(); got != tt.want {
				t.Errorf("Source() = %q, want %q", got, tt.want)
			}
		})
	}
}
