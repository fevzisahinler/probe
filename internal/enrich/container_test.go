package enrich

import "testing"

const (
	id1 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	id2 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestFromCgroup(t *testing.T) {
	tests := []struct {
		name   string
		cgroup string
		want   Info
	}{
		{"docker scope", "docker-" + id1 + ".scope", Info{ContainerID: id1}},
		{"containerd scope", "cri-containerd-" + id2 + ".scope", Info{ContainerID: id2}},
		{"bare container id", id1, Info{ContainerID: id1}},
		{"systemd service", "nginx.service", Info{Service: "nginx.service"}},
		{"host session scope", "session-3.scope", Info{}},
		{"empty", "", Info{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromCgroup(tt.cgroup); got != tt.want {
				t.Errorf("FromCgroup() = %+v, want %+v", got, tt.want)
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
		{"full container id truncated", Info{ContainerID: id1}, "container:" + id1[:shortIDLen]},
		{"short container id kept whole", Info{ContainerID: "abc"}, "container:abc"},
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
