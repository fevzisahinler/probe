package cgroup

import "testing"

func TestModeFromMagic(t *testing.T) {
	tests := []struct {
		name  string
		magic int64
		want  Mode
	}{
		{"cgroup2 unified", 0x63677270, ModeV2},
		{"tmpfs (v1 mount)", 0x01021994, ModeV1},
		{"unknown fs falls back to v1", 0x12345678, ModeV1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := modeFromMagic(tt.magic); got != tt.want {
				t.Errorf("modeFromMagic(%#x) = %v, want %v", tt.magic, got, tt.want)
			}
		})
	}
}

func TestModeString(t *testing.T) {
	tests := map[Mode]string{ModeV1: "v1", ModeV2: "v2", Mode(0): "unknown"}
	for m, want := range tests {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", m, got, want)
		}
	}
}
