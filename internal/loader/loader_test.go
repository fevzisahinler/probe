package loader

import "testing"

func TestCString(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"nul terminated", []byte("hello\x00\x00\x00"), "hello"},
		{"no terminator", []byte("nofinalnul"), "nofinalnul"},
		{"leading nul", []byte("\x00rest"), ""},
		{"empty", []byte{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cString(tt.in); got != tt.want {
				t.Errorf("cString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatIP(t *testing.T) {
	v4 := make([]byte, 16)
	copy(v4, []byte{127, 0, 0, 1})

	v6 := make([]byte, 16)
	v6[15] = 1 // ::1

	tests := []struct {
		name   string
		family uint16
		addr   []byte
		want   string
	}{
		{"ipv4", afInet, v4, "127.0.0.1"},
		{"ipv6 loopback", afInet6, v6, "::1"},
		{"unknown family", 99, make([]byte, 16), ""},
		{"short ipv4 buffer", afInet, []byte{1, 2}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatIP(tt.family, tt.addr); got != tt.want {
				t.Errorf("formatIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
