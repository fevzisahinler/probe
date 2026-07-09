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

func TestArgString(t *testing.T) {
	// buf mimics the kernel's fixed 128-byte argv capture: s is copied in and
	// the unused tail is left as NUL.
	buf := func(s string) []byte {
		b := make([]byte, 128)
		copy(b, s)
		return b
	}

	tests := []struct {
		name string
		b    []byte
		n    uint16
		want string
	}{
		{"single arg", buf("bash\x00"), 5, "bash"},
		{"multiple args, real space preserved", buf("bash\x00-c\x00ls -la\x00"), 15, "bash -c ls -la"},
		{"n zero yields empty", buf("ignored\x00"), 0, ""},
		{"all nul yields empty", buf(""), 8, ""},
		{"no trailing nul within n", buf("bash\x00-i"), 7, "bash -i"},
		{"n larger than buffer is capped to len", []byte("bash\x00-i\x00"), 999, "bash -i"},
		{"pipe payload preserved", buf("sh\x00-c\x00curl x | sh\x00"), 20, "sh -c curl x | sh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := argString(tt.b, tt.n); got != tt.want {
				t.Errorf("argString(_, %d) = %q, want %q", tt.n, got, tt.want)
			}
		})
	}
}
