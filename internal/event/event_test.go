package event

import "testing"

func TestTypeString(t *testing.T) {
	tests := map[Type]string{
		Exec:      "EXEC",
		Open:      "OPEN",
		Chmod:     "CHMOD",
		Connect:   "CONN",
		Exit:      "EXIT",
		Type(0):   "UNKNOWN",
		Type(200): "UNKNOWN",
	}

	for tp, want := range tests {
		if got := tp.String(); got != want {
			t.Errorf("Type(%d).String() = %q, want %q", tp, got, want)
		}
	}
}

func TestTypeOf(t *testing.T) {
	known := map[string]Type{"exec": Exec, "open": Open, "chmod": Chmod, "connect": Connect, "exit": Exit}
	for name, want := range known {
		if got, ok := TypeOf(name); !ok || got != want {
			t.Errorf("TypeOf(%q) = %v, %v; want %v, true", name, got, ok, want)
		}
	}
	if _, ok := TypeOf("nope"); ok {
		t.Error("TypeOf(\"nope\") should report unknown")
	}
}

func TestIsWrite(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  bool
	}{
		{"O_RDONLY", 0o0, false},
		{"O_WRONLY", 0o1, true},
		{"O_RDWR", 0o2, true},
		{"O_RDWR|O_CREAT ignores upper bits", 0o2 | 0o100, true},
		{"O_RDONLY|O_CLOEXEC ignores upper bits", 0o0 | 0o2000000, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Event{Flags: tt.flags}).IsWrite(); got != tt.want {
				t.Errorf("IsWrite(%#o) = %v, want %v", tt.flags, got, tt.want)
			}
		})
	}
}

func TestIsRead(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  bool
	}{
		{"O_RDONLY", 0o0, true},
		{"O_WRONLY", 0o1, false},
		{"O_RDWR reads too", 0o2, true},
		{"O_RDWR|O_CREAT ignores upper bits", 0o2 | 0o100, true},
		{"O_WRONLY|O_APPEND ignores upper bits", 0o1 | 0o2000, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Event{Flags: tt.flags}).IsRead(); got != tt.want {
				t.Errorf("IsRead(%#o) = %v, want %v", tt.flags, got, tt.want)
			}
		})
	}
}
