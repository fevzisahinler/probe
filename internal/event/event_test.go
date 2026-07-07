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
