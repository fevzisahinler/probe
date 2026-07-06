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
