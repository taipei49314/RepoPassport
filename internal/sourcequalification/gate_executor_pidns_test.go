package sourcequalification

import "testing"

func TestLinuxStatusNSpidCount(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want int
	}{
		{name: "host", raw: "Name:\tgo\nNSpid:\t12345\n", want: 1},
		{name: "nested pid namespace", raw: "Name:\tgo\nNSpid:\t1\t9562\n", want: 2},
		{name: "missing", raw: "Name:\tgo\n", want: 0},
		{name: "empty fields", raw: "NSpid:\n", want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := linuxStatusNSpidCount([]byte(test.raw)); got != test.want {
				t.Fatalf("linuxStatusNSpidCount(%q) = %d, want %d", test.raw, got, test.want)
			}
		})
	}
}
