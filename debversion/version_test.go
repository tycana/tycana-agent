package debversion

import "testing"

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in   string
		want Version
		str  string
	}{
		{"1.0", Version{0, "1.0", ""}, "1.0"},
		{"1.0-1", Version{0, "1.0", "1"}, "1.0-1"},
		{"2:1.0-1", Version{2, "1.0", "1"}, "2:1.0-1"},
		{"0:1.0-1", Version{0, "1.0", "1"}, "1.0-1"},
		{"1.0-1-2", Version{0, "1.0-1", "2"}, "1.0-1-2"},
		{"1:2:3-4", Version{1, "2:3", "4"}, "1:2:3-4"},
		{"0:2:3", Version{0, "2:3", ""}, "0:2:3"},
		{"  1.2.3-0ubuntu1~24.04.1 ", Version{0, "1.2.3", "0ubuntu1~24.04.1"}, "1.2.3-0ubuntu1~24.04.1"},
		{"a1.0", Version{0, "a1.0", ""}, "a1.0"}, // dpkg warns, accepts
	}
	for _, c := range cases {
		got, err := ParseVersion(c.in)
		if err != nil {
			t.Errorf("ParseVersion(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseVersion(%q) = %+v, want %+v", c.in, got, c.want)
		}
		if got.String() != c.str {
			t.Errorf("ParseVersion(%q).String() = %q, want %q", c.in, got.String(), c.str)
		}
	}
	for _, bad := range []string{"", "  ", "1 0", ":1.0", "a:1.0", "1:", "1.0-", "-1", "-1:1.0", "2147483648:1"} {
		if v, err := ParseVersion(bad); err == nil {
			t.Errorf("ParseVersion(%q) = %+v, want error", bad, v)
		}
	}
}

// Vectors from dpkg's lib/dpkg/t/t-version.c and deb-version(7).
func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.0-0", 0}, // empty revision equals "0"
		{"0:1.0", "1.0", 0},
		{"1.0", "1:0.1", -1},
		{"1.0", "1.1", -1},
		{"1.0", "1.0.1", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~~a", -1},
		{"1.0~~a", "1.0~", -1},
		{"1.0~", "1.0", -1},
		{"1.0", "1.0a", -1},
		{"1.0a", "1.0+", -1}, // letters sort before non-letters
		{"1.0+", "1.0.", -1},
		{"1.0-1", "1.0-2", -1},
		{"1.0-1ubuntu1", "1.0-1", 1},
		{"1.0-1~bpo1", "1.0-1", -1},
		{"2.39-0ubuntu8.3", "2.39-0ubuntu8.10", -1},
		{"1.01", "1.1", 0},
		{"1.001", "1.0001", 0},
		{"10", "9", 1},
		{"1.2.3", "1.2.3.0", -1},
		{"6.8.0-45.45", "6.8.0-100.100", -1},
	}
	for _, c := range cases {
		a, err := ParseVersion(c.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParseVersion(c.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := Compare(a, b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(b, a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}
