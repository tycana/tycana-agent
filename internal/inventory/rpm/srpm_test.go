package rpm

import "testing"

func TestSourceRPM(t *testing.T) {
	cases := []struct{ in, name, vr string }{
		{"bash-5.1.8-9.el9.src.rpm", "bash", "5.1.8-9.el9"},
		{"python-setuptools-53.0.0-15.el9.src.rpm", "python-setuptools", "53.0.0-15.el9"},
		{"kernel-5.14.0-687.36.1.el9_8.src.rpm", "kernel", "5.14.0-687.36.1.el9_8"},
		{"foo-1-2.nosrc.rpm", "foo", "1-2"},
		{"(none)", "", ""}, {"", "", ""}, {"bash.src.rpm", "", ""}, {"bash-1.src.rpm", "", ""},
	}
	for _, c := range cases {
		name, vr, ok := SourceRPM(c.in)
		if name != c.name || vr != c.vr || ok != (c.name != "") {
			t.Errorf("SourceRPM(%q) = %q, %q, %v", c.in, name, vr, ok)
		}
	}
}
