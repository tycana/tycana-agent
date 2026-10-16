package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		code     int
		inStdout string
		inStderr string
	}{
		{"no args", nil, 2, "", "Usage:"},
		{"help", []string{"help"}, 0, "observe-only", ""},
		{"version", []string{"version"}, 0, "tycana ", ""},
		{"version json", []string{"version", "--json"}, 0, `"version"`, ""},
		{"version bad flag", []string{"version", "--nope"}, 2, "", "flag provided but not defined"},
		{"unknown", []string{"upgrade"}, 2, "", `unknown command "upgrade"`},
		{"baseline list", []string{"baseline", "--list"}, 0, "ubuntu2404-level1-server", ""},
		{"baseline bad format", []string{"baseline", "--format", "xml"}, 2, "", `unknown format "xml"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if got := run(c.args, &out, &errb); got != c.code {
				t.Fatalf("exit %d, want %d; stderr=%s", got, c.code, errb.String())
			}
			if c.inStdout != "" && !strings.Contains(out.String(), c.inStdout) {
				t.Errorf("stdout missing %q:\n%s", c.inStdout, out.String())
			}
			if c.inStderr != "" && !strings.Contains(errb.String(), c.inStderr) {
				t.Errorf("stderr missing %q:\n%s", c.inStderr, errb.String())
			}
		})
	}
}
