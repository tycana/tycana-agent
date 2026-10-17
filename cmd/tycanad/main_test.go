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
		{"no state directory", []string{"--config", "/nonexistent/tycanad.yaml", "--state-dir", "/nonexistent/state", "--once"}, 1, "", "state directory"},
		{"argument", []string{"apply"}, 2, "", "unexpected argument"},
		{"help", []string{"--help"}, 0, "", "never changes"},
		{"version", []string{"--version"}, 0, "tycana ", ""},
		{"bad flag", []string{"--apply"}, 2, "", "flag provided but not defined"},
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
