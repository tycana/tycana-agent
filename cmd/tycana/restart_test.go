package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const ubuntuRestart = "../../testdata/lab/ubuntu2404/restart/snapshot.json"

func TestRestartFromSnapshot(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"restart", "--snapshot", ubuntuRestart}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	s := out.String()
	for _, want := range []string{
		"4 units use a file replaced since they started (inferred); 2 unknown; 17 with no evidence.\n",
		"inferred  dbus.service",
		"replaced: /usr/lib/x86_64-linux-gnu/libsystemd.so.0.38.0",
		"a script run by /usr/bin/python3.12",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	if strings.Contains(s, "Kernel:") {
		t.Error("a snapshot has no kernel section")
	}

	out.Reset()
	if code := run([]string{"restart", "--snapshot", ubuntuRestart, "--format", "json"}, &out, &errb); code != 0 {
		t.Fatalf("json exit %d: %s", code, errb.String())
	}
	var r restartOutput
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Findings) != 23 {
		t.Fatalf("json: %v, %d findings", err, len(r.Findings))
	}
}

func TestRestartFlags(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"restart", "--format", "yaml"}, &out, &errb); code != 2 {
		t.Errorf("bad format: exit %d", code)
	}
	if code := run([]string{"restart", "extra"}, &out, &errb); code != 2 {
		t.Errorf("extra argument: exit %d", code)
	}
	if code := run([]string{"restart", "--snapshot", "/nonexistent"}, &out, &errb); code != 1 {
		t.Errorf("missing snapshot: exit %d", code)
	}
}
