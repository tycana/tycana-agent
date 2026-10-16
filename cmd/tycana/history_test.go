package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"tycana.ai/agent/internal/history"
)

const labRoot = "../../testdata/lab/ubuntu2404/root"

func TestHistoryCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"history", "--root", labRoot}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	for _, want := range []string{"America/New_York", "apt-get purge -y -qq hello  (requested by operator)",
		"downgrade  tzdata:all", "2026c-0ubuntu0.24.04.1 -> 2024a-2ubuntu1", "purge", "not-installed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("text missing %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if code := run([]string{"history", "--root", labRoot, "--format", "json", "--since", "2026-10-16T01:09:00Z"}, &out, &errb); code != 0 {
		t.Fatalf("json: exit %d: %s", code, errb.String())
	}
	var h history.History
	if err := json.Unmarshal(out.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if len(h.Changes) == 0 || h.Changes[0].Package != "tzdata" || h.Changes[0].Transaction != 0 {
		t.Errorf("since: %+v", h.Changes)
	}

	for _, args := range [][]string{
		{"history", "--since", "yesterday"},
		{"history", "--format", "xml", "--root", labRoot},
		{"history", "extra"},
	} {
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code := run([]string{"history", "--help"}, &out, &errb); code != 0 {
		t.Errorf("--help: exit %d", code)
	}
}

func TestSafe(t *testing.T) {
	if got := safe("apt-get install x"); got != "apt-get install x" {
		t.Errorf("plain: %q", got)
	}
	if got := safe("apt \x1b]0;pwned\x07 x"); strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("escape sequence survived: %q", got)
	}
}
