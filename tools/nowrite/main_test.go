package main

import (
	"strings"
	"testing"
)

func TestBad(t *testing.T) {
	got, err := scan("testdata/bad")
	if err != nil {
		t.Fatal(err)
	}
	msgs := make([]string, 0, len(got))
	for _, f := range got {
		msgs = append(msgs, f.msg)
	}
	joined := strings.Join(msgs, "\n")
	for _, want := range []string{"os.WriteFile", "os.Remove", `import "os/exec"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing finding %q in:\n%s", want, joined)
		}
	}
	if len(got) != 3 {
		t.Errorf("want 3 findings, got %d:\n%s", len(got), joined)
	}
}

func TestGood(t *testing.T) {
	got, err := scan("testdata/good")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		for _, f := range got {
			t.Errorf("unexpected: %s: %s", f.pos, f.msg)
		}
	}
}

func TestModule(t *testing.T) {
	got, err := scan("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		t.Errorf("%s: %s", f.pos, f.msg)
	}
}
