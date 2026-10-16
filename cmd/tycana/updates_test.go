package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"tycana.ai/agent/internal/updates"
)

func TestWriteUpdatesText(t *testing.T) {
	b, err := os.ReadFile("../../testdata/lab/ubuntu2404/updates/report.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var r updates.Report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeUpdatesText(&out, r); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		"54 updates can be installed now (apt), 51 with a security fix.\n",
		"4 deferred by phasing.\n",
		"phased 10%",
		"tzdata:all",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}
