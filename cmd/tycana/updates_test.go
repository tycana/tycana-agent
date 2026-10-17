package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"tycana.ai/agent/internal/collect"

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

func TestWriteAutopilotText(t *testing.T) {
	var out bytes.Buffer
	writeAutopilotText(&out, &updates.Autopilot{
		Tool: "unattended-upgrades", Installed: true, Why: []string{"apt-daily-upgrade.timer is masked"},
		Origins: []string{"Ubuntu:noble-security"}, Reboot: "never",
		Install: []updates.Planned{{Name: "libssl3t64", Security: true}, {Name: "tzdata"}},
		Skip:    []updates.Skipped{{Name: "snapd", Reason: "no newer version from an allowed origin"}},
	})
	for _, want := range []string{
		"Autopilot: unattended-upgrades will not run: apt-daily-upgrade.timer is masked.\n",
		"If it ran, it would install 2 of these updates (1 with a security fix) and leaves 1, judged on today's package lists.\n",
		"Automatic reboot: never.\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	out.Reset()
	writeAutopilotText(&out, &updates.Autopilot{Tool: "dnf-automatic"})
	if !strings.Contains(out.String(), "dnf-automatic is not installed. Nothing installs updates on its own.") {
		t.Errorf("not installed:\n%s", out.String())
	}
	if collect.DistroID("ubuntu") != "Ubuntu" || collect.DistroID("debian") != "Debian" || collect.DistroID("") != "" {
		t.Error("distroID")
	}
}
