package main

import (
	"bytes"
	"strings"
	"testing"

	"tycana.ai/agent/internal/collect"
	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/restart"
	"tycana.ai/agent/internal/updates"
)

func TestGroupUpdatesDpkg(t *testing.T) {
	inv := &inventory.Snapshot{PackageDB: inventory.PackageDB{Format: "deb"}, Packages: []inventory.Package{
		{Name: "libssl3t64", Arch: "amd64", SourceName: "openssl", SourceEVR: "3.0.13-0ubuntu3.4"},
		{Name: "openssl", Arch: "amd64", SourceName: "openssl", SourceEVR: "3.0.13-0ubuntu3.4"},
		{Name: "vim", Arch: "amd64", SourceName: "vim", SourceEVR: "2:9.1.0016-1ubuntu7.3"},
		{Name: "tzdata", Arch: "all", SourceName: "tzdata", SourceEVR: "2024a"},
		{Name: "snapd", Arch: "amd64", SourceName: "snapd", SourceEVR: "2.63"},
	}}
	r := &updates.Report{Updates: []updates.Update{
		{Name: "vim", Arch: "amd64", Security: true, State: updates.Upgrade},
		{Name: "libssl3t64", Arch: "amd64", Security: true, State: updates.Upgrade},
		{Name: "openssl", Arch: "amd64", Security: true, State: updates.Upgrade},
		{Name: "tzdata", Arch: "all", State: updates.Upgrade},
		{Name: "snapd", Arch: "amd64", State: updates.Phased},
	}}
	acts, phased, held := groupUpdates(inv, r)
	if len(acts) != 3 || phased != 1 || held != 0 {
		t.Fatalf("%d actions, %d phased, %d held: %+v", len(acts), phased, held, acts)
	}
	if acts[0].name != "openssl" || len(acts[0].pkgs) != 2 || !acts[0].security || acts[1].name != "vim" || acts[2].security {
		t.Errorf("order or grouping: %+v", acts)
	}
}

func TestGroupUpdatesRPM(t *testing.T) {
	inv := &inventory.Snapshot{PackageDB: inventory.PackageDB{Format: "rpm"}, Packages: []inventory.Package{
		{Name: "openssl-libs", Arch: "x86_64", SourceName: "openssl"},
		{Name: "openssl", Arch: "x86_64", SourceName: "openssl"},
		{Name: "curl", Arch: "x86_64", SourceName: "curl"},
	}}
	adv := func(id, sev string) []updates.Advisory {
		return []updates.Advisory{{ID: id, Type: "security", Severity: sev}}
	}
	r := &updates.Report{Updates: []updates.Update{
		{Name: "curl", Arch: "x86_64", Security: true, State: updates.Upgrade, Advisories: adv("ALSA-2026:2", "Moderate")},
		{Name: "openssl-libs", Arch: "x86_64", Security: true, State: updates.Upgrade, Advisories: adv("ALSA-2026:1", "Important")},
		{Name: "openssl", Arch: "x86_64", Security: true, State: updates.Upgrade, Advisories: adv("ALSA-2026:1", "Important")},
	}}
	acts, _, _ := groupUpdates(inv, r)
	if len(acts) != 2 || acts[0].name != "ALSA-2026:1" || len(acts[0].pkgs) != 2 || acts[0].severity != "Important" {
		t.Errorf("%+v", acts)
	}
}

func TestWriteStatus(t *testing.T) {
	inv := &inventory.Snapshot{PackageDB: inventory.PackageDB{Format: "deb"}}
	rs := &collect.Restart{Kernel: &collect.KernelRestart{Running: "6.8.0-45-generic", NewestInstalled: "6.8.0-49-generic", RebootNeeded: true}}
	rs.Findings = []restart.Finding{{Unit: "nginx.service", Status: restart.Inferred}}
	var b bytes.Buffer
	writeStatus(&b, statusView{inv: inv, updates: &updates.Report{}, restart: rs, tags: map[string]string{"owner": "web"}, signed: "Signed state: x."})
	out := b.String()
	for _, want := range []string{"Tags (the operator's", "owner=web", "1. reboot: kernel 6.8.0-45-generic runs", "2. restart 1 services", "no CVE data"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}
