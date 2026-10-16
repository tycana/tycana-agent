package updates

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"tycana.ai/agent/internal/hostexec"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixtureRunner answers each registered command with a captured output.
func fixtureRunner(t *testing.T, dir string, wantPolicy []string) runner {
	t.Helper()
	files := map[hostexec.ID]string{
		hostexec.AptSimulateDistUpgrade: "apt-simulate-dist-upgrade.txt",
		hostexec.AptSimulateUpgrade:     "apt-simulate-upgrade.txt",
		hostexec.AptCachePolicy:         "apt-cache-policy.txt",
	}
	return func(_ context.Context, id hostexec.ID, extra ...string) (hostexec.Result, error) {
		if id == hostexec.AptCachePolicy && !slices.Equal(extra, wantPolicy) {
			t.Errorf("policy asked for %q, fixture has %q", extra, wantPolicy)
		}
		b, err := os.ReadFile(filepath.Join(dir, files[id]))
		return hostexec.Result{Stdout: b}, err
	}
}

func golden(t *testing.T, path string, got any) {
	t.Helper()
	b, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if *update {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(b) {
		t.Errorf("%s differs; run go test -update and review the diff", path)
	}
}

// Ubuntu 24.04 lab VM, 2026-10-16: 44 plain upgrades, 4 deferred by
// phasing (10% and 30%), 4 kernel metapackages kept back, 6 new kernel packages,
// nano held with nothing newer.
func TestAptUbuntu2404(t *testing.T) {
	dir := "../../testdata/lab/ubuntu2404/updates"
	b, err := os.ReadFile(filepath.Join(dir, "apt-cache-policy-query.txt"))
	if err != nil {
		t.Fatal(err)
	}
	run := fixtureRunner(t, dir, strings.Fields(string(b)))
	r, err := collectApt(context.Background(), run, "amd64", []string{"nano"})
	if err != nil {
		t.Fatal(err)
	}
	count := map[State]int{}
	for _, u := range r.Updates {
		count[u.State]++
	}
	want := map[State]int{Upgrade: 44, Phased: 4, DistUpgrade: 4, New: 6}
	for s, n := range want {
		if count[s] != n {
			t.Errorf("%s: %d updates, want %d", s, count[s], n)
		}
	}
	if len(count) != len(want) {
		t.Errorf("states %v, want %v", count, want)
	}
	for _, u := range r.Updates {
		if u.Name == "snapd" && (u.PhasedPercent != 10 || u.Candidate != "2.77.1+ubuntu24.04" || u.Arch != "amd64") {
			t.Errorf("snapd: %+v", u)
		}
		if (u.Name == "libssl3t64" || u.Name == "tzdata") && !u.Security {
			t.Errorf("%s carries a security fix: %+v", u.Name, u)
		}
	}
	// Ubuntu's own count on the same VM: apt-check printed "54;51", 54
	// installable now (phased excluded) of which 51 carry a security fix.
	now, sec := 0, 0
	for _, u := range r.Updates {
		if u.State != Phased && u.State != Held {
			now++
			if u.Security {
				sec++
			}
		}
	}
	if now != 54 || sec != 51 {
		t.Errorf("apt-check says 54;51, we say %d;%d", now, sec)
	}
	golden(t, filepath.Join(dir, "report.golden.json"), r)
}

func TestParseSimulationLines(t *testing.T) {
	out := []byte(`The following packages will be REMOVED:
  oldpkg
Inst libc6:i386 [2.39-0ubuntu8.5] (2.39-0ubuntu8.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [i386]) []
Inst newpkg (1.0 Debian:12.7/stable [all])
Inst localpkg [0.9] (1.0 [amd64])
Remv oldpkg [3.1]
Conf newpkg (1.0 Debian:12.7/stable [all])
`)
	s, err := parseSimulation(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.installs) != 3 || len(s.removals) != 1 {
		t.Fatalf("%+v", s)
	}
	libc := s.installs[0]
	if libc.Name != "libc6" || libc.Arch != "i386" || libc.Installed != "2.39-0ubuntu8.5" || !libc.Security || len(libc.Origins) != 2 {
		t.Errorf("libc6: %+v", libc)
	}
	if n := s.installs[1]; n.Installed != "" || n.Origins[0] != (Origin{Label: "Debian", Suite: "stable"}) || n.Security {
		t.Errorf("newpkg: %+v", n)
	}
	if l := s.installs[2]; l.Candidate != "1.0" || len(l.Origins) != 0 {
		t.Errorf("localpkg: %+v", l)
	}
	if s.removals[0] != (Removal{Name: "oldpkg", Installed: "3.1"}) {
		t.Errorf("removal: %+v", s.removals[0])
	}
	if !slices.Equal(s.lists["The following packages will be REMOVED:"], []string{"oldpkg"}) {
		t.Errorf("lists: %v", s.lists)
	}
	if _, err := parseSimulation([]byte("Inst garbage\n")); err == nil {
		t.Error("accepted a malformed Inst line")
	}
}

func TestParsePolicyRejectsUnknownLines(t *testing.T) {
	if _, err := parsePolicy([]byte("curl:\n  Installed: 1\n  Surprise: x\n")); err == nil {
		t.Error("accepted an unknown line")
	}
}
