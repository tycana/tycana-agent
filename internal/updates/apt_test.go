package updates

import (
	"context"
	"encoding/json"
	"flag"
	"maps"
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

// labCase is one captured host. now and sec are what the host's own tools
// say: installable now (phased and held excluded) and how many of those
// carry a security fix.
type labCase struct {
	dir        string
	nativeArch string
	held       []string
	states     map[State]int
	now, sec   int
}

var labCases = []labCase{
	// Ubuntu 24.04, 2026-10-16, before the VM's unattended-upgrades run:
	// 44 plain upgrades, 4 deferred by phasing (10% to 40%), 4 kernel
	// metapackages kept back, 6 new kernel packages, nano held with
	// nothing newer. apt-check printed "54;51".
	{
		dir: "ubuntu2404", nativeArch: "amd64", held: []string{"nano"},
		states: map[State]int{Upgrade: 44, Phased: 4, DistUpgrade: 4, New: 6},
		now:    54, sec: 51,
	},
	// Debian 12, 2026-10-16, with curl held (nothing newer) and openssl
	// held for this capture. apt list --upgradable: 10, all from
	// oldstable-security; the held openssl is one of them.
	{
		dir: "debian12", nativeArch: "amd64", held: []string{"curl", "openssl"},
		states: map[State]int{Upgrade: 9, Held: 1},
		now:    9, sec: 9,
	},
}

func TestAptLab(t *testing.T) {
	for _, c := range labCases {
		t.Run(c.dir, func(t *testing.T) {
			dir := filepath.Join("../../testdata/lab", c.dir, "updates")
			b, err := os.ReadFile(filepath.Join(dir, "apt-cache-policy-query.txt"))
			if err != nil {
				t.Fatal(err)
			}
			run := fixtureRunner(t, dir, strings.Fields(string(b)))
			r, err := collectApt(context.Background(), run, c.nativeArch, c.held)
			if err != nil {
				t.Fatal(err)
			}
			count := map[State]int{}
			now, sec := 0, 0
			for _, u := range r.Updates {
				count[u.State]++
				if u.State != Phased && u.State != Held {
					now++
					if u.Security {
						sec++
					}
				}
				if len(u.Origins) == 0 {
					t.Errorf("%s: no origins", u.Name)
				}
			}
			if !maps.Equal(count, c.states) {
				t.Errorf("states %v, want %v", count, c.states)
			}
			if now != c.now || sec != c.sec {
				t.Errorf("native tools say %d;%d, we say %d;%d", c.now, c.sec, now, sec)
			}
			golden(t, filepath.Join(dir, "report.golden.json"), r)
		})
	}
}

func TestSecurityRuleUbuntu(t *testing.T) {
	dir := "../../testdata/lab/ubuntu2404/updates"
	b, _ := os.ReadFile(filepath.Join(dir, "apt-cache-policy-query.txt"))
	r, err := collectApt(context.Background(), fixtureRunner(t, dir, strings.Fields(string(b))), "amd64", []string{"nano"})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Updates {
		switch u.Name {
		case "snapd":
			if u.PhasedPercent != 10 || u.Candidate != "2.77.1+ubuntu24.04" || u.Arch != "amd64" {
				t.Errorf("snapd: %+v", u)
			}
		case "libssl3t64", "tzdata":
			// tzdata: candidate in noble-updates only, an intermediate
			// version in noble-security.
			if !u.Security {
				t.Errorf("%s carries a security fix: %+v", u.Name, u)
			}
		}
	}
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
	if n := s.installs[1]; n.Installed != "" || n.Origins[0] != (Origin{Suite: "stable"}) || n.Security {
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
