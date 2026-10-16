package restart

import (
	"bufio"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestLabUbuntu2404 replays the restart state of tycana-ubuntu2404 after
// its own unattended-upgrades run on 2026-10-16 (testdata README) against
// the root ground truth captured at the same moment: the units whose
// processes mapped a deleted file in /proc/<pid>/maps.
//
// The property under test is the one the product promises: a unit the
// agent calls "inferred" is stale, and a stale unit is never "none".
func TestLabUbuntu2404(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "lab", "ubuntu2404", "restart")
	snap := readSnapshotFile(t, filepath.Join(dir, "snapshot.json"))
	stale := groundTruth(t, filepath.Join(dir, "deleted-maps.tsv"))

	got := map[string]Status{}
	for _, f := range Analyze(snap).Findings {
		got[f.Unit] = f.Status
		switch {
		case f.Status == Inferred && !stale[f.Unit]:
			t.Errorf("%s: inferred, but no process of it mapped a deleted file", f.Unit)
		case f.Status == None && stale[f.Unit]:
			t.Errorf("%s: none, but root saw it map a deleted file", f.Unit)
		}
	}
	for u := range stale {
		if _, ok := got[u]; !ok {
			t.Errorf("%s: stale per root, absent from the snapshot", u)
		}
	}
	// The measured result, recorded for backlog item B1. A change here
	// changes what the brief reports.
	want := map[string]Status{
		"dbus.service":                Inferred,
		"systemd-logind.service":      Inferred,
		"session-4.scope":             Inferred,
		"user@1000.service":           Inferred,
		"unattended-upgrades.service": Unknown, // python3: libsystemd and libudev via modules
		"init.scope":                  Unknown,
	}
	for u, w := range want {
		if got[u] != w {
			t.Errorf("%s: %s, want %s", u, got[u], w)
		}
	}
	n := 0
	for _, s := range got {
		if s == None {
			n++
		}
	}
	if n != 17 {
		t.Errorf("%d units none, want 17", n)
	}
}

func readSnapshotFile(t *testing.T, name string) Snapshot {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var s Snapshot
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// groundTruth reads deleted-maps.tsv (pid, cgroup, exe, deleted paths) and
// returns the units with a stale process. A process in a user manager's
// init.scope belongs to user@UID.service.
func groundTruth(t *testing.T, name string) map[string]bool {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	stale := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 4 {
			continue
		}
		parts := strings.Split(fields[1], "/")
		if parts[len(parts)-1] == "init.scope" && len(parts) > 1 {
			parts = parts[:len(parts)-1]
		}
		stale[parts[len(parts)-1]] = true
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(stale) == 0 {
		t.Fatal("empty ground truth")
	}
	t.Logf("stale per root: %v", slices.Sorted(maps.Keys(stale)))
	return stale
}
