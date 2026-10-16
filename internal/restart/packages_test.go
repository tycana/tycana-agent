package restart

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDpkgChanges(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	at := time.Date(2026, 10, 16, 14, 34, 28, 520790449, time.UTC)
	for _, n := range []string{"libssl3t64:amd64.list", "tzdata.list", "tzdata.md5sums"} {
		writeFile(t, root, "/var/lib/dpkg/info/"+n, nil)
		must(t, os.Chtimes(filepath.Join(info, n), at, at))
	}
	got, err := DpkgChanges(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "libssl3t64:amd64" || !got[0].Changed.Equal(at) || got[0].Coarse {
		t.Errorf("%+v", got)
	}
}

func TestPackageRule(t *testing.T) {
	t0 := time.Date(2026, 10, 16, 14, 16, 20, 500000000, time.UTC)
	snap := Snapshot{
		Units: []Unit{
			{ID: "old.service", MainPID: 1, Start: t0, Exec: "/bin/a"},
			{ID: "new.service", MainPID: 2, Start: t0.Add(time.Hour), Exec: "/bin/a"},
			{ID: "script.service", MainPID: 3, Start: t0.Add(time.Hour), Exec: "/bin/s"},
			{ID: "init.scope", Start: t0},
			{ID: "same-second.service", MainPID: 4, Start: t0.Add(30 * time.Minute).Add(200 * time.Millisecond), Exec: "/bin/a"},
			{ID: "nostart.service", MainPID: 5, Exec: "/bin/a"},
		},
		Programs: map[string]Program{
			"/bin/a": {Path: "/bin/a", Closure: []string{"/bin/a"}},
			"/bin/s": {Path: "/bin/s", Interpreter: "/bin/py", Closure: []string{"/bin/py"}},
		},
		Files: map[string]FileTime{"/bin/a": {Time: t0.Add(-time.Hour)}, "/bin/py": {Time: t0.Add(-time.Hour)}},
		Packages: []PackageChange{
			{Name: "libcurl4", Changed: t0.Add(10 * time.Minute)},
			{Name: "glibc", Changed: t0.Add(30 * time.Minute), Coarse: true}, // whole second
		},
	}
	want := map[string]Status{
		"old.service":         Possible, // two packages changed after it started
		"new.service":         None,     // nothing changed after it started
		"script.service":      None,     // a script, but nothing changed after it started
		"init.scope":          Possible,
		"same-second.service": Possible, // started inside glibc's install second
		"nostart.service":     Unknown,
	}
	r := Analyze(snap)
	for _, f := range r.Findings {
		if f.Status != want[f.Unit] {
			t.Errorf("%s: %s (%s), want %s", f.Unit, f.Status, f.Reason, want[f.Unit])
		}
		if f.Unit == "old.service" && (f.ChangedCount != 2 || !slices.Equal(f.Changed, []string{"glibc", "libcurl4"})) {
			t.Errorf("old.service changed %v (%d)", f.Changed, f.ChangedCount)
		}
		if f.Status == None && !strings.Contains(f.Reason, "no package changed") {
			t.Errorf("%s: reason %q", f.Unit, f.Reason)
		}
	}
	h := Host(snap, r)
	if h.State != "restart-needed" || h.Possible != 3 || h.Unknown != 1 || !h.PackageData || !h.LatestChange.Equal(t0.Add(30*time.Minute)) {
		t.Errorf("%+v", h)
	}
	if h := Host(Snapshot{}, Report{}); h.State != "unknown" || h.PackageData {
		t.Errorf("no package data: %+v", h)
	}
}

func TestDetectLivePatching(t *testing.T) {
	root := t.TempDir()
	if lp := DetectLivePatching(root, nil, nil, []PackageInfo{{Name: "glibc", Version: "2.34", Release: "100.el9"}}); len(lp.Kernel)+len(lp.UserSpace) != 0 {
		t.Errorf("plain host: %+v", lp)
	}
	writeFile(t, root, "/proc/kcare/effective_version", []byte("5.14.0-687.57.1.el9_8.x86_64\n"))
	lp := DetectLivePatching(root, []string{"kpatch_5_14_0_1_1"}, []string{"ksplice_abc"}, []PackageInfo{
		{Name: "glibc", Version: "2.34", Release: "100.0.1.el9_6.ksplice1"},
		{Name: "kernelcare", Version: "2.90", Release: "1"},
	})
	if len(lp.Kernel) != 3 || !strings.Contains(lp.Kernel[2], "effective kernel 5.14.0-687.57.1") {
		t.Errorf("kernel %q", lp.Kernel)
	}
	if len(lp.UserSpace) != 2 || !strings.Contains(lp.UserSpace[0], "Ksplice-aware glibc") {
		t.Errorf("user space %q", lp.UserSpace)
	}
}
