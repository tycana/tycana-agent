package history

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"tycana.ai/agent/internal/inventory/dpkg"
)

const dpkgLog = `2026-10-15 21:02:24 startup archives unpack
2026-10-15 21:02:24 install hello:amd64 <none> 2.10-3build1
2026-10-15 21:02:24 status half-installed hello:amd64 2.10-3build1
2026-10-15 21:02:24 status unpacked hello:amd64 2.10-3build1
2026-10-15 21:02:24 configure hello:amd64 2.10-3build1 <none>
2026-10-15 21:02:24 status half-configured hello:amd64 2.10-3build1
2026-10-15 21:02:24 status installed hello:amd64 2.10-3build1
2026-10-15 21:09:43 upgrade tzdata:all 2026c-0ubuntu0.24.04.1 2024a-2ubuntu1
2026-10-15 21:09:43 status installed tzdata:all 2024a-2ubuntu1
2026-10-15 21:10:35 upgrade hello:amd64 2.10-3build1 2.10-3build1
2026-10-15 21:10:35 status installed hello:amd64 2.10-3build1
2026-10-15 21:11:28 remove hello:amd64 2.10-3build1 <none>
2026-10-15 21:11:28 status config-files hello:amd64 2.10-3build1
2026-10-15 21:11:28 status not-installed hello:amd64 <none>
2026-10-15 21:12:00 remove at:amd64 3.2.5 <none>
2026-10-15 21:12:00 status config-files at:amd64 3.2.5
2026-10-15 21:12:01 purge at:amd64 3.2.5 <none>
2026-10-15 21:12:01 conffile /etc/at.deny remove
2026-10-15 21:12:01 status not-installed at:amd64 <none>
2026-10-15 21:13:00 install broken:amd64 <none> 1.0
2026-10-15 21:13:00 status half-installed broken:amd64 1.0
2026-10-15 21:13:01 status not-installed broken:amd64 <none>
2026-10-15 21:14:00 upgrade curl:amd64 8.5.0-2ubuntu10.15 8.5.0-2ubuntu10.16
2026-10-15 21:14:00 status half-configured curl:amd64 8.5.0-2ubuntu10.16
`

func TestParseDpkgLog(t *testing.T) {
	z := Zone{Name: "UTC", loc: time.UTC}
	got, err := parseDpkgLog([]byte(dpkgLog), z)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ kind, pkg, arch, from, to, end, endVer string }{
		{KindInstall, "hello", "amd64", "", "2.10-3build1", "installed", "2.10-3build1"},
		{KindDowngrade, "tzdata", "all", "2026c-0ubuntu0.24.04.1", "2024a-2ubuntu1", "installed", "2024a-2ubuntu1"},
		{KindReinstall, "hello", "amd64", "2.10-3build1", "2.10-3build1", "installed", "2.10-3build1"},
		{KindRemove, "hello", "amd64", "2.10-3build1", "", "config-files", "2.10-3build1"},
		{KindPurge, "hello", "amd64", "2.10-3build1", "", "not-installed", ""}, // no purge line in the log
		{KindRemove, "at", "amd64", "3.2.5", "", "config-files", "3.2.5"},
		{KindPurge, "at", "amd64", "3.2.5", "", "not-installed", ""},     // purge line present, counted once
		{KindInstall, "broken", "amd64", "", "1.0", "not-installed", ""}, // rolled back: not a purge
		{KindUpgrade, "curl", "amd64", "8.5.0-2ubuntu10.15", "8.5.0-2ubuntu10.16", "half-configured", "8.5.0-2ubuntu10.16"},
	}
	if len(got) != len(want) {
		for _, c := range got {
			t.Logf("%+v", c)
		}
		t.Fatalf("%d changes, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.Kind != w.kind || g.Package != w.pkg || g.Arch != w.arch || g.From != w.from || g.To != w.to ||
			g.EndState != w.end || g.EndVersion != w.endVer || g.Transaction != -1 {
			t.Errorf("change %d = %+v, want %+v", i, g, w)
		}
	}
	if got[0].LocalTime != "2026-10-15 21:02:24" || !got[0].Time.Equal(time.Date(2026, 10, 15, 21, 2, 24, 0, time.UTC)) {
		t.Errorf("time: %+v", got[0])
	}
	if _, err := parseDpkgLog([]byte("2026-10-15 21:02:24 install x\n"), z); err == nil {
		t.Error("short line: want error")
	}
	if _, err := parseDpkgLog([]byte("2026-13-15 21:02:24 install x:amd64 <none> 1\n"), z); err == nil {
		t.Error("bad date: want error")
	}
}

const aptLog = `Remove: orphan:amd64 (0.1)
End-Date: 2026-10-15  20:00:00

Start-Date: 2026-10-15  21:08:40
Commandline: apt-get install --only-upgrade -y -qq curl
Requested-By: operator (1000)
Upgrade: libcurl4t64:amd64 (8.5.0-2ubuntu10.15, 8.5.0-2ubuntu10.16), curl:amd64 (8.5.0-2ubuntu10.15, 8.5.0-2ubuntu10.16)
End-Date: 2026-10-15  21:08:41

Start-Date: 2026-10-15  21:20:00
Commandline: /usr/bin/unattended-upgrade
Install: linux-image-6.8.0-150-generic:amd64 (6.8.0-150.150, automatic)
Reinstall: hello:amd64 (2.10-3build1)
Purge: at:amd64 (3.2.5)
Error: Sub-process /usr/bin/dpkg returned an error code (1)
End-Date: 2026-10-15  21:20:05

Start-Date: 2026-10-15  21:30:00
Commandline: apt-get upgrade
`

func TestParseAptHistory(t *testing.T) {
	got, err := parseAptHistory([]byte(aptLog), Zone{Name: "UTC", loc: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%d transactions, want 3 (fragment skipped, unfinished kept)", len(got))
	}
	a := got[0]
	if a.RequestedBy != "operator" || a.RequestedByUID == nil || *a.RequestedByUID != 1000 || len(a.Changes) != 2 ||
		a.Changes[1] != (TransactionChange{Kind: KindUpgrade, Package: "curl", Arch: "amd64", From: "8.5.0-2ubuntu10.15", To: "8.5.0-2ubuntu10.16"}) {
		t.Errorf("first: %+v", a)
	}
	b := got[1]
	if b.RequestedBy != "" || b.RequestedByUID != nil || b.Error == "" || len(b.Changes) != 3 ||
		b.Changes[0] != (TransactionChange{Kind: KindInstall, Package: "linux-image-6.8.0-150-generic", Arch: "amd64", To: "6.8.0-150.150", Automatic: true}) ||
		b.Changes[1] != (TransactionChange{Kind: KindReinstall, Package: "hello", Arch: "amd64", From: "2.10-3build1", To: "2.10-3build1"}) ||
		b.Changes[2] != (TransactionChange{Kind: KindPurge, Package: "at", Arch: "amd64", From: "3.2.5"}) {
		t.Errorf("second: %+v", b)
	}
	if !got[2].End.IsZero() || got[2].Commandline != "apt-get upgrade" {
		t.Errorf("unfinished: %+v", got[2])
	}
	if _, err := parseAptHistory([]byte("Start-Date: 2026-10-15\n"), Zone{loc: time.UTC}); err == nil {
		t.Error("bad Start-Date: want error")
	}
	if _, err := parseAptHistory([]byte("Start-Date: 2026-10-15  21:00:00\nInstall: nover:amd64\n"), Zone{loc: time.UTC}); err == nil {
		t.Error("entry without version: want error")
	}
}

// writeTree materializes an in-memory tree in a temp directory, because
// Collect takes a path.
func writeTree(t *testing.T, fsys fstest.MapFS) string {
	t.Helper()
	root := t.TempDir()
	for name, f := range fsys {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if f.Mode&os.ModeSymlink != 0 {
			if err := os.Symlink(string(f.Data), p); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(p, f.Data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestCollectRotationsZoneAndLinking(t *testing.T) {
	tz, err := os.ReadFile("../../testdata/lab/ubuntu2404/root/usr/share/zoneinfo/America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"etc/localtime":                       {Data: []byte("/usr/share/zoneinfo/America/New_York"), Mode: os.ModeSymlink},
		"usr/share/zoneinfo/America/New_York": {Data: tz},
		"var/log/dpkg.log.2.gz":               {Data: gz(t, "2026-01-10 08:00:00 install old:amd64 <none> 1\n2026-01-10 08:00:00 status installed old:amd64 1\n")},
		"var/log/dpkg.log.1":                  {Data: []byte("2026-10-15 21:08:40 upgrade curl:amd64 1 2\n")},
		"var/log/dpkg.log":                    {Data: []byte("2026-10-15 21:08:41 status installed curl:amd64 2\n2026-10-15 22:00:00 install manual:amd64 <none> 1\n")},
		"var/log/dpkg.log.bak":                {Data: []byte("garbage that must not be read\n")},
		"var/log/apt/history.log.1.gz":        {Data: gz(t, "Start-Date: 2026-10-15  21:08:40\nUpgrade: curl:amd64 (1, 2)\nEnd-Date: 2026-10-15  21:08:41\n")},
	}
	h, err := Collect(writeTree(t, fsys))
	if err != nil {
		t.Fatal(err)
	}
	if h.Zone.Name != "America/New_York" || h.Zone.Source != "/usr/share/zoneinfo/America/New_York" {
		t.Errorf("zone %+v", h.Zone)
	}
	wantSources := []string{"/var/log/apt/history.log.1.gz", "/var/log/dpkg.log.2.gz", "/var/log/dpkg.log.1", "/var/log/dpkg.log"}
	if len(h.Sources) != len(wantSources) {
		t.Fatalf("sources %v", h.Sources)
	}
	for i := range wantSources {
		if h.Sources[i] != wantSources[i] {
			t.Errorf("sources %v, want %v", h.Sources, wantSources)
		}
	}
	if len(h.Changes) != 3 || h.Changes[0].Package != "old" || h.Changes[1].EndState != "installed" {
		t.Fatalf("changes %+v", h.Changes)
	}
	// EST in January (UTC-5), EDT in October (UTC-4).
	if !h.Changes[0].Time.Equal(time.Date(2026, 1, 10, 13, 0, 0, 0, time.UTC)) ||
		!h.Changes[1].Time.Equal(time.Date(2026, 10, 16, 1, 8, 40, 0, time.UTC)) {
		t.Errorf("UTC conversion: %v %v", h.Changes[0].Time, h.Changes[1].Time)
	}
	if h.Changes[0].Transaction != -1 || h.Changes[1].Transaction != 0 || h.Changes[2].Transaction != -1 {
		t.Errorf("linking: %d %d %d", h.Changes[0].Transaction, h.Changes[1].Transaction, h.Changes[2].Transaction)
	}
	s := h.Since(time.Date(2026, 10, 16, 1, 30, 0, 0, time.UTC))
	if len(s.Changes) != 1 || len(s.Transactions) != 0 || s.Changes[0].Package != "manual" || s.Changes[0].Transaction != -1 {
		t.Errorf("Since: %+v", s)
	}
	s = h.Since(time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC))
	if len(s.Changes) != 2 || len(s.Transactions) != 1 || s.Changes[0].Transaction != 0 {
		t.Errorf("Since with transaction: %+v", s)
	}
}

func TestZoneFallbacksAndDST(t *testing.T) {
	h, err := Collect(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if h.Zone.Name != "UTC" || len(h.Changes) != 0 || len(h.Transactions) != 0 {
		t.Errorf("empty root: %+v", h)
	}
	tz, err := os.ReadFile("../../testdata/lab/ubuntu2404/root/usr/share/zoneinfo/America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	z, err := hostZone(fstest.MapFS{"etc/localtime": {Data: tz}, "etc/timezone": {Data: []byte("America/New_York\n")}})
	if err != nil {
		t.Fatal(err)
	}
	// 2026-11-01 01:30 happens twice in New York.
	amb, _ := z.parse("2026-11-01", "01:30:00")
	plain, _ := z.parse("2026-10-15", "12:00:00")
	if z.Name != "America/New_York" || !z.ambiguous(amb) || z.ambiguous(plain) {
		t.Errorf("zone %+v ambiguous(amb)=%v ambiguous(plain)=%v", z, z.ambiguous(amb), z.ambiguous(plain))
	}
}

// TestLabHistoryAgreesWithDatabase checks the captured logs against the
// captured dpkg database from the same moment: every apt change has a
// matching dpkg change in the same transaction, and replaying dpkg.log
// ends in exactly the state and version the database holds.
func TestLabHistoryAgreesWithDatabase(t *testing.T) {
	dirs, err := filepath.Glob("../../testdata/lab/*/root/var/lib/dpkg/status")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("dpkg fixtures: %v, %v", dirs, err)
	}
	for _, status := range dirs {
		root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(status))))
		t.Run(filepath.Base(filepath.Dir(root)), func(t *testing.T) { labHistoryAgrees(t, root) })
	}
}

func labHistoryAgrees(t *testing.T, root string) {
	t.Helper()
	h, err := Collect(root)
	if err != nil {
		t.Fatal(err)
	}
	db, err := dpkg.ReadDatabase(os.DirFS(root), dpkg.DefaultAdminDir)
	if err != nil {
		t.Fatal(err)
	}
	ubuntu := strings.Contains(root, "ubuntu2404")
	if ubuntu && (h.Zone.Name != "America/New_York" || len(h.Transactions) < 7 || len(h.Changes) < 20) {
		t.Fatalf("zone %q, %d transactions, %d changes", h.Zone.Name, len(h.Transactions), len(h.Changes))
	}
	if len(h.Transactions) == 0 || len(h.Changes) == 0 {
		t.Fatalf("%d transactions, %d changes", len(h.Transactions), len(h.Changes))
	}

	for ti, tr := range h.Transactions {
		for _, ac := range tr.Changes {
			found := false
			for _, c := range h.Changes {
				if c.Transaction == ti && c.Package == ac.Package && c.Kind == ac.Kind &&
					(c.Arch == ac.Arch || c.Arch == "all") && c.From == ac.From && c.To == ac.To {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("apt %s %s:%s (%s -> %s) in %q has no matching dpkg change", ac.Kind, ac.Package, ac.Arch, ac.From, ac.To, tr.Commandline)
			}
		}
	}

	final := map[string]Change{}
	for _, c := range h.Changes {
		final[c.Package+":"+c.Arch] = c
	}
	have := map[string]dpkg.Package{}
	for _, p := range db.Packages {
		have[p.Name+":"+p.Architecture] = p
	}
	kinds := map[string]bool{}
	for key, c := range final {
		kinds[c.Kind] = true
		p, ok := have[key]
		switch {
		case c.EndState == "not-installed" && ok:
			t.Errorf("%s: log ends not-installed, database has %s %s", key, p.State, p.Version)
		case c.EndState != "not-installed" && !ok:
			t.Errorf("%s: log ends %s %s, database has nothing", key, c.EndState, c.EndVersion)
		case ok && (p.State != c.EndState || p.Version.String() != c.EndVersion):
			t.Errorf("%s: log ends %s %s, database has %s %s", key, c.EndState, c.EndVersion, p.State, p.Version)
		}
	}
	if !ubuntu {
		return
	}
	for _, k := range []string{KindInstall, KindUpgrade, KindDowngrade, KindRemove, KindPurge} {
		if !kinds[k] {
			t.Errorf("fixture no longer exercises a final %q change", k)
		}
	}
}
