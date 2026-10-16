package inventory

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectLabUbuntu2404(t *testing.T) {
	dir := "../../testdata/lab/ubuntu2404"
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.FixedZone("x", -4*3600))
	s, db, err := Collect(os.DirFS(filepath.Join(dir, "root")), now)
	if err != nil {
		t.Fatal(err)
	}
	uname, err := os.ReadFile(filepath.Join(dir, "expected", "uname-r.txt"))
	if err != nil {
		t.Fatal(err)
	}
	query, err := os.ReadFile(filepath.Join(dir, "expected", "dpkg-query.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	running := strings.TrimSpace(string(uname))

	if s.Schema != Schema || !s.CollectedAt.Equal(now) || s.CollectedAt.Location() != time.UTC {
		t.Errorf("header: %q %v", s.Schema, s.CollectedAt)
	}
	if s.OS.ID != "ubuntu" || s.OS.VersionID != "24.04" || s.OS.VersionCodename != "noble" {
		t.Errorf("OS = %+v", s.OS)
	}
	if s.PackageDB.Format != "deb" || s.PackageDB.NativeArch != "amd64" || s.PackageDB.JournalReplayed != 0 {
		t.Errorf("PackageDB = %+v", s.PackageDB)
	}
	if n := bytes.Count(query, []byte("\n")); len(s.Packages) != n || len(db.Packages) != n {
		t.Errorf("%d packages, dpkg-query listed %d", len(s.Packages), n)
	}
	if s.Kernel.Running.Release != running || s.Kernel.NewestInstalled != running || !s.Kernel.EffectiveKnown {
		t.Errorf("Kernel = %+v, running %q", s.Kernel, running)
	}
	var found bool
	for _, k := range s.Kernel.Installed {
		if k.Release == running {
			found = k.Running && k.BootImage
		}
	}
	if !found {
		t.Errorf("running kernel %q not among installed %+v", running, s.Kernel.Installed)
	}

	// Spot checks on edge cases staged on the VM before capture.
	want := map[string]string{"at amd64": "config-files/deinstall", "nano amd64": "installed/hold", "libc6 i386": "installed/install"}
	for _, p := range s.Packages {
		if w, ok := want[p.Name+" "+p.Arch]; ok {
			if got := p.State + "/" + p.Want; got != w {
				t.Errorf("%s %s: %s, want %s", p.Name, p.Arch, got, w)
			}
			delete(want, p.Name+" "+p.Arch)
		}
	}
	if len(want) != 0 {
		t.Errorf("edge-case packages missing from fixture: %v", want)
	}
}

func TestCollectNoPackageDB(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte("ID=x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Collect(os.DirFS(root), time.Now()); err == nil || !strings.Contains(err.Error(), "no supported package database") {
		t.Errorf("err = %v", err)
	}
}
