package inventory

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// materialize copies a lab fixture's root/ tree to a temp directory,
// decompressing *.gz files, because SQLite opens databases by path and
// the rpm fixture is committed gzipped.
func materialize(t *testing.T, fixtureRoot string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(fixtureRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(fixtureRoot, p)
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, out)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".gz") {
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return err
			}
			if data, err = io.ReadAll(zr); err != nil {
				return err
			}
			out = strings.TrimSuffix(out, ".gz")
		}
		return os.WriteFile(out, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestCollectLabAlma9(t *testing.T) {
	dir := "../../testdata/lab/alma9"
	root := materialize(t, filepath.Join(dir, "root"))
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	s, native, err := Collect(root, now)
	if err != nil {
		t.Fatal(err)
	}
	uname, err := os.ReadFile(filepath.Join(dir, "expected", "uname-r.txt"))
	if err != nil {
		t.Fatal(err)
	}
	query, err := os.ReadFile(filepath.Join(dir, "expected", "rpm-qa.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	running := strings.TrimSpace(string(uname))

	if s.OS.ID != "almalinux" || s.OS.VersionID != "9.8" || !strings.Contains(s.OS.IDLike[0], "rhel") {
		t.Errorf("OS = %+v", s.OS)
	}
	if s.PackageDB.Format != "rpm" || s.PackageDB.Path != "/var/lib/rpm" || s.PackageDB.NativeArch != "x86_64" || s.PackageDB.Retries != 0 || len(s.PackageDB.Notes) != 0 {
		t.Errorf("PackageDB = %+v", s.PackageDB)
	}
	if n := bytes.Count(query, []byte("\n")); len(s.Packages) != n || native.RPM == nil || len(native.RPM.Packages) != n || native.Dpkg != nil {
		t.Errorf("%d packages, rpm -qa listed %d", len(s.Packages), n)
	}
	if s.Kernel.Running.Release != running || s.Kernel.NewestInstalled != running || !s.Kernel.EffectiveKnown || len(s.Kernel.Installed) != 1 {
		t.Errorf("Kernel = %+v, running %q", s.Kernel, running)
	}
	if k := s.Kernel.Installed[0]; k.Package != "kernel-core" || !k.Running || !k.BootImage {
		t.Errorf("installed kernel: %+v", k)
	}

	// Spot checks on state staged on the VM before capture.
	byName := map[string]Package{}
	for _, p := range s.Packages {
		byName[p.Name] = p
	}
	if p := byName["tzdata"]; p.EVR != "2026b-1.el9" || p.Arch != "noarch" || p.SourceName != "tzdata" || p.SourceEVR != "2026b-1.el9" || p.State != "installed" {
		t.Errorf("tzdata (downgraded on the VM): %+v", p)
	}
	if p := byName["openssl"]; p.Epoch != 1 || !strings.HasPrefix(p.EVR, "1:3.5.8-") || p.Version != "3.5.8" {
		t.Errorf("openssl (epoch 1): %+v", p)
	}
	if p := byName["gpg-pubkey"]; p.Arch != "" || p.SourceName != "" || p.PackageID != "" || p.InstalledAt.IsZero() {
		t.Errorf("gpg-pubkey: %+v", p)
	}
	if p := byName["bash"]; p.PackageID == "" || p.InstalledAt.IsZero() || p.InstalledSizeBytes == 0 || p.License == "" || p.Vendor == "" {
		t.Errorf("bash header tags: %+v", p)
	}
	if _, ok := byName["tree"]; ok {
		t.Error("tree was removed on the VM but is in the inventory")
	}
}
