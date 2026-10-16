package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/inventory/dpkg"
	"tycana.ai/agent/internal/inventory/rpm"
)

func fakeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"etc/os-release":                "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n",
		"proc/sys/kernel/osrelease":     "6.8.0-45-generic\n",
		"boot/vmlinuz-6.8.0-45-generic": "",
		"var/lib/dpkg/status":           "",
		"var/lib/dpkg/updates/.keep":    "",
	}
	status, err := os.ReadFile("../../internal/inventory/dpkg/testdata/synthetic/var/lib/dpkg/status")
	if err != nil {
		t.Fatal(err)
	}
	files["var/lib/dpkg/status"] = string(status)
	for name, data := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestInventoryFormats(t *testing.T) {
	root := fakeRoot(t)

	var out, errb bytes.Buffer
	if code := run([]string{"inventory", "--root", root}, &out, &errb); code != 0 {
		t.Fatalf("text: exit %d: %s", code, errb.String())
	}
	for _, want := range []string{"Ubuntu 24.04 LTS", "6.8.0-45-generic", "installed,held", "zlib 1:1.3.dfsg-3.1ubuntu2"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("text output missing %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if code := run([]string{"inventory", "--root", root, "--format", "json"}, &out, &errb); code != 0 {
		t.Fatalf("json: exit %d: %s", code, errb.String())
	}
	var snap inventory.Snapshot
	if err := json.Unmarshal(out.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Schema != inventory.Schema || snap.OS.ID != "ubuntu" || len(snap.Packages) != 8 || snap.PackageDB.NativeArch != "amd64" {
		t.Errorf("json snapshot: %+v", snap)
	}

	out.Reset()
	if code := run([]string{"inventory", "--root", root, "--format", "dpkg-query"}, &out, &errb); code != 0 {
		t.Fatalf("dpkg-query: exit %d: %s", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), "rc \tat\t3.2.5-2.1ubuntu3\tamd64\t") {
		t.Errorf("dpkg-query output starts %q", out.String()[:40])
	}
}

func TestInventoryErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"inventory", "--root", t.TempDir()}, &out, &errb); code != 1 {
		t.Errorf("empty root: exit %d, want 1", code)
	}
	if code := run([]string{"inventory", "--format", "xml", "--root", fakeRoot(t)}, &out, &errb); code != 2 {
		t.Errorf("bad format: exit %d, want 2", code)
	}
	if code := run([]string{"inventory", "extra"}, &out, &errb); code != 2 {
		t.Errorf("extra arg: exit %d, want 2", code)
	}
}

func TestLabScriptFormatInSync(t *testing.T) {
	for script, format := range map[string]string{"lab-dpkg.sh": dpkg.QueryFormat, "lab-rpm.sh": rpm.QueryFormat} {
		b, err := os.ReadFile("../../scripts/" + script)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "FORMAT='"+format+"'") {
			t.Errorf("scripts/%s FORMAT differs from the package's QueryFormat %q", script, format)
		}
	}
}

func TestInventoryWrongNativeFormat(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"inventory", "--root", fakeRoot(t), "--format", "rpm-query"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "is deb, not rpm") {
		t.Errorf("rpm-query on a deb host: exit %d, stderr %q", code, errb.String())
	}
}
