package updates

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"tycana.ai/agent/internal/hostexec"
)

// AlmaLinux 9, 2026-10-16, from the system metadata cache as nobody: 66
// updates. dnf's own "check-update --security" lists 55 packages; the
// updateinfo summary counts 54 security notices.
func TestDnfAlma9(t *testing.T) {
	dir := "../../testdata/lab/alma9/updates"
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	run := func(_ context.Context, id hostexec.ID, _ ...string) (hostexec.Result, error) {
		switch id {
		case hostexec.DnfCheckUpdate:
			return hostexec.Result{Stdout: read("dnf-check-update.txt"), ExitCode: 100}, nil
		case hostexec.DnfUpdateinfo:
			return hostexec.Result{Stdout: read("dnf-updateinfo.txt")}, nil
		}
		t.Fatalf("unexpected command %s", id)
		return hostexec.Result{}, nil
	}
	installed := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(read("installed.tsv"))), "\n") {
		k, v, _ := strings.Cut(line, "\t")
		installed[k] = v
	}
	r, err := collectDnf(context.Background(), run, installed)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Updates) != 66 {
		t.Errorf("%d updates, want 66", len(r.Updates))
	}
	// The security set must be exactly dnf's own.
	var want, got []string
	for _, line := range strings.Split(string(read("dnf-check-update-security.txt")), "\n") {
		if f := strings.Fields(line); len(f) == 3 {
			want = append(want, f[0])
		}
	}
	ids := map[string]bool{}
	for _, u := range r.Updates {
		if u.Installed == "" || u.Installed == u.Candidate {
			t.Errorf("%s.%s: installed %q, candidate %q", u.Name, u.Arch, u.Installed, u.Candidate)
		}
		if u.Security {
			got = append(got, u.Name+"."+u.Arch)
		}
		for _, a := range u.Advisories {
			ids[a.ID] = true
		}
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("security set differs from dnf check-update --security:\n got %v\nwant %v", got, want)
	}
	if len(ids) != 54 {
		t.Errorf("%d advisories, want 54", len(ids))
	}
	golden(t, filepath.Join(dir, "report.golden.json"), r)
}

func TestParseCheckUpdateWrapped(t *testing.T) {
	out := []byte(`
a-very-long-package-name-that-dnf-wraps.x86_64
                        1.0-2.el9                baseos
short.noarch            2:3.4-5.el9              appstream
Obsoleting Packages
grub2-tools.x86_64      1:2.06-80.el9            baseos
    grub2-tools.x86_64  1:2.06-70.el9            @System
`)
	ups, err := parseCheckUpdate(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 2 || ups[0].Name != "a-very-long-package-name-that-dnf-wraps" || ups[0].Candidate != "1.0-2.el9" ||
		ups[1].Arch != "noarch" || ups[1].Candidate != "2:3.4-5.el9" || ups[1].Origins[0].Suite != "appstream" {
		t.Errorf("%+v", ups)
	}
	if _, err := parseCheckUpdate([]byte("a.x86_64 1.0 repo extra\n")); err == nil {
		t.Error("accepted a row with four fields")
	}
}

func TestSplitNEVRA(t *testing.T) {
	for in, want := range map[string]string{
		"NetworkManager-libnm-1:1.54.3-5.el9_8.x86_64": "NetworkManager-libnm.x86_64",
		"python3-libs-3.9.25-3.el9_8.1.x86_64":         "python3-libs.x86_64",
		"tzdata-2026e-1.el9_8.noarch":                  "tzdata.noarch",
	} {
		n, a, err := splitNEVRA(in)
		if err != nil || n+"."+a != want {
			t.Errorf("%s: %s.%s %v, want %s", in, n, a, err, want)
		}
	}
	if _, _, err := splitNEVRA("noversion.x86_64"); err == nil {
		t.Error("accepted a name without version")
	}
}
