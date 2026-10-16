package restart

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLabAlmaNeedsRestarting compares the agent's rule with the output of
// "dnf needs-restarting -r" on the same host and moment.
func TestLabAlmaNeedsRestarting(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "lab", "alma9", "restart")
	f, err := os.Open(filepath.Join(dir, "installtime.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var pkgs []Installed
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, at, _ := strings.Cut(sc.Text(), " ")
		s, err := strconv.ParseInt(at, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, Installed{Name: name, At: time.Unix(s, 0)})
	}
	root := t.TempDir()
	b, err := os.ReadFile(filepath.Join(dir, "proc-stat-btime"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "/proc/stat", append([]byte("cpu  1 2 3\n"), b...))
	boot, err := BootTime(root)
	if err != nil {
		t.Fatal(err)
	}
	h := NeedsRestarting(root, pkgs, boot)

	// The names dnf printed, from needs-restarting.txt.
	out, err := os.ReadFile(filepath.Join(dir, "needs-restarting.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, line := range strings.Split(string(out), "\n") {
		if n, ok := strings.CutPrefix(line, "  * "); ok {
			want = append(want, n)
		}
	}
	if !h.Required || !slices.Equal(h.Packages, want) {
		t.Errorf("agent %v %q, dnf %q", h.Required, h.Packages, want)
	}
}

// TestLabOracleUEK: on Oracle Linux 9 only kernel-uek-core was updated.
// dnf needs-restarting -r asked for a reboot; the agent's built-in Red Hat
// list does not know kernel-uek-core and said "not required" (2026-10-16).
// With the host's own list it agrees with dnf.
func TestLabOracleUEK(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "lab", "oel9", "reboot")
	pkgs := readInstallTimes(t, filepath.Join(dir, "installtime.txt"))
	root := t.TempDir()
	b, err := os.ReadFile(filepath.Join(dir, "proc-stat-btime"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "/proc/stat", b)
	boot, err := BootTime(root)
	if err != nil {
		t.Fatal(err)
	}
	if h := NeedsRestarting(root, pkgs, boot); h.Required || h.ListSource != "built-in" {
		t.Errorf("built-in list: %+v (the recorded miss)", h)
	}
	src, err := os.ReadFile(filepath.Join(dir, "needs_restarting-excerpt.py"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, "/usr/lib/python3.9/site-packages/dnf-plugins/needs_restarting.py", src)
	h := NeedsRestarting(root, pkgs, boot)
	want := dnfReboot(t, filepath.Join(dir, "needs-restarting.txt"))
	if !h.Required || h.ListSource != "host" || !slices.Equal(h.Packages, want) {
		t.Errorf("agent %+v, dnf %q", h, want)
	}
}

func TestHostNeedRebootIsData(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/usr/lib/python3.12/site-packages/dnf-plugins/needs_restarting.py",
		[]byte("x = 1\nNEED_REBOOT = ['kernel', \"glibc\",\n   '$(reboot)', '../x', 'kernel']\nY = ['ignored']\n"))
	if got := hostNeedReboot(root); !slices.Equal(got, []string{"kernel", "glibc"}) {
		t.Errorf("%q", got)
	}
	if got := hostNeedReboot(t.TempDir()); got != nil {
		t.Errorf("no plugin: %q", got)
	}
}

func readInstallTimes(t *testing.T, name string) []Installed {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var pkgs []Installed
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n, at, _ := strings.Cut(sc.Text(), " ")
		s, err := strconv.ParseInt(at, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, Installed{Name: n, At: time.Unix(s, 0)})
	}
	return pkgs
}

// dnfReboot reads the package names "dnf needs-restarting -r" printed.
func dnfReboot(t *testing.T, name string) []string {
	t.Helper()
	out, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if n, ok := strings.CutPrefix(line, "  * "); ok {
			names = append(names, n)
		}
	}
	return names
}

func TestNeedsRestartingD(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/dnf/plugins/needs-restarting.d/local.conf", []byte("openssl-libs\n../evil\n\nzlib\n"))
	writeFile(t, root, "/etc/dnf/plugins/needs-restarting.d/ignored.txt", []byte("bash\n"))
	boot := time.Date(2026, 10, 16, 17, 18, 22, 0, time.UTC)
	h := NeedsRestarting(root, []Installed{
		{Name: "openssl-libs", At: boot.Add(time.Hour)},
		{Name: "bash", At: boot.Add(time.Hour)},
		{Name: "zlib", At: boot.Add(-time.Hour)},
		{Name: "glibc", At: boot.Add(time.Minute)},
		{Name: "glibc", At: boot.Add(time.Minute)}, // multilib: two arches
	}, boot)
	if !h.Required || !slices.Equal(h.Packages, []string{"glibc", "openssl-libs"}) {
		t.Errorf("%+v", h)
	}
	if h := NeedsRestarting(root, nil, boot); h.Required {
		t.Errorf("nothing installed: %+v", h)
	}
}

func TestRebootRequired(t *testing.T) {
	root := t.TempDir()
	if h := RebootRequired(root); h.Required {
		t.Errorf("no file: %+v", h)
	}
	writeFile(t, root, "/run/reboot-required", []byte("*** System restart required ***\n"))
	writeFile(t, root, "/run/reboot-required.pkgs", []byte("linux-image-6.8.0-147-generic\nlinux-base\nlinux-base\n"))
	h := RebootRequired(root)
	if !h.Required || !slices.Equal(h.Packages, []string{"linux-image-6.8.0-147-generic", "linux-base"}) {
		t.Errorf("%+v", h)
	}
}

func TestBootTime(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/proc/stat", []byte("cpu 1\nbtime 1792171102\nprocesses 5\n"))
	got, err := BootTime(root)
	if err != nil || !got.Equal(time.Unix(1792171102, 0)) {
		t.Errorf("%v %v", got, err)
	}
	writeFile(t, root, "/proc/stat", []byte("cpu 1\n"))
	if _, err := BootTime(root); err == nil {
		t.Error("no btime: no error")
	}
}
