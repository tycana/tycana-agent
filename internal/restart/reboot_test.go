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
