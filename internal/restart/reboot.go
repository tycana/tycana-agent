package restart

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// RebootHint is a distribution's own rule for "reboot now", applied by the
// agent without running the distribution's tool.
type RebootHint struct {
	// Rule is "needs-restarting" (the rule of dnf needs-restarting -r) or
	// "reboot-required" (the file Debian and Ubuntu packages write).
	Rule     string `json:"rule"`
	Required bool   `json:"required"`
	// Packages are the packages that triggered the rule. Data from the
	// host.
	Packages []string `json:"packages,omitempty"`
	// Boot is the kernel boot time the rule compared against.
	Boot time.Time `json:"boot,omitzero"`
}

// needReboot is NEED_REBOOT of dnf-plugins-core 4.3.0
// (dnf-plugins/needs_restarting.py, AlmaLinux 9), after Red Hat's
// https://access.redhat.com/solutions/27943. Files in
// /etc/dnf/plugins/needs-restarting.d/ add names, one per line.
var needReboot = []string{
	"kernel", "kernel-rt", "glibc", "linux-firmware",
	"systemd", "dbus", "dbus-broker", "dbus-daemon",
	"microcode_ctl",
}

// rpmName is a package name as needs-restarting.d files hold them.
var rpmName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// Installed is one package and when it was installed.
type Installed struct {
	Name string
	At   time.Time
}

// NeedsRestarting applies the rule of "dnf needs-restarting -r": a reboot
// is required when a package on its list was installed after boot.
// dnf takes the boot time from systemd's UnitsLoadStartTimestamp, a few
// seconds after the kernel's; the agent uses the kernel's.
func NeedsRestarting(root string, pkgs []Installed, boot time.Time) RebootHint {
	names := slices.Concat(needReboot, needsRestartingD(root))
	h := RebootHint{Rule: "needs-restarting", Boot: boot}
	for _, p := range pkgs {
		if slices.Contains(names, p.Name) && p.At.After(boot) && !slices.Contains(h.Packages, p.Name) {
			h.Packages = append(h.Packages, p.Name)
		}
	}
	slices.Sort(h.Packages)
	h.Required = len(h.Packages) > 0
	return h
}

func needsRestartingD(root string) []string {
	matches, _ := filepath.Glob(filepath.Join(root, "etc/dnf/plugins/needs-restarting.d/*.conf"))
	slices.Sort(matches)
	var names []string
	for _, m := range matches {
		b, err := readSmall(m)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if n := strings.TrimSpace(line); rpmName.MatchString(n) {
				names = append(names, n)
			}
		}
	}
	return names
}

// RebootRequired reads /run/reboot-required and its .pkgs list, which
// Debian and Ubuntu packages (kernels, libc, update-notifier) write when
// they want a reboot.
func RebootRequired(root string) RebootHint {
	h := RebootHint{Rule: "reboot-required"}
	if _, err := os.Stat(filepath.Join(root, "run/reboot-required")); err != nil {
		return h
	}
	h.Required = true
	if b, err := readSmall(filepath.Join(root, "run/reboot-required.pkgs")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if n := strings.TrimSpace(line); n != "" && !slices.Contains(h.Packages, n) && len(h.Packages) < 1000 {
				h.Packages = append(h.Packages, n)
			}
		}
	}
	return h
}

// BootTime reads the kernel boot time ("btime") from /proc/stat.
func BootTime(root string) (time.Time, error) {
	b, err := readSmall(filepath.Join(root, "proc/stat"))
	if err != nil {
		return time.Time{}, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "btime "); ok {
			s, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return time.Time{}, fmt.Errorf("/proc/stat btime: %w", err)
			}
			return time.Unix(s, 0).UTC(), nil
		}
	}
	return time.Time{}, errors.New("/proc/stat: no btime line")
}

// readSmall reads at most 1 MiB.
func readSmall(name string) ([]byte, error) {
	f, err := os.Open(name) //nolint:gosec // fixed host paths under the caller's root
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	return io.ReadAll(io.LimitReader(f, 1<<20))
}
