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
	// ListSource says where the needs-restarting package list came from:
	// "host" (the installed dnf plugin, which distributions extend: Oracle
	// adds kernel-uek and kernel-uek-core) or "built-in".
	ListSource string `json:"list_source,omitempty"`
}

// needReboot is NEED_REBOOT of dnf-plugins-core 4.3.0
// (dnf-plugins/needs_restarting.py, AlmaLinux 9), after Red Hat's
// https://access.redhat.com/solutions/27943. It is the fallback: the
// agent reads the list from the installed plugin (hostNeedReboot), because
// distributions change it. Files in /etc/dnf/plugins/needs-restarting.d/
// add names, one per line.
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
	h := RebootHint{Rule: "needs-restarting", Boot: boot, ListSource: "built-in"}
	base := needReboot
	if host := hostNeedReboot(root); len(host) > 0 {
		base, h.ListSource = host, "host"
	}
	names := slices.Concat(base, needsRestartingD(root))
	for _, p := range pkgs {
		if slices.Contains(names, p.Name) && p.At.After(boot) && !slices.Contains(h.Packages, p.Name) {
			h.Packages = append(h.Packages, p.Name)
		}
	}
	slices.Sort(h.Packages)
	h.Required = len(h.Packages) > 0
	return h
}

// needsRestartingPy is where dnf-plugins-core installs the plugin.
const needsRestartingPy = "usr/lib/python3*/site-packages/dnf-plugins/needs_restarting.py"

// needRebootList matches the list literal in the plugin source.
var needRebootList = regexp.MustCompile(`(?s)\nNEED_REBOOT = \[([^\]]*)\]`)
var quoted = regexp.MustCompile(`['"]([^'"]*)['"]`)

// hostNeedReboot reads NEED_REBOOT from the installed plugin. The file is
// data: only quoted strings that are valid package names are taken, and
// nothing in it is executed. nil when the plugin or the list is absent.
func hostNeedReboot(root string) []string {
	matches, _ := filepath.Glob(filepath.Join(root, needsRestartingPy))
	slices.Sort(matches)
	for _, m := range matches {
		b, err := readSmall(m)
		if err != nil {
			continue
		}
		lit := needRebootList.FindSubmatch(b)
		if lit == nil {
			continue
		}
		var names []string
		for _, q := range quoted.FindAllSubmatch(lit[1], -1) {
			if n := string(q[1]); rpmName.MatchString(n) && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			return names
		}
	}
	return nil
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
