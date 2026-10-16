package baseline

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"tycana.ai/agent/internal/filetime"
	"tycana.ai/agent/internal/hostexec"
	"tycana.ai/agent/internal/inventory"
)

// Collect builds the Host view of the live system for the checks in b.
// It reads files as the agent's user, the package list from the
// inventory, and unit state from systemd. Nothing is written.
func Collect(ctx context.Context, b *Baseline, snap *inventory.Snapshot) (*Host, error) {
	h := &Host{
		Root:          "/",
		Stat:          liveStat,
		ReadFile:      liveRead,
		ReadDir:       os.ReadDir,
		PackageFormat: snap.PackageDB.Format,
		Packages:      map[string][]string{},
	}
	for _, p := range snap.Packages {
		// dpkg keeps removed packages with their configuration files
		// ("config-files"); OVAL's dpkginfo counts only installed ones.
		if p.State != "" && p.State != "installed" {
			continue
		}
		h.Packages[p.Name] = append(h.Packages[p.Name], p.EVR)
	}
	h.OverflowUID = overflow("/proc/sys/kernel/overflowuid")
	h.OverflowGID = overflow("/proc/sys/kernel/overflowgid")
	h.UserNS = partialUserNS()
	h.Container = container()
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("mountinfo: %w", err)
	}
	h.Mounts = parseMountinfo(mi)
	h.Sandboxed = sandboxed(h.Mounts)
	units := b.units()
	h.Units = map[string]map[string]string{}
	for len(units) > 0 {
		n := min(len(units), 400)
		res, err := hostexec.Run(ctx, hostexec.SystemctlShowUnits, units[:n]...)
		if err != nil {
			return nil, fmt.Errorf("systemctl show: %w", err)
		}
		// systemctl prints one block per name, in order; an alias's
		// block carries its target's Id, so key by the name asked for.
		blocks := showBlocks(res.Stdout)
		if len(blocks) != n {
			return nil, fmt.Errorf("systemctl show: %d blocks for %d units", len(blocks), n)
		}
		for i, blk := range blocks {
			h.Units[units[i]] = blk
		}
		units = units[n:]
	}
	if b.needsDeps() {
		res, err := hostexec.Run(ctx, hostexec.SystemctlListDependencies)
		if err != nil {
			return nil, fmt.Errorf("systemctl list-dependencies: %w", err)
		}
		h.Wanted = []string{}
		for _, l := range strings.Split(string(res.Stdout), "\n") {
			if u := strings.TrimSpace(l); u != "" {
				h.Wanted = append(h.Wanted, u)
			}
		}
	}
	return h, nil
}

func liveStat(path string) (Meta, error) {
	m, err := filetime.Lstat(path)
	if err != nil {
		return Meta{}, err
	}
	return Meta{Mode: m.Mode, UID: m.UID, GID: m.GID, Type: m.Type}, nil
}

func liveRead(path string) ([]byte, error) {
	// A FIFO would block the run and a device would read garbage; the
	// checks only read regular files (and /proc/sys, which reports them
	// as regular).
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, unknownf("%s is not a regular file", path)
	}
	f, err := os.Open(path) //nolint:gosec // paths come from the baseline, read-only
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, unknownf("%s is larger than 4 MiB", path)
	}
	return b, nil
}

func overflow(path string) uint32 {
	b, err := os.ReadFile(path) //nolint:gosec // fixed /proc path
	if err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32); err == nil {
			return uint32(n)
		}
	}
	return 65534
}

// partialUserNS reports whether this process's user namespace maps fewer
// than all ids. The initial namespace's uid_map is "0 0 4294967295".
func partialUserNS() bool {
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return true
	}
	f := strings.Fields(string(b))
	return len(f) != 3 || f[0] != "0" || f[1] != "0" || f[2] != "4294967295"
}

// container applies systemd-detect-virt's file tests and OVAL's
// "machine" rule (no /.dockerenv, no /run/.containerenv).
func container() bool {
	for _, p := range []string{"/run/systemd/container", "/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// parseMountinfo reads proc_pid_mountinfo(5). Octal escapes (\040 for a
// space) are decoded.
func parseMountinfo(b []byte) []Mount {
	var out []Mount
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		sep := slices.Index(f, "-")
		if sep < 6 || len(f) < sep+4 {
			continue
		}
		opts := strings.Split(f[5], ",")
		opts = append(opts, strings.Split(f[sep+3], ",")...)
		out = append(out, Mount{
			Root: unescape(f[3]), Target: unescape(f[4]),
			FSType: f[sep+1], Source: unescape(f[sep+2]), Options: opts,
		})
	}
	return out
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// units lists the systemd units the checks and their conditions read.
func (b *Baseline) units() []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	for i := range b.Checks {
		c := &b.Checks[i]
		for _, u := range c.unitsRead() {
			add(u)
		}
	}
	slices.Sort(out)
	return out
}
