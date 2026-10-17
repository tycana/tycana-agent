package updates

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"tycana.ai/agent/internal/hostexec"
)

// CollectDnf asks dnf, from its system metadata cache, which updates are
// available and which advisories they resolve. installed maps "name.arch"
// to the installed EVR (the newest one, for install-only packages such as
// the kernel). dnf does not refresh metadata here; the host's own
// dnf-makecache timer does that, and the report is as fresh as the cache.
func CollectDnf(ctx context.Context, installed map[string]string) (Report, error) {
	return collectDnf(ctx, hostexec.Run, installed)
}

func collectDnf(ctx context.Context, run runner, installed map[string]string) (Report, error) {
	cu, err := run(ctx, hostexec.DnfCheckUpdate)
	if err != nil {
		return Report{}, err
	}
	ups, err := parseCheckUpdate(cu.Stdout)
	if err != nil {
		return Report{}, fmt.Errorf("dnf check-update: %w", err)
	}
	ui, err := run(ctx, hostexec.DnfUpdateinfo)
	if err != nil {
		return Report{}, err
	}
	advs, err := parseUpdateinfoList(ui.Stdout)
	if err != nil {
		return Report{}, fmt.Errorf("dnf updateinfo: %w", err)
	}
	r := Report{Schema: Schema, Manager: "dnf"}
	for _, u := range ups {
		u.Installed = installed[u.Name+"."+u.Arch]
		u.State = Upgrade
		// "updateinfo list --available" lists only advisories newer than
		// what is installed, and check-update offers the newest version,
		// so every listed advisory for this name.arch is resolved by the
		// update. A versionlock or exclude could break that; neither is
		// read yet.
		u.Advisories = advs[u.Name+"."+u.Arch]
		u.Security = slices.ContainsFunc(u.Advisories, func(a Advisory) bool { return a.Type == "security" })
		r.Updates = append(r.Updates, u)
	}
	slices.SortFunc(r.Updates, func(a, b Update) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Arch, b.Arch))
	})
	return r, nil
}

// parseCheckUpdate reads "name.arch  evr  repo" rows. dnf puts a long
// name on a line of its own and the rest on the next, so fields are
// collected across lines. The "Obsoleting Packages" section that can
// follow repeats packages as pairs and is not an update list.
func parseCheckUpdate(out []byte) ([]Update, error) {
	var ups []Update
	var fields []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Obsoleting Packages") {
			break
		}
		// dnf's notices about the running kernel when a newer one with a
		// security fix is installed: "Security: kernel-core-NEVRA is an
		// installed security update" and "... is the currently running
		// version". They are not update rows; the kernel state (restart)
		// covers them. Seen on AlmaLinux 9 after an upgrade, before the
		// reboot (M5 lab, 2026-10-17).
		if strings.HasPrefix(line, "Security: ") {
			continue
		}
		fields = append(fields, strings.Fields(line)...)
		if len(fields) < 3 {
			continue
		}
		if len(fields) > 3 {
			return nil, fmt.Errorf("unrecognized line %q", line)
		}
		name, arch, ok := cutLast(fields[0], ".")
		if !ok {
			return nil, fmt.Errorf("no architecture in %q", fields[0])
		}
		ups = append(ups, Update{Name: name, Arch: arch, Candidate: fields[1], Origins: []Origin{{Suite: fields[2]}}})
		fields = nil
	}
	if len(fields) > 0 {
		return nil, fmt.Errorf("incomplete row %q", strings.Join(fields, " "))
	}
	return ups, sc.Err()
}

// parseUpdateinfoList reads "ID TYPE NEVRA" rows of "dnf updateinfo list"
// and groups the advisories by "name.arch". TYPE is "Important/Sec.",
// "bugfix", "enhancement", or "newpackage".
func parseUpdateinfoList(out []byte) (map[string][]Advisory, error) {
	advs := map[string][]Advisory{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return nil, fmt.Errorf("unrecognized line %q", sc.Text())
		}
		a := Advisory{ID: f[0], Type: f[1]}
		if sev, ok := strings.CutSuffix(f[1], "/Sec."); ok {
			a.Type, a.Severity = "security", sev
		}
		name, arch, err := splitNEVRA(f[2])
		if err != nil {
			return nil, err
		}
		key := name + "." + arch
		if !slices.Contains(advs[key], a) {
			advs[key] = append(advs[key], a)
		}
	}
	return advs, sc.Err()
}

// splitNEVRA takes name and arch from "name-[epoch:]version-release.arch".
func splitNEVRA(s string) (name, arch string, err error) {
	nvr, arch, ok := cutLast(s, ".")
	if !ok {
		return "", "", fmt.Errorf("no architecture in %q", s)
	}
	nv, _, ok1 := cutLast(nvr, "-")
	name, _, ok2 := cutLast(nv, "-")
	if !ok1 || !ok2 || name == "" {
		return "", "", fmt.Errorf("not a NEVRA: %q", s)
	}
	return name, arch, nil
}

func cutLast(s, sep string) (before, after string, ok bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}
