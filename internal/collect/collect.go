// Package collect runs the agent's observers in one place, so that the
// CLI commands and tycanad build the same data: the inventory, the
// waiting updates and the host's autopilot, the restart state, and the
// baseline. Every step only reads (ADR 0017).
package collect

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"tycana.ai/agent/internal/baseline"
	"tycana.ai/agent/internal/exposure"
	"tycana.ai/agent/internal/hostexec"
	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/inventory/kernel"
	"tycana.ai/agent/internal/restart"
	"tycana.ai/agent/internal/sockdiag"
	"tycana.ai/agent/internal/updates"
)

// Updates lists the waiting updates with apt or dnf and predicts the
// host's autopilot.
func Updates(ctx context.Context, snap *inventory.Snapshot) (updates.Report, error) {
	var r updates.Report
	var err error
	switch snap.PackageDB.Format {
	case "deb":
		var held []string
		for _, p := range snap.Packages {
			if p.Want == "hold" {
				held = append(held, updates.AptName(p.Name, p.Arch, snap.PackageDB.NativeArch))
			}
		}
		r, err = updates.CollectApt(ctx, snap.PackageDB.NativeArch, held)
	case "rpm":
		// Install-only packages (kernels) have several versions installed;
		// keep the one installed last.
		installed := map[string]string{}
		at := map[string]time.Time{}
		for _, p := range snap.Packages {
			k := p.Name + "." + p.Arch
			if _, seen := at[k]; !seen || !p.InstalledAt.Before(at[k]) {
				installed[k], at[k] = p.EVR, p.InstalledAt
			}
		}
		r, err = updates.CollectDnf(ctx, installed)
	default:
		err = fmt.Errorf("package format %q not supported", snap.PackageDB.Format)
	}
	if err != nil {
		return r, err
	}
	if err := updates.PredictAutopilot(ctx, &r, DistroID(snap.OS.ID), snap.OS.VersionCodename); err != nil {
		return r, fmt.Errorf("autopilot: %w", err)
	}
	return r, nil
}

// DistroID is the Origin name apt and the autopilots use for an
// os-release ID.
func DistroID(id string) string {
	switch id {
	case "ubuntu":
		return "Ubuntu"
	case "debian":
		return "Debian"
	}
	if id == "" {
		return ""
	}
	return strings.ToUpper(id[:1]) + id[1:]
}

// Restart is "tycana restart --format json".
type Restart struct {
	// Host is the main result (ADR 0020); the findings are detail.
	Host         restart.HostState     `json:"host"`
	Kernel       *KernelRestart        `json:"kernel,omitempty"`
	LivePatching *restart.LivePatching `json:"live_patching,omitempty"`
	Reboot       *restart.RebootHint   `json:"reboot_hint,omitempty"`
	restart.Report
}

// KernelRestart compares the running kernel with the newest installed.
type KernelRestart struct {
	Running         string `json:"running"`
	NewestInstalled string `json:"newest_installed,omitempty"`
	// RebootNeeded is true when a newer kernel is installed than the one
	// running. With live patches or Ksplice (EffectiveKnown false) the
	// running kernel may already carry the fixes.
	RebootNeeded   bool `json:"reboot_needed"`
	EffectiveKnown bool `json:"effective_known"`
}

// RestartInputs collects what the restart analysis reads, and fills the
// kernel, live-patch, and reboot parts of out.
func RestartInputs(ctx context.Context, inv *inventory.Snapshot, now time.Time, out *Restart) (restart.Snapshot, error) {
	out.Kernel = kernelState(inv.Kernel)
	out.Reboot = rebootHint(inv)
	lp := livePatching(inv)
	out.LivePatching = &lp
	pkgs, err := packageChanges(inv)
	if err != nil {
		return restart.Snapshot{}, err
	}
	return restart.Collect(ctx, now, pkgs)
}

// Analyze completes out from a restart snapshot.
func Analyze(snap restart.Snapshot, out *Restart) {
	out.Report = restart.Analyze(snap)
	out.Host = restart.Host(snap, out.Report)
	if out.Kernel != nil && out.Kernel.RebootNeeded {
		out.Host.State = "restart-needed"
	}
}

// RestartState collects and analyzes the restart state of the host.
func RestartState(ctx context.Context, inv *inventory.Snapshot, now time.Time) (Restart, error) {
	var out Restart
	snap, err := RestartInputs(ctx, inv, now, &out)
	if err != nil {
		return out, err
	}
	Analyze(snap, &out)
	return out, nil
}

// packageChanges is when each package last changed: dpkg's info files,
// or rpm's install times (whole seconds).
func packageChanges(inv *inventory.Snapshot) ([]restart.PackageChange, error) {
	switch inv.PackageDB.Format {
	case "deb":
		return restart.DpkgChanges("/")
	case "rpm":
		out := make([]restart.PackageChange, 0, len(inv.Packages))
		for _, p := range inv.Packages {
			if !p.InstalledAt.IsZero() {
				out = append(out, restart.PackageChange{Name: p.Name + "." + p.Arch, Changed: p.InstalledAt, Coarse: true})
			}
		}
		return out, nil
	}
	return nil, nil
}

func livePatching(inv *inventory.Snapshot) restart.LivePatching {
	names := make([]string, 0, len(inv.Kernel.LivePatches))
	for _, p := range inv.Kernel.LivePatches {
		names = append(names, p.Name)
	}
	pkgs := make([]restart.PackageInfo, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		pkgs = append(pkgs, restart.PackageInfo{Name: p.Name, Version: p.Version, Release: p.Release})
	}
	return restart.DetectLivePatching("/", names, inv.Kernel.KspliceModules, pkgs)
}

// rebootHint applies the distribution's own reboot rule: dnf's
// needs-restarting on rpm hosts, /run/reboot-required on dpkg hosts.
func rebootHint(inv *inventory.Snapshot) *restart.RebootHint {
	switch inv.PackageDB.Format {
	case "rpm":
		boot, err := restart.BootTime("/")
		if err != nil {
			return nil
		}
		pkgs := make([]restart.Installed, 0, len(inv.Packages))
		for _, p := range inv.Packages {
			pkgs = append(pkgs, restart.Installed{Name: p.Name, At: p.InstalledAt})
		}
		h := restart.NeedsRestarting("/", pkgs, boot)
		return &h
	case "deb":
		h := restart.RebootRequired("/")
		return &h
	}
	return nil
}

func kernelState(k kernel.Info) *KernelRestart {
	return &KernelRestart{
		Running:         k.Running.Release,
		NewestInstalled: k.NewestInstalled,
		RebootNeeded:    k.NewestInstalled != "" && k.NewestInstalled != k.Running.Release,
		EffectiveKnown:  k.EffectiveKnown,
	}
}

// ErrNoPreset is returned when no built-in baseline is for the host.
var ErrNoPreset = errors.New("no built-in baseline for this release")

// Baseline evaluates the built-in baseline for the host's release, with
// exceptions exc and the target percent (0: the default).
func Baseline(ctx context.Context, snap *inventory.Snapshot, exc []baseline.Exception, target float64, now time.Time) (*baseline.Report, error) {
	b, err := baseline.PresetFor(snap.OS.ID, snap.OS.VersionID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s %s", ErrNoPreset, snap.OS.ID, snap.OS.VersionID)
	}
	return Evaluate(ctx, b, snap, exc, target, now)
}

// Evaluate evaluates b on the host.
func Evaluate(ctx context.Context, b *baseline.Baseline, snap *inventory.Snapshot, exc []baseline.Exception, target float64, now time.Time) (*baseline.Report, error) {
	h, err := baseline.Collect(ctx, b, snap)
	if err != nil {
		return nil, err
	}
	r := baseline.Evaluate(b, h, exc, target, now)
	return &r, nil
}

// Exposure reads, for each running unit of the restart snapshot, its
// listening sockets, main program, and packages, and the host's setuid
// packages (tycana-hq ADR 0029, ADR 0032). It needs AF_NETLINK and
// ProtectProc=default in tycanad's unit and no privilege.
func Exposure(ctx context.Context, inv *inventory.Snapshot, snap restart.Snapshot, now time.Time) *exposure.Report {
	h := exposure.Host{
		Root: "/", Proc: "/proc",
		Cgroups:  func() (map[uint64]string, error) { return sockdiag.CgroupPaths("/sys/fs/cgroup") },
		Format:   inv.PackageDB.Format,
		RPMDir:   strings.TrimPrefix(inv.PackageDB.Path, "/"),
		Sockets:  sockdiag.Listening,
		Triggers: socketTriggers,
	}
	return exposure.Collect(ctx, h, snap, now)
}

// socketTriggers asks systemd for the Triggers= of each socket unit.
// It asks in batches of 200, below hostexec's limit of names per call.
func socketTriggers(ctx context.Context, sockets []string) (map[string][]string, error) {
	out := map[string][]string{}
	for len(sockets) > 0 {
		n := min(len(sockets), 200)
		res, err := hostexec.Run(ctx, hostexec.SystemctlShowSocketTriggers, sockets[:n]...)
		if err != nil {
			return out, err
		}
		maps.Copy(out, exposure.ParseTriggers(res.Stdout))
		sockets = sockets[n:]
	}
	return out, nil
}
