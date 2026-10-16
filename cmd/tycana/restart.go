package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/inventory/kernel"
	"tycana.ai/agent/internal/restart"
)

// restartOutput is "tycana restart --format json".
type restartOutput struct {
	// Host is the main result (ADR 0020); the findings are detail.
	Host         restart.HostState     `json:"host"`
	Kernel       *kernelRestart        `json:"kernel,omitempty"`
	LivePatching *restart.LivePatching `json:"live_patching,omitempty"`
	Reboot       *restart.RebootHint   `json:"reboot_hint,omitempty"`
	restart.Report
}

type kernelRestart struct {
	Running         string `json:"running"`
	NewestInstalled string `json:"newest_installed,omitempty"`
	// RebootNeeded is true when a newer kernel is installed than the one
	// running. With live patches or Ksplice (EffectiveKnown false) the
	// running kernel may already carry the fixes.
	RebootNeeded   bool `json:"reboot_needed"`
	EffectiveKnown bool `json:"effective_known"`
}

func runRestart(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana restart", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text, json, or snapshot (the collected inputs)")
	from := fs.String("snapshot", "", "analyze a snapshot file instead of this host")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: tycana restart [--format text|json|snapshot] [--snapshot FILE]\n\n"+
			"Lists running services that still use a program or library replaced on disk since\n"+
			"they started, and whether a newer kernel waits for a reboot. Needs no privilege:\n"+
			"it reads systemd's unit data, the ELF files the services load at start, and the\n"+
			"creation time of each file. Findings are inferred, not observed; libraries a\n"+
			"service loads later (PAM, NSS, OpenSSL providers, interpreter modules) are not\n"+
			"checked.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tycana restart: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	switch *format {
	case "text", "json", "snapshot":
	default:
		fmt.Fprintf(stderr, "tycana restart: unknown format %q\n", *format)
		return 2
	}

	var snap restart.Snapshot
	var out restartOutput
	var err error
	if *from != "" {
		snap, err = readSnapshot(*from)
	} else {
		now := time.Now()
		var inv *inventory.Snapshot
		inv, _, err = inventory.Collect("/", now)
		var pkgs []restart.PackageChange
		if err == nil {
			out.Kernel = kernelState(inv.Kernel)
			out.Reboot = rebootHint(inv)
			lp := livePatching(inv)
			out.LivePatching = &lp
			pkgs, err = packageChanges(inv)
		}
		if err == nil {
			snap, err = restart.Collect(context.Background(), now, pkgs)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "tycana restart: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if *format == "snapshot" {
		err = enc.Encode(snap)
	} else {
		out.Report = restart.Analyze(snap)
		out.Host = restart.Host(snap, out.Report)
		if out.Kernel != nil && out.Kernel.RebootNeeded {
			out.Host.State = "restart-needed"
		}
		if *format == "json" {
			err = enc.Encode(out)
		} else {
			err = writeRestartText(stdout, out)
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "tycana restart: %v\n", err)
		return 1
	}
	return 0
}

func readSnapshot(name string) (restart.Snapshot, error) {
	var s restart.Snapshot
	b, err := os.ReadFile(name) //nolint:gosec // the operator names the snapshot to read
	if err != nil {
		return s, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("%s: %w", name, err)
	}
	return s, nil
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

func kernelState(k kernel.Info) *kernelRestart {
	return &kernelRestart{
		Running:         k.Running.Release,
		NewestInstalled: k.NewestInstalled,
		RebootNeeded:    k.NewestInstalled != "" && k.NewestInstalled != k.Running.Release,
		EffectiveKnown:  k.EffectiveKnown,
	}
}

func writeRestartText(w io.Writer, out restartOutput) error {
	count := map[restart.Status]int{}
	for _, f := range out.Findings {
		count[f.Status]++
	}
	h := out.Host
	switch h.State {
	case "restart-needed":
		fmt.Fprintf(w, "Host: restart needed. A reboot clears all of it.\n")
	case "current":
		fmt.Fprintf(w, "Host: current. No package changed after a running service started.\n")
	default:
		fmt.Fprintf(w, "Host: unknown.\n")
	}
	if h.PackageData {
		fmt.Fprintf(w, "Services: %d use a replaced file (inferred); %d started before a package change (possible); %d unknown; %d current.\n",
			count[restart.Inferred], count[restart.Possible], count[restart.Unknown], count[restart.None])
		if !h.LatestChange.IsZero() {
			fmt.Fprintf(w, "Latest package change: %s UTC.\n", h.LatestChange.Format("2006-01-02 15:04:05"))
		}
	} else {
		fmt.Fprintf(w, "Services: %d use a replaced file (inferred); %d possible; %d unknown; %d with no evidence (no package change times in this snapshot).\n",
			count[restart.Inferred], count[restart.Possible], count[restart.Unknown], count[restart.None])
	}
	if k := out.Kernel; k != nil {
		switch {
		case k.RebootNeeded:
			fmt.Fprintf(w, "Kernel: running %s, newest installed %s: a reboot is needed.\n", k.Running, k.NewestInstalled)
		default:
			fmt.Fprintf(w, "Kernel: running %s, the newest installed.\n", k.Running)
		}
		if !k.EffectiveKnown {
			fmt.Fprintln(w, "Live patches are loaded: the running kernel may carry fixes its release does not show.")
		}
	}
	if lp := out.LivePatching; lp != nil {
		for _, l := range lp.Kernel {
			fmt.Fprintf(w, "Live patch: %s.\n", l)
		}
		for _, l := range lp.UserSpace {
			fmt.Fprintf(w, "Live patch: %s.\n", l)
		}
	}
	if h := out.Reboot; h != nil {
		switch {
		case h.Required && len(h.Packages) > 0:
			fmt.Fprintf(w, "Reboot hint (%s): required, for %s.\n", h.Rule, strings.Join(h.Packages, ", "))
		case h.Required:
			fmt.Fprintf(w, "Reboot hint (%s): required.\n", h.Rule)
		default:
			fmt.Fprintf(w, "Reboot hint (%s): not required.\n", h.Rule)
		}
	}
	if len(out.Findings) == 0 {
		return nil
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tUNIT\tSTARTED (UTC)\tDETAIL")
	for _, f := range out.Findings {
		started := "-"
		if !f.Start.IsZero() {
			started = f.Start.Format("2006-01-02 15:04:05")
		}
		detail := f.Reason
		if len(f.Replaced) > 0 {
			paths := make([]string, len(f.Replaced))
			for i, r := range f.Replaced {
				paths[i] = r.Path
			}
			detail = "replaced: " + strings.Join(paths, " ")
		}
		if f.Status == restart.Possible && len(f.Modules) > 0 {
			paths := make([]string, len(f.Modules))
			for i, m := range f.Modules {
				paths[i] = m.Path
			}
			detail = "modules replaced: " + strings.Join(paths, " ")
		} else if f.Status == restart.Possible && f.ChangedCount > 0 {
			detail = fmt.Sprintf("%d packages changed after it started: %s", f.ChangedCount, strings.Join(f.Changed[:min(len(f.Changed), 5)], " "))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Status, f.Unit, started, detail)
	}
	return tw.Flush()
}
