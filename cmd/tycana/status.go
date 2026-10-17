package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"tycana.ai/agent/internal/agent"
	"tycana.ai/agent/internal/collect"
	"tycana.ai/agent/internal/hostexec"
	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/restart"
	"tycana.ai/agent/internal/state"
	"tycana.ai/agent/internal/updates"
)

// runStatus is the administrator's view (tycana-hq M4 review, proposal
// 3.4, accepted 2026-10-17): the actions first, from live data, without
// privilege. The signed state and the chain are in "tycana evidence
// status". The CLI has no CVE data (ADR 0008, 0016): an action is an
// update of one source package or advisory, a reboot, or the restart of
// services.
func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("state-dir", state.DefaultDir, "tycanad's state directory")
	scratch := fs.Bool("allow-dnf-scratch", false, "let dnf create its /var/tmp/dnf-USER-* directory on this host")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: tycana status [--allow-dnf-scratch] [--state-dir DIR]\n\n"+
			"Shows what to do on this host now: the updates, grouped by source package or\n"+
			"advisory, the reboot, and the services to restart. It reads the host live and\n"+
			"needs no privilege. The signed state and its chain are in 'sudo tycana evidence\n"+
			"status'. This view has no CVE data.\n\n"+
			"On dnf hosts, dnf run without root creates /var/tmp/dnf-USER-*; without\n"+
			"--allow-dnf-scratch the updates are not read.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tycana status: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if _, err := os.Lstat(agent.HaltFile); err == nil {
		fmt.Fprintf(stdout, "HALTED: %s exists. tycanad collects nothing and signs nothing until it is removed.\n\n", agent.HaltFile)
	}
	now := time.Now()
	inv, _, err := inventory.Collect("/", now)
	if err != nil {
		fmt.Fprintf(stderr, "tycana status: %v\n", err)
		return 1
	}
	v := statusView{inv: inv}
	if cfg, err := agent.LoadConfig(agent.ConfigPath); err == nil {
		v.tags = cfg.Tags
	}
	if inv.PackageDB.Format == "rpm" && !*scratch {
		v.updatesErr = fmt.Sprintf("not read: dnf would leave /var/tmp/dnf-%s-* on this host. Run 'tycana status --allow-dnf-scratch', or 'sudo tycana evidence status' for the last signed list", dnfUser())
	} else {
		hostexec.AllowScratch = *scratch
		r, err := collect.Updates(context.Background(), inv)
		if err != nil {
			v.updatesErr = err.Error()
		} else {
			v.updates = &r
		}
	}
	if rs, err := collect.RestartState(context.Background(), inv, now); err != nil {
		v.restartErr = err.Error()
	} else {
		v.restart = &rs
	}
	v.signed = signedLine(*dir, now)
	writeStatus(stdout, v)
	return 0
}

type statusView struct {
	inv        *inventory.Snapshot
	tags       map[string]string
	updates    *updates.Report
	updatesErr string
	restart    *collect.Restart
	restartErr string
	signed     string
}

// statusAction is one row of the action list.
type statusAction struct {
	kind     string // "update", "reboot", "restart"
	security bool
	name     string // source package or advisory
	from, to string
	severity string
	pkgs     []string
	state    updates.State
	units    []string
	detail   string
}

// groupUpdates turns the update list into actions: one per source
// package version on dpkg hosts, one per advisory on dnf hosts (an update
// with several advisories joins the first in ID order; one without an
// advisory is grouped by its source rpm). Phased and held updates are
// not actions now.
func groupUpdates(inv *inventory.Snapshot, r *updates.Report) (acts []statusAction, phased, held int) {
	src := map[string]inventory.Package{}
	for _, p := range inv.Packages {
		src[p.Name+":"+p.Arch] = p
		if _, ok := src[p.Name]; !ok {
			src[p.Name] = p
		}
	}
	byKey := map[string]*statusAction{}
	var order []string
	for _, u := range r.Updates {
		switch u.State {
		case updates.Phased:
			phased++
			continue
		case updates.Held:
			held++
			continue
		}
		p, ok := src[u.Name+":"+u.Arch]
		if !ok {
			p = src[u.Name]
		}
		a := statusAction{kind: "update", security: u.Security, name: p.SourceName, from: p.SourceEVR, state: u.State}
		if a.name == "" {
			a.name, a.from = u.Name, u.Installed
		}
		if inv.PackageDB.Format == "rpm" {
			ids := make([]string, 0, len(u.Advisories))
			for _, adv := range u.Advisories {
				ids = append(ids, adv.ID)
			}
			sort.Strings(ids)
			if len(ids) > 0 {
				a.name, a.from = ids[0], ""
				for _, adv := range u.Advisories {
					if adv.ID == ids[0] {
						a.severity = adv.Severity
						a.security = a.security || adv.Type == "security"
					}
				}
			}
		}
		k := a.name + "\x00" + a.from
		x := byKey[k]
		if x == nil {
			x = &a
			byKey[k] = x
			order = append(order, k)
		}
		x.security = x.security || u.Security
		if u.State == updates.DistUpgrade {
			x.state = updates.DistUpgrade
		}
		x.pkgs = append(x.pkgs, u.Name)
	}
	for _, k := range order {
		acts = append(acts, *byKey[k])
	}
	rank := func(s string) int {
		if r, ok := map[string]int{"Critical": 0, "Important": 1, "Moderate": 2, "Low": 3}[s]; ok {
			return r
		}
		return 4
	}
	sort.SliceStable(acts, func(i, j int) bool {
		x, y := acts[i], acts[j]
		if x.security != y.security {
			return x.security
		}
		if rank(x.severity) != rank(y.severity) {
			return rank(x.severity) < rank(y.severity)
		}
		return x.name < y.name
	})
	return acts, phased, held
}

// hostActions are the reboot and the service restarts.
func hostActions(rs *collect.Restart) []statusAction {
	if rs == nil {
		return nil
	}
	var acts []statusAction
	if k := rs.Kernel; k != nil && k.RebootNeeded {
		acts = append(acts, statusAction{kind: "reboot", from: k.Running, to: k.NewestInstalled})
	} else if h := rs.Reboot; h != nil && h.Required {
		acts = append(acts, statusAction{kind: "reboot", detail: h.Rule + ": " + shortList(h.Packages, 5)})
	}
	var units []string
	for _, f := range rs.Findings {
		if f.Status == restart.Inferred {
			units = append(units, f.Unit)
		}
	}
	if len(units) > 0 {
		sort.Strings(units)
		acts = append(acts, statusAction{kind: "restart", units: units})
	}
	return acts
}

func writeStatus(w io.Writer, v statusView) {
	host, _ := os.Hostname()
	fmt.Fprintf(w, "%s (%s). Live view, read now without privilege.\n", safe(host), safe(v.inv.OS.PrettyName))
	if len(v.tags) > 0 {
		keys := make([]string, 0, len(v.tags))
		for k := range v.tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = k + "=" + safe(v.tags[k])
		}
		fmt.Fprintf(w, "Tags (the operator's, from %s): %s.\n", agent.ConfigPath, strings.Join(parts, ", "))
	}
	var acts []statusAction
	phased, held := 0, 0
	if v.updates != nil {
		acts, phased, held = groupUpdates(v.inv, v.updates)
	}
	var first, other []statusAction
	for _, a := range acts {
		if a.security {
			first = append(first, a)
		} else {
			other = append(other, a)
		}
	}
	nsec := len(first)
	first = append(first, hostActions(v.restart)...)
	fmt.Fprintln(w)
	switch {
	case v.updatesErr != "":
		fmt.Fprintf(w, "Updates: %s.\n", v.updatesErr)
	case len(first) == 0 && len(other) == 0 && v.restartErr == "":
		fmt.Fprintln(w, "Nothing to do: no update waits, and no reboot or restart is needed.")
	}
	if len(first) > 0 {
		fmt.Fprintf(w, "Do these first (%d updates with a security fix, then the reboot and restarts):\n", nsec)
		for i, a := range first {
			fmt.Fprintf(w, "%3d. %s\n", i+1, actionText(a))
		}
	}
	if len(other) > 0 {
		names := make([]string, len(other))
		for i, a := range other {
			names[i] = a.name
		}
		fmt.Fprintf(w, "\nOther updates, without a security fix: %d (%s).\n", len(other), shortList(names, 6))
	}
	if phased > 0 || held > 0 {
		fmt.Fprintf(w, "Not now: %d deferred by phasing, %d held by an operator.\n", phased, held)
	}
	if v.restartErr != "" {
		fmt.Fprintf(w, "Restart state: not read: %s.\n", v.restartErr)
	}
	if v.updates != nil {
		writeAutopilotText(w, v.updates.Autopilot)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, v.signed)
	fmt.Fprintln(w, "This view has no CVE data. The CVEs that each action clears are in Tycana's assessment\n"+
		"of the signed records. 'tycana updates' and 'tycana restart' give the full lists.")
}

func actionText(a statusAction) string {
	switch a.kind {
	case "reboot":
		if a.to != "" {
			return fmt.Sprintf("reboot: kernel %s runs; %s is installed", a.from, a.to)
		}
		return "reboot: required by " + a.detail
	case "restart":
		return fmt.Sprintf("restart %d services that use replaced files (inferred): %s", len(a.units), shortList(a.units, 5))
	}
	s := "update " + a.name
	if a.severity != "" {
		s += " (" + a.severity + ")"
	}
	if a.from != "" {
		s += " from " + a.from
	}
	s += fmt.Sprintf(": %d packages (%s)", len(a.pkgs), shortList(a.pkgs, 4))
	if a.state == updates.DistUpgrade {
		s += "; needs a full upgrade"
	}
	return s
}

func shortList(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(s[:n], ", "), len(s)-n)
}

// signedLine is one line on the signed state: what a user who can read
// the records gets, or how to get it.
func signedLine(dir string, now time.Time) string {
	b, err := exportBundle(state.Reader(dir), time.Time{}, now)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return "Signed state: only root and the tycana user can read it: 'sudo tycana evidence status'."
		}
		return "Signed state: not read: " + safe(err.Error()) + "."
	}
	r, _, _, err := b.Verify(nil)
	switch {
	case err != nil:
		return "Signed state: " + safe(err.Error()) + "."
	case r.Records == 0:
		return "Signed state: tycanad has signed no record on this host."
	case !r.OK():
		return fmt.Sprintf("Signed state: the chain is NOT complete (%d problems): 'sudo tycana evidence status'.", len(r.Breaks)+len(r.Invalid))
	}
	return fmt.Sprintf("Signed state: last record %s ago; chain complete, %d records. Details: 'tycana evidence status'.",
		now.Sub(r.To).Round(time.Minute), r.Records)
}

// runEvidenceStatus is the signed state and the chain: the auditor's
// view, which needs sudo (the "tycana status" of M4).
func runEvidenceStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana evidence status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("state-dir", state.DefaultDir, "tycanad's state directory")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tycana evidence status: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if _, err := os.Lstat(agent.HaltFile); err == nil {
		fmt.Fprintf(stdout, "HALTED: %s exists. tycanad collects nothing and signs nothing until it is removed.\n\n", agent.HaltFile)
	}
	now := time.Now()
	b, err := exportBundle(state.Reader(*dir), time.Time{}, now)
	if err != nil {
		fmt.Fprintf(stderr, "tycana evidence status: %v\n", err)
		if errors.Is(err, os.ErrPermission) {
			fmt.Fprintln(stderr, "Only root and the tycana user can read the records. Run the command with sudo.")
		}
		return 1
	}
	r, src, ids, err := b.Verify(nil)
	if err != nil {
		fmt.Fprintf(stderr, "tycana evidence status: %v\n", err)
		return 1
	}
	if r.Records > 0 {
		fmt.Fprintf(stdout, "Last signed record: %s ago.\n", now.Sub(r.To).Round(time.Minute))
	}
	writeEvidenceSummary(stdout, b, r, src, ids)
	if !r.OK() {
		return 1
	}
	return 0
}
