package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
	"text/tabwriter"
	"time"

	"tycana.ai/agent/internal/collect"
	"tycana.ai/agent/internal/hostexec"
	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/updates"
)

func runUpdates(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana updates", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	scratch := fs.Bool("allow-dnf-scratch", false, "let dnf create its /var/tmp/dnf-USER-* directory on this host")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: tycana updates [--format text|json] [--allow-dnf-scratch]\n\n"+
			"Lists the updates waiting on this host, as apt or dnf computes them from its own\n"+
			"metadata. Runs only simulations and queries; never refreshes metadata or installs.\n\n"+
			"dnf, run without root, always creates /var/tmp/dnf-USER-* for its logs and locks.\n"+
			"Inside the tycanad unit /var/tmp is private and that directory disappears; run\n"+
			"directly, it stays on the host, so this command refuses unless you pass\n"+
			"--allow-dnf-scratch.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tycana updates: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "tycana updates: unknown format %q\n", *format)
		return 2
	}
	snap, _, err := inventory.Collect("/", time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "tycana updates: %v\n", err)
		return 1
	}
	if snap.PackageDB.Format == "rpm" {
		hostexec.AllowScratch = *scratch
	}
	r, err := collect.Updates(context.Background(), snap)
	if errors.Is(err, hostexec.ErrScratchWrite) {
		err = fmt.Errorf("%w\n(dnf would leave /var/tmp/dnf-%s-* on this host; pass --allow-dnf-scratch to accept that)", err, dnfUser())
	}
	if err != nil {
		fmt.Fprintf(stderr, "tycana updates: %v\n", err)
		return 1
	}
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(r)
	} else {
		err = writeUpdatesText(stdout, r)
	}
	if err != nil {
		fmt.Fprintf(stderr, "tycana updates: %v\n", err)
		return 1
	}
	return 0
}

func writeUpdatesText(w io.Writer, r updates.Report) error {
	count := map[updates.State]int{}
	sec := 0
	for _, u := range r.Updates {
		count[u.State]++
		if u.Security && u.State != updates.Phased && u.State != updates.Held {
			sec++
		}
	}
	now := count[updates.Upgrade] + count[updates.DistUpgrade] + count[updates.New]
	fmt.Fprintf(w, "%d updates can be installed now (%s), %d with a security fix.\n",
		now, r.Manager, sec)
	if n := count[updates.Phased]; n > 0 {
		fmt.Fprintf(w, "%d deferred by phasing.\n", n)
	}
	if n := count[updates.Held]; n > 0 {
		fmt.Fprintf(w, "%d held by an operator.\n", n)
	}
	if len(r.Removals) > 0 {
		fmt.Fprintf(w, "%d packages would be removed by a full upgrade.\n", len(r.Removals))
	}
	writeAutopilotText(w, r.Autopilot)
	if len(r.Updates) == 0 {
		return nil
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATE\tSEC\tPACKAGE\tINSTALLED\tCANDIDATE\tFROM")
	for _, u := range r.Updates {
		mark := ""
		if u.Security {
			mark = "yes"
		}
		state := string(u.State)
		if u.PhasedPercent > 0 {
			state = fmt.Sprintf("%s %d%%", state, u.PhasedPercent)
		}
		suites := make([]string, 0, len(u.Origins))
		for _, o := range u.Origins {
			suites = append(suites, o.Suite)
		}
		installed := u.Installed
		if installed == "" {
			installed = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s:%s\t%s\t%s\t%s\n", state, mark, u.Name, u.Arch, installed, u.Candidate, strings.Join(suites, ","))
	}
	for _, rm := range r.Removals {
		fmt.Fprintf(tw, "remove\t\t%s\t%s\t-\t\n", rm.Name, rm.Installed)
	}
	return tw.Flush()
}

// writeAutopilotText says what the host's own updater will do.
func writeAutopilotText(w io.Writer, a *updates.Autopilot) {
	if a == nil {
		return
	}
	fmt.Fprintln(w)
	switch {
	case !a.Installed:
		fmt.Fprintf(w, "Autopilot: %s is not installed. Nothing installs updates on its own.\n", a.Tool)
		return
	case a.Runs && !a.NextRun.IsZero():
		fmt.Fprintf(w, "Autopilot: %s runs next at %s UTC (%s).\n", a.Tool, a.NextRun.Format("2006-01-02 15:04"), a.Timer)
	case a.Runs:
		fmt.Fprintf(w, "Autopilot: %s runs (%s).\n", a.Tool, a.Timer)
	default:
		fmt.Fprintf(w, "Autopilot: %s will not run: %s.\n", a.Tool, strings.Join(a.Why, "; "))
	}
	sec := 0
	for _, p := range a.Install {
		if p.Security {
			sec++
		}
	}
	verb := "It installs"
	if !a.Runs {
		verb = "If it ran, it would install"
	}
	fmt.Fprintf(w, "%s %d of these updates (%d with a security fix) and leaves %d, judged on today's package lists.\n",
		verb, len(a.Install), sec, len(a.Skip))
	if len(a.Origins) > 0 {
		fmt.Fprintf(w, "Allowed origins: %s.\n", strings.Join(a.Origins, "; "))
	}
	if a.UpgradeType != "" {
		fmt.Fprintf(w, "Upgrade type: %s.\n", a.UpgradeType)
	}
	fmt.Fprintf(w, "Automatic reboot: %s.\n", a.Reboot)
	if a.Runs {
		for _, why := range a.Why {
			fmt.Fprintf(w, "Note: %s.\n", why)
		}
	}
}

// distroID is unattended-upgrades' ${distro_id}: lsb_release's ID, which
// is os-release's ID with a capital first letter for the distributions it
// supports.
// dnfUser names the user dnf will run as: hostexec runs commands as
// nobody when the CLI is root.
func dnfUser() string {
	if os.Geteuid() == 0 {
		return "nobody"
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "USER"
}
