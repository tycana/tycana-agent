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
	ctx := context.Background()
	var r updates.Report
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
		hostexec.AllowScratch = *scratch
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
		if errors.Is(err, hostexec.ErrScratchWrite) {
			err = fmt.Errorf("%w\n(dnf would leave /var/tmp/dnf-%s-* on this host; pass --allow-dnf-scratch to accept that)", err, dnfUser())
		}
	default:
		err = fmt.Errorf("package format %q not supported", snap.PackageDB.Format)
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
