package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/inventory/dpkg"
	"tycana.ai/agent/internal/inventory/rpm"
)

func runInventory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana inventory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text, json, dpkg-query, or rpm-query (byte-identical to the native tool with the format in --help)")
	root := fs.String("root", "/", "read the host rooted at this directory (for mounted images and tests)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: tycana inventory [--format text|json|dpkg-query|rpm-query] [--root DIR]\n\n"+
			"Reads the package database, os-release, and kernel state. Never writes or runs anything.\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\n--format dpkg-query matches:\n  dpkg-query -W -f='%s'\n--format rpm-query matches:\n  LC_ALL=C rpm -qa --qf '%s'\n", dpkg.QueryFormat, rpm.QueryFormat)
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tycana inventory: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	snap, native, err := inventory.Collect(*root, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "tycana inventory: %v\n", err)
		return 1
	}
	switch *format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(snap)
	case "dpkg-query":
		if native.Dpkg == nil {
			fmt.Fprintf(stderr, "tycana inventory: the host's package database is %s, not deb\n", snap.PackageDB.Format)
			return 1
		}
		err = native.Dpkg.WriteQuery(stdout)
	case "rpm-query":
		if native.RPM == nil {
			fmt.Fprintf(stderr, "tycana inventory: the host's package database is %s, not rpm\n", snap.PackageDB.Format)
			return 1
		}
		err = native.RPM.WriteQuery(stdout)
	case "text":
		err = writeText(stdout, snap)
	default:
		fmt.Fprintf(stderr, "tycana inventory: unknown format %q\n", *format)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "tycana inventory: %v\n", err)
		return 1
	}
	return 0
}

func writeText(w io.Writer, s *inventory.Snapshot) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	name := s.OS.PrettyName
	if name == "" {
		name = s.OS.ID + " " + s.OS.VersionID
	}
	fmt.Fprintf(tw, "Host OS\t%s\n", name)
	fmt.Fprintf(tw, "Kernel running\t%s\n", s.Kernel.Running.Release)
	if s.Kernel.NewestInstalled != "" && s.Kernel.NewestInstalled != s.Kernel.Running.Release {
		fmt.Fprintf(tw, "Kernel newest\t%s (installed, not running)\n", s.Kernel.NewestInstalled)
	}
	switch {
	case len(s.Kernel.LivePatches) > 0:
		names := make([]string, 0, len(s.Kernel.LivePatches))
		for _, p := range s.Kernel.LivePatches {
			names = append(names, p.Name)
		}
		fmt.Fprintf(tw, "Live patches\t%s (effective level unknown until M2)\n", strings.Join(names, ", "))
	case len(s.Kernel.KspliceModules) > 0:
		fmt.Fprintf(tw, "Ksplice\tloaded (effective level unknown until M2)\n")
	default:
		fmt.Fprintf(tw, "Live patches\tnone\n")
	}
	counts := map[string]int{}
	for _, p := range s.Packages {
		counts[p.State]++
	}
	other := len(s.Packages) - counts["installed"] - counts["config-files"]
	if s.PackageDB.Format == "rpm" {
		fmt.Fprintf(tw, "Packages\t%d installed (%s, %s)\n", counts["installed"], s.PackageDB.Format, s.PackageDB.Path)
	} else {
		fmt.Fprintf(tw, "Packages\t%d installed, %d removed with config left, %d partly installed (%s, %s)\n",
			counts["installed"], counts["config-files"], other, s.PackageDB.Format, s.PackageDB.Path)
	}
	if s.PackageDB.JournalReplayed > 0 {
		fmt.Fprintf(tw, "Warning\tdpkg journal had %d pending entries: dpkg is running or was interrupted\n", s.PackageDB.JournalReplayed)
	}
	if s.PackageDB.Retries > 0 {
		fmt.Fprintf(tw, "Warning\tthe rpm database changed during the read; read again %d time(s)\n", s.PackageDB.Retries)
	}
	for _, n := range s.PackageDB.Notes {
		fmt.Fprintf(tw, "Note\t%s\n", n)
	}
	fmt.Fprintln(tw)
	fmt.Fprintln(tw, "STATE\tNAME\tARCH\tVERSION\tSOURCE")
	for _, p := range s.Packages {
		state := p.State
		if p.Want == "hold" {
			state += ",held"
		}
		src := ""
		if p.SourceName != "" && (p.SourceName != p.Name || p.SourceEVR != p.EVR) {
			src = p.SourceName + " " + p.SourceEVR
		}
		arch := p.Arch
		if arch == "" {
			arch = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", state, p.Name, arch, p.EVR, src)
	}
	return tw.Flush()
}
