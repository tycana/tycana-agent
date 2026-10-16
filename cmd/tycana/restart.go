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
	Kernel *kernelRestart `json:"kernel,omitempty"`
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
		if err == nil {
			out.Kernel = kernelState(inv.Kernel)
			snap, err = restart.Collect(context.Background(), now)
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
	fmt.Fprintf(w, "%d units use a file replaced since they started (inferred); %d unknown; %d with no evidence.\n",
		count[restart.Inferred], count[restart.Unknown], count[restart.None])
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
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Status, f.Unit, started, detail)
	}
	return tw.Flush()
}
