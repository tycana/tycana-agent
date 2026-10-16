package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"tycana.ai/agent/internal/baseline"
	"tycana.ai/agent/internal/inventory"
)

func runBaseline(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana baseline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	file := fs.String("file", "", "evaluate this baseline file instead of the built-in preset")
	excFile := fs.String("exceptions", "", "exceptions file (version 1)")
	target := fs.Float64("target", baseline.DefaultTarget, "target compliance score in percent")
	all := fs.Bool("all", false, "list every check, not only the ones that did not pass")
	list := fs.Bool("list", false, "list the built-in baselines and exit")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: tycana baseline [--format text|json] [--file BASELINE] [--exceptions FILE] [--target N] [--all]\n"+
			"       tycana baseline --list\n\n"+
			"Evaluates the host against a configuration baseline. The built-in baselines are\n"+
			"generated from ComplianceAsCode content. Only reads; changes nothing.\n\n"+
			"A check the agent cannot read without privilege is \"unknown\", never \"fail\".\n"+
			"The score is passed / (passed + failed); excepted, not applicable, unknown,\n"+
			"and faulty checks are counted apart.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tycana baseline: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "tycana baseline: unknown format %q\n", *format)
		return 2
	}
	if *list {
		ps, err := baseline.Presets()
		if err != nil {
			fmt.Fprintf(stderr, "tycana baseline: %v\n", err)
			return 1
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tFOR\tCHECKS\tNOT COVERED\tTITLE")
		for _, b := range ps {
			var rel []string
			for _, r := range b.Applies {
				rel = append(rel, r.ID+" "+r.VersionID)
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", b.Name, strings.Join(rel, ", "), len(b.Checks), len(b.NotCovered), b.Title)
		}
		_ = tw.Flush()
		return 0
	}
	now := time.Now()
	snap, _, err := inventory.Collect("/", now)
	if err != nil {
		fmt.Fprintf(stderr, "tycana baseline: %v\n", err)
		return 1
	}
	var b *baseline.Baseline
	if *file != "" {
		b, err = loadFile(*file, baseline.Load)
		if err == nil && !b.For(snap.OS.ID, snap.OS.VersionID) {
			fmt.Fprintf(stderr, "tycana baseline: note: %s is not for %s %s\n", b.Name, snap.OS.ID, snap.OS.VersionID)
		}
	} else {
		b, err = baseline.PresetFor(snap.OS.ID, snap.OS.VersionID)
	}
	if err != nil {
		fmt.Fprintf(stderr, "tycana baseline: %v\n", err)
		return 1
	}
	var exc []baseline.Exception
	if *excFile != "" {
		exc, err = loadFile(*excFile, baseline.LoadExceptions)
		if err != nil {
			fmt.Fprintf(stderr, "tycana baseline: %v\n", err)
			return 1
		}
	}
	h, err := baseline.Collect(context.Background(), b, snap)
	if err != nil {
		fmt.Fprintf(stderr, "tycana baseline: %v\n", err)
		return 1
	}
	r := baseline.Evaluate(b, h, exc, *target, now)
	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(r)
	} else {
		err = writeBaselineText(stdout, r, *all)
	}
	if err != nil {
		fmt.Fprintf(stderr, "tycana baseline: %v\n", err)
		return 1
	}
	return 0
}

func loadFile[T any](path string, load func(io.Reader) (T, error)) (T, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied path, read-only
	if err != nil {
		var zero T
		return zero, err
	}
	defer func() { _ = f.Close() }()
	return load(f)
}

// statusOrder is the order of the text report: what needs work first.
var statusOrder = []baseline.Status{baseline.Fail, baseline.Unknown, baseline.Error,
	baseline.Excepted, baseline.NotApplicable, baseline.Pass}

func writeBaselineText(w io.Writer, r baseline.Report, all bool) error {
	s := r.Score
	met := "below"
	if s.Met {
		met = "meets"
	}
	fmt.Fprintf(w, "%s: %.1f%% (%d of %d evaluated checks pass), %s the %.0f%% target.\n",
		r.Title, s.Percent, s.Passed, s.Passed+s.Failed, met, s.Target)
	fmt.Fprintf(w, "Not in the score: %d excepted, %d not applicable, %d unknown (cannot read without privilege or through the sandbox), %d faulty content, %d source rules not covered.\n",
		s.Excepted, s.NotApplicable, s.Unknown, s.Errors, s.NotCovered)
	fmt.Fprintf(w, "Source: %s %s (%s), %s.\n\n", r.Source.Project, short(r.Source.Commit), r.Source.Product, r.Source.License)
	res := slices.Clone(r.Results)
	slices.SortStableFunc(res, func(a, b baseline.Result) int {
		return slices.Index(statusOrder, a.Status) - slices.Index(statusOrder, b.Status)
	})
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCHECK\tSEVERITY\tWHY")
	for _, x := range res {
		if !all && (x.Status == baseline.Pass || x.Status == baseline.NotApplicable) {
			continue
		}
		why := x.Reason
		if x.Exception != nil {
			why = fmt.Sprintf("%s (owner %s, until %s; found %s)", x.Exception.Reason, x.Exception.Owner, x.Exception.Expires, x.Found)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", x.Status, x.ID, x.Severity, why)
	}
	return tw.Flush()
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
