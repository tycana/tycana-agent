package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"tycana.ai/agent/internal/history"
)

func runHistory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana history", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	since := fs.String("since", "", "only changes at or after this time (2006-01-02 or RFC 3339; dates are UTC)")
	root := fs.String("root", "/", "read the host rooted at this directory")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: tycana history [--since TIME] [--format text|json] [--root DIR]\n\n"+
			"Normalizes dpkg.log and apt history.log (rotations included) and dnf's history database. Never writes or runs anything.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tycana history: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	h, err := history.Collect(*root)
	if err != nil {
		fmt.Fprintf(stderr, "tycana history: %v\n", err)
		return 1
	}
	if *since != "" {
		t, err := parseSince(*since)
		if err != nil {
			fmt.Fprintf(stderr, "tycana history: --since: %v\n", err)
			return 2
		}
		h = h.Since(t)
	}
	switch *format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(h)
	case "text":
		err = writeHistoryText(stdout, h)
	default:
		fmt.Fprintf(stderr, "tycana history: unknown format %q\n", *format)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "tycana history: %v\n", err)
		return 1
	}
	return 0
}

func parseSince(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", s)
}

func writeHistoryText(w io.Writer, h *history.History) error {
	fmt.Fprintf(w, "Times are UTC, converted from %s (%s).\n", h.Zone.Name, h.Zone.Source)
	if len(h.Sources) == 0 {
		fmt.Fprintln(w, "No dpkg.log, apt history.log, or dnf history found.")
		return nil
	}
	fmt.Fprintf(w, "Sources: %s\n", strings.Join(h.Sources, ", "))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	cur := -2
	for _, c := range h.Changes {
		if c.Transaction != cur {
			cur = c.Transaction
			fmt.Fprintln(tw)
			if cur < 0 {
				fmt.Fprintf(tw, "%s  dpkg run with no apt record\n", c.Time.Format("2006-01-02 15:04:05Z"))
			} else {
				tr := h.Transactions[cur]
				who := ""
				switch {
				case tr.RequestedBy != "":
					who = "  (requested by " + safe(tr.RequestedBy) + ")"
				case tr.RequestedByUID != nil:
					who = fmt.Sprintf("  (uid %d)", *tr.RequestedByUID)
				}
				what := safe(tr.Commandline)
				if tr.Source == "dnf" {
					what = fmt.Sprintf("dnf transaction %d: %s", tr.ID, what)
					if tr.Commandline == "" {
						what = fmt.Sprintf("dnf transaction %d (no command line recorded)", tr.ID)
					}
				}
				fmt.Fprintf(tw, "%s  %s%s\n", tr.Start.Format("2006-01-02 15:04:05Z"), what, who)
				if tr.Error != "" {
					fmt.Fprintf(tw, "  apt reported an error: %s\n", safe(tr.Error))
				}
				if tr.State == "error" {
					fmt.Fprintln(tw, "  dnf recorded an error for this transaction")
				}
				if tr.OutOfBandBefore {
					fmt.Fprintln(tw, "  the rpm database changed outside dnf before this transaction")
				}
				for _, o := range tr.Output {
					fmt.Fprintf(tw, "  output: %s\n", safe(o))
				}
			}
		}
		ver := c.To
		switch {
		case c.From != "" && c.To != "" && c.From != c.To:
			ver = c.From + " -> " + c.To
		case c.To == "":
			ver = c.From
		}
		end := c.EndState
		if end == "" {
			end = "(no status recorded)"
		}
		fmt.Fprintf(tw, "  %s\t%s:%s\t%s\t%s\n", c.Kind, c.Package, c.Arch, ver, end)
	}
	return tw.Flush()
}

// safe makes host-supplied text inert on a terminal: control characters,
// including escape sequences, are shown quoted instead of interpreted.
func safe(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) < 0 {
		return s
	}
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}
