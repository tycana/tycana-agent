package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"tycana.ai/agent/internal/agent"
	"tycana.ai/agent/internal/state"
)

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("state-dir", state.DefaultDir, "tycanad's state directory")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: tycana status [--state-dir DIR]\n\n"+
			"Shows the latest state that tycanad signed on this host, and whether its chain\n"+
			"of records is complete. Only root and the tycana user can read the records; run\n"+
			"it with sudo. For a live view without privilege, use tycana inventory, updates,\n"+
			"restart, and baseline.\n\n")
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
	b, err := exportBundle(state.Reader(*dir), time.Time{}, now)
	if err != nil {
		fmt.Fprintf(stderr, "tycana status: %v\n", err)
		if errors.Is(err, os.ErrPermission) {
			fmt.Fprintln(stderr, "Only root and the tycana user can read the records. Run the command with sudo.")
		}
		return 1
	}
	r, src, ids, err := b.Verify(nil)
	if err != nil {
		fmt.Fprintf(stderr, "tycana status: %v\n", err)
		return 1
	}
	if r.Records > 0 {
		age := now.Sub(r.To).Round(time.Minute)
		fmt.Fprintf(stdout, "Last signed record: %s ago.\n", age)
	}
	writeEvidenceSummary(stdout, b, r, src, ids)
	if !r.OK() {
		return 1
	}
	return 0
}
