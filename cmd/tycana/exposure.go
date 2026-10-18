package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"tycana.ai/agent/internal/collect"
	"tycana.ai/agent/internal/inventory"
)

func runExposure(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana exposure", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: tycana exposure\n\n"+
			"Prints, as JSON, what tycanad records for the order of actions: for each running\n"+
			"unit, the addresses and ports it listens on, its main program (from argv[0] of its\n"+
			"main process, when a package owns that file), the packages of the code it maps at\n"+
			"start, and whether it runs an interpreter; and the packages that own a setuid file.\n"+
			"Needs no privilege. Code loaded after start is not seen.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tycana exposure: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	ctx := context.Background()
	now := time.Now()
	inv, _, err := inventory.Collect("/", now)
	if err != nil {
		fmt.Fprintf(stderr, "tycana exposure: %v\n", err)
		return 1
	}
	var rs collect.Restart
	snap, err := collect.RestartInputs(ctx, inv, now, &rs)
	if err != nil {
		fmt.Fprintf(stderr, "tycana exposure: %v\n", err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(collect.Exposure(ctx, inv, snap, now)); err != nil {
		fmt.Fprintf(stderr, "tycana exposure: %v\n", err)
		return 1
	}
	return 0
}
