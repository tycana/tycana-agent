// Command tycanad is the Tycana host agent: an unprivileged observer that
// reads package, update, and restart state and reports it.
//
// It never changes a host. There is no write unit, no package-manager
// invocation beyond read-only queries, and no code path that modifies
// packages, services, or configuration. CI enforces this (tools/nowrite).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"tycana.ai/agent/internal/buildinfo"
)

const description = `tycanad — the Tycana host agent (observe-only)

tycanad runs as an unprivileged service, reads what is installed, what is
pending, and what needs a restart, and signs what it saw. It never changes
the host.

This build is the M0 skeleton: no observers are implemented yet. Running it
without --help or --version exits with status 2.

Flags:
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycanad", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, description)
		fs.PrintDefaults()
	}
	showVersion := fs.Bool("version", false, "print build information and exit")
	configPath := fs.String("config", "/etc/tycana/tycanad.yaml", "path to the agent configuration (unused in this build)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		if err := buildinfo.Get().Write(stdout, false); err != nil {
			fmt.Fprintf(stderr, "tycanad: %v\n", err)
			return 1
		}
		return 0
	}
	_ = configPath
	fmt.Fprintln(stderr, "tycanad: no observers are implemented in this build (M0 skeleton); see --help")
	return 2
}
