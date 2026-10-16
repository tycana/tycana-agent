// Command tycana is the operator CLI for the Tycana agent.
//
// The agent never changes a host. This CLI reads and reports; it has no
// subcommand that modifies packages, services, or configuration.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"tycana.ai/agent/internal/buildinfo"
)

const usage = `tycana — operator CLI for the Tycana agent (observe-only)

Usage:
  tycana <command> [flags]

Commands:
  inventory   list installed packages, OS, and kernel state (--format json|dpkg-query)
  history     package changes from dpkg and apt logs (--since DATE, --format json)
  version     print build information (--json for machine-readable output)
  help        print this help

The agent never changes a host. Every command here reads and reports.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "history":
		return runHistory(args[1:], stdout, stderr)
	case "inventory":
		return runInventory(args[1:], stdout, stderr)
	case "version":
		return runVersion(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "--version":
		return runVersion(nil, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "tycana: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := buildinfo.Get().Write(stdout, *asJSON); err != nil {
		fmt.Fprintf(stderr, "tycana: %v\n", err)
		return 1
	}
	return 0
}
