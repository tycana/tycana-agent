// Command tycanad is the Tycana host agent: an unprivileged observer that
// reads package, update, restart, and baseline state, and signs what it
// saw (tycana-hq ADR 0025).
//
// It never changes a host. There is no write unit, no package-manager
// invocation beyond read-only queries, and no code path that modifies
// packages, services, or configuration. Its only writes are its key and
// records in its own state directory. CI enforces this (tools/nowrite).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"tycana.ai/agent/internal/agent"
	"tycana.ai/agent/internal/buildinfo"
	"tycana.ai/agent/internal/hostexec"
	"tycana.ai/agent/internal/state"
)

const description = `tycanad — the Tycana host agent (observe-only)

tycanad runs as an unprivileged service. At each interval it reads what is
installed, what is waiting, what needs a restart, and the configuration
baseline, and keeps two records signed with the host key in its state
directory. It never changes the host.

While /etc/tycana/halt exists, it collects nothing and signs nothing.
At start it compares its own binary with the package that installed it;
on a mismatch it exits with status 3.

Flags:
`

// exitBinaryChanged is the unit's RestartPreventExitStatus.
const exitBinaryChanged = 3

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
	configPath := fs.String("config", agent.ConfigPath, "path to the agent configuration")
	stateDir := fs.String("state-dir", state.DefaultDir, "the agent's state directory (the unit's StateDirectory)")
	once := fs.Bool("once", false, "run one cycle and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tycanad: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	if *showVersion {
		if err := buildinfo.Get().Write(stdout, false); err != nil {
			fmt.Fprintf(stderr, "tycanad: %v\n", err)
			return 1
		}
		return 0
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{} // journald adds the time
			}
			return a
		},
	}))
	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		log.Error("configuration", "error", err)
		return 1
	}
	bi := buildinfo.Get()
	check, err := agent.CheckBinary("/", "/proc/self/exe")
	if err != nil {
		log.Error("self-check failed: not starting", "error", err)
		if errors.Is(err, agent.ErrBinaryChanged) {
			return exitBinaryChanged
		}
		return 1
	}
	store, err := state.Open(*stateDir)
	if err != nil {
		log.Error("state directory", "error", err)
		return 1
	}
	a := &agent.Agent{
		Store: store, Config: cfg, Collect: agent.HostCollector(cfg), Log: log,
		Now: time.Now, Root: "/", HaltPath: agent.HaltFile,
		Version: bi.Version, Commit: bi.Commit, Check: check,
	}
	if err := a.Init(); err != nil {
		log.Error("start", "error", err)
		return 1
	}
	log.Info("started", "version", bi.Version, "self_check", a.Check.Result, "detail", a.Check.Detail,
		"interval", time.Duration(cfg.Interval).String(), "retention_days", cfg.RetentionDays)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, hostexec.Terminate)
	defer stop()
	if *once {
		err = a.Cycle(ctx)
	} else {
		err = a.Run(ctx)
	}
	if err != nil {
		log.Error("cycle", "error", err)
		return 1
	}
	return 0
}
