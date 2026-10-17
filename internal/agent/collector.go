package agent

import (
	"context"
	"os"
	"time"

	"tycana.ai/agent/evidence"
	"tycana.ai/agent/internal/baseline"
	"tycana.ai/agent/internal/collect"
	"tycana.ai/agent/internal/inventory"
)

// HostCollector is the production Collector: the same observers as the
// CLI commands, on the live host.
func HostCollector(cfg Config) Collector {
	return func(ctx context.Context, now time.Time) (HostInventory, HostAssessment, []evidence.CollectError) {
		var inv HostInventory
		var as HostAssessment
		var errs []evidence.CollectError
		fail := func(src string, err error) {
			errs = append(errs, evidence.CollectError{Source: src, Error: err.Error()})
		}
		snap, _, err := inventory.Collect("/", now)
		if err != nil {
			// Nothing else can run without the package list.
			fail("inventory", err)
			return inv, as, errs
		}
		inv.Inventory = snap
		if r, err := collect.Updates(ctx, snap); err != nil {
			fail("updates", err)
		} else {
			as.Updates = &r
		}
		if r, err := collect.RestartState(ctx, snap, now); err != nil {
			fail("restart", err)
		} else {
			as.Restart = &r
		}
		var exc []baseline.Exception
		if cfg.Exceptions != "" {
			f, err := os.Open(cfg.Exceptions)
			if err == nil {
				exc, err = baseline.LoadExceptions(f)
				_ = f.Close()
			}
			if err != nil {
				fail("baseline-exceptions", err)
			}
		}
		r, err := collect.Baseline(ctx, snap, exc, cfg.BaselineTarget, now)
		if err != nil {
			fail("baseline", err)
		} else {
			as.Baseline = r
		}
		return inv, as, errs
	}
}
