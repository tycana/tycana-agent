package agent

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"tycana.ai/agent/evidence"
	"tycana.ai/agent/internal/baseline"
	"tycana.ai/agent/internal/collect"
	"tycana.ai/agent/internal/exposure"
	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/state"
	"tycana.ai/agent/internal/updates"
)

// HaltFile stops collection and signing while it exists (safety model
// 5.4, path B). /etc/tycana is root-owned, so only root can make it.
const HaltFile = "/etc/tycana/halt"

// CycleLimit is the time limit of one cycle (Mark, 2026-10-18, tycana-hq
// ADR 0025 item 7). File reads have no time limit of their own, and a
// cycle that never ends stops the records and the halt check. At the
// limit the agent keeps a marker and exits with ExitCycleLimit; systemd
// starts it again (Restart=on-failure) and the next record carries the
// error.
const CycleLimit = 10 * time.Minute

// ExitCycleLimit is the exit status at the cycle limit: EX_TEMPFAIL of
// sysexits.h, which systemd shows as "status=75/TEMPFAIL". It is not the
// unit's RestartPreventExitStatus, so systemd restarts the agent. (4 was
// tried first; systemd shows it as "4/NOPERMISSION", which reads as a
// privilege fault. Lab, 2026-10-18.)
const ExitCycleLimit = 75

// ErrCycleLimit is what Cycle returns when the limit stopped it and Exit
// returned (only in tests).
var ErrCycleLimit = errors.New("the cycle did not finish within the time limit")

// appID is Tycana's systemd application id: the host id is
// sd_id128_get_machine_app_specific(appID), so the raw machine id never
// leaves the host.
var appID = [16]byte{0x83, 0x56, 0x52, 0x4e, 0xa4, 0xd3, 0x42, 0x71, 0x90, 0xb0, 0x5a, 0x57, 0x8b, 0xce, 0xe2, 0x52}

// HostInventory is the body of a host-inventory record.
type HostInventory struct {
	Inventory *inventory.Snapshot `json:"inventory,omitempty"`
}

// HostAssessment is the body of a host-assessment record.
type HostAssessment struct {
	Updates *updates.Report  `json:"updates,omitempty"`
	Restart *collect.Restart `json:"restart,omitempty"`
	// Exposure is what the matcher orders actions by (tycana-hq ADR
	// 0029, ADR 0032).
	Exposure *exposure.Report `json:"exposure,omitempty"`
	Baseline *baseline.Report `json:"baseline,omitempty"`
}

// Collector gathers one cycle's data. Errors per source go into the
// records; the agent never signs a record that hides a failure.
type Collector func(ctx context.Context, now time.Time) (HostInventory, HostAssessment, []evidence.CollectError)

// Agent is one tycanad process.
type Agent struct {
	Store   *state.Store
	Config  Config
	Collect Collector
	Log     *slog.Logger
	Now     func() time.Time
	// Root is the host root ("/"); tests use a fixture.
	Root string
	// HaltPath is HaltFile; tests change it.
	HaltPath string
	// Version and Commit are the build's.
	Version, Commit string
	// Check is the result of the start-up self-check.
	Check SelfCheck
	// Limit is the cycle time limit; zero means CycleLimit.
	Limit time.Duration
	// Exit ends the process at the cycle limit; nil means os.Exit.
	Exit func(code int)

	key        *evidence.Key
	prevKeyID  string
	seq        uint64
	prevDigest string
	cycle      uint64
	storeErrs  []evidence.CollectError
	// overrun is set when Init found a cycle-limit marker; the marker
	// is removed after the next record names it.
	overrun bool
	// writeMu orders the cycle's writes and the cycle-limit exit, so the
	// agent never exits in the middle of a record.
	writeMu sync.Mutex
}

// Init loads or makes the key and finds the end of the chain. It runs
// once, before the first cycle.
func (a *Agent) Init() error {
	recs, err := a.Store.Records()
	if err != nil {
		return err
	}
	// A new key only when the key file is absent or does not parse. A
	// key that is present and parses is never replaced (Fable review of
	// ADR 0025); an error reading it stops the agent.
	k, err := a.Store.Key()
	var perr *evidence.ParseError
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist), errors.As(err, &perr):
		if err != nil && perr != nil {
			a.Log.Warn("host key does not parse; making a new key", "error", err)
		}
		if k, err = a.Store.CreateKey(true); err != nil {
			return fmt.Errorf("host key: %w", err)
		}
		a.Log.Info("made a new host key", "keyid", k.ID)
	default:
		return fmt.Errorf("host key: %w", err)
	}
	a.key = k
	if o, err := a.Store.OverrunMarker(); err != nil {
		a.storeErr(fmt.Sprintf("cycle-limit marker: %v", err))
	} else if o != nil {
		a.overrun = true
		a.storeErrs = append(a.storeErrs, evidence.CollectError{Source: "cycle-limit", Error: o.Message(a.limit())})
	}
	if len(recs) == 0 {
		return nil
	}
	last := recs[len(recs)-1]
	a.seq = last.Sequence
	raw, err := state.ReadRecord(last)
	if err != nil {
		a.storeErr(fmt.Sprintf("record %d cannot be read: %v", last.Sequence, err))
		return nil
	}
	var env evidence.Envelope
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Signatures) == 0 {
		a.storeErr(fmt.Sprintf("record %d is not an envelope", last.Sequence))
		return nil //nolint:nilerr // recorded in the next record
	}
	signer := env.Signatures[0].KeyID
	pub, der, err := evidence.ParsePublic(k.PublicPEM())
	if err != nil {
		return err
	}
	c, err := evidence.Open(raw, map[string]*ecdsa.PublicKey{k.ID: pub}, map[string][]byte{k.ID: der})
	if err != nil {
		if signer != k.ID {
			// The chain continues with a new key; the record says so.
			a.prevKeyID = signer
		} else {
			a.storeErr(fmt.Sprintf("record %d does not verify with the host key: %v", last.Sequence, err))
		}
		a.prevDigest = payloadDigest(env)
		return nil
	}
	a.prevDigest = evidence.Digest(c.Payload)
	a.cycle = c.Header.Record.Cycle
	a.Check.ComparePrevious(PreviousAgent{Version: c.Header.Agent.Version, Commit: c.Header.Agent.Commit, BinarySHA256: c.Header.Agent.BinarySHA256}, a.Version, a.Commit)
	return nil
}

// payloadDigest is the chain digest of an envelope that did not verify,
// so the next record still names it.
func payloadDigest(env evidence.Envelope) string {
	p, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return ""
	}
	return evidence.Digest(p)
}

func (a *Agent) storeErr(msg string) {
	a.Log.Warn("state directory", "problem", msg)
	a.storeErrs = append(a.storeErrs, evidence.CollectError{Source: "store", Error: msg})
}

// Halted reports whether the halt file exists. Any type counts, a
// dangling symbolic link too.
func (a *Agent) Halted() bool {
	_, err := os.Lstat(a.HaltPath)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
}

// Cycle collects once and keeps two signed records. It does nothing
// while halted.
func (a *Agent) Cycle(ctx context.Context) error {
	if a.Halted() {
		a.Log.Info("halt file present: no collection and no records", "path", a.HaltPath)
		return a.markHalt()
	}
	start := a.Now()
	w := a.watch(start)
	inv, as, errs := a.Collect(context.WithValue(ctx, stepKey{}, w.setStep), start)
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if !w.finish() {
		<-w.done
		return ErrCycleLimit
	}
	if a.Halted() {
		a.Log.Info("halt file appeared during the cycle: nothing signed", "path", a.HaltPath)
		return a.markHalt()
	}
	halt, err := a.Store.HaltMarker()
	if err != nil {
		a.storeErr(fmt.Sprintf("halt marker: %v", err))
	}
	a.cycle++
	errs = append(a.storeErrs, errs...)
	a.storeErrs = nil
	host := a.hostInfo(inv.Inventory)
	if err := a.sign(evidence.TypeHostInventory, host, errs, halt, inv); err != nil {
		return err
	}
	if err := a.sign(evidence.TypeHostAssessment, host, errs, halt, as); err != nil {
		return err
	}
	if halt != nil {
		// Both records of this cycle name the halt; the next do not.
		if err := a.Store.ClearHaltMarker(); err != nil {
			return err
		}
	}
	if a.overrun {
		if err := a.Store.ClearOverrunMarker(); err != nil {
			return err
		}
		a.overrun = false
	}
	a.Log.Info("signed records", "cycle", a.cycle, "sequence", a.seq, "errors", len(errs), "seconds", a.Now().Sub(start).Seconds())
	return a.prune()
}

func (a *Agent) limit() time.Duration {
	if a.Limit > 0 {
		return a.Limit
	}
	return CycleLimit
}

// stepKey holds the watchdog's step setter in the collector's context.
type stepKey struct{}

// SetStep names the collector that runs now, for the cycle-limit error.
func SetStep(ctx context.Context, name string) {
	if f, ok := ctx.Value(stepKey{}).(func(string)); ok {
		f(name)
	}
}

// watchdog ends a cycle that runs past the limit.
type watchdog struct {
	mu       sync.Mutex
	step     string
	finished bool
	fired    bool
	done     chan struct{}
	timer    *time.Timer
}

func (a *Agent) watch(start time.Time) *watchdog {
	w := &watchdog{done: make(chan struct{})}
	w.timer = time.AfterFunc(a.limit(), func() { a.limitReached(w, start) })
	return w
}

func (w *watchdog) setStep(s string) {
	w.mu.Lock()
	w.step = s
	w.mu.Unlock()
}

// finish ends the watch. It reports false when the limit came first.
// The caller holds writeMu, so it is past the limit only if the
// watchdog already ran.
func (w *watchdog) finish() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.timer.Stop()
	if w.fired {
		return false
	}
	w.finished = true
	return true
}

// limitReached runs at the limit. A cycle that is writing its records
// holds writeMu; when it finishes, the watch is over and nothing
// happens. Otherwise the marker is kept and the process exits.
func (a *Agent) limitReached(w *watchdog, start time.Time) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	w.mu.Lock()
	if w.finished {
		w.mu.Unlock()
		return
	}
	w.fired = true
	step := w.step
	w.mu.Unlock()
	defer close(w.done)
	o, err := a.Store.OverrunMarker()
	if err != nil || o == nil {
		o = &state.Overrun{First: start.UTC().Truncate(time.Millisecond)}
	}
	o.Last, o.Step = start.UTC().Truncate(time.Millisecond), step
	o.Count++
	if err := a.Store.SetOverrunMarker(*o); err != nil {
		a.Log.Error("cycle-limit marker", "error", err)
	}
	a.Log.Error("the cycle did not finish within the time limit: exiting, systemd starts the agent again",
		"limit", a.limit().String(), "step", step, "started", start.UTC())
	exit := a.Exit
	if exit == nil {
		exit = os.Exit
	}
	exit(ExitCycleLimit)
}

// markHalt records that a cycle saw the halt file: the first time it was
// seen stays, the last time moves.
func (a *Agent) markHalt() error {
	now := a.Now().UTC().Truncate(time.Millisecond)
	h, err := a.Store.HaltMarker()
	if err != nil || h == nil {
		h = &evidence.Halt{From: now}
	}
	h.To = now
	return a.Store.SetHaltMarker(*h)
}

func (a *Agent) sign(typ string, host evidence.HostInfo, errs []evidence.CollectError, halt *evidence.Halt, body any) error {
	h := evidence.Header{
		Record: evidence.RecordInfo{Type: typ, Sequence: a.seq + 1, Previous: a.prevDigest,
			PreviousKeyID: a.prevKeyID, Created: a.Now().UTC().Truncate(time.Millisecond), Cycle: a.cycle},
		Host: host,
		Agent: evidence.AgentInfo{Version: a.Version, Commit: a.Commit, BinarySHA256: a.Check.SHA256,
			SelfCheck: a.Check.Result},
		Errors: errs,
		Halted: halt,
	}
	if len(a.Config.Tags) > 0 {
		h.Operator = &evidence.Operator{Tags: a.Config.Tags}
	}
	payload, err := evidence.NewStatement(h, a.key.PublicDER, body)
	if err != nil {
		return err
	}
	env, err := a.key.Sign(payload)
	if err != nil {
		return err
	}
	raw, err := env.Marshal()
	if err != nil {
		return err
	}
	if err := a.Store.Append(h.Record.Sequence, typ, raw); err != nil {
		return err
	}
	a.seq, a.prevDigest, a.prevKeyID = h.Record.Sequence, evidence.Digest(payload), ""
	return nil
}

func (a *Agent) hostInfo(inv *inventory.Snapshot) evidence.HostInfo {
	h := evidence.HostInfo{ID: a.hostID()}
	if b, err := os.ReadFile(a.Root + "proc/sys/kernel/hostname"); err == nil {
		h.Hostname = strings.TrimSpace(string(b))
	}
	if inv != nil {
		h.OS, h.OSVersion = inv.OS.ID, inv.OS.VersionID
		h.BootID, h.Kernel = inv.Kernel.Running.BootID, inv.Kernel.Running.Release
	}
	return h
}

func (a *Agent) hostID() string {
	b, err := os.ReadFile(a.Root + "etc/machine-id")
	if err != nil {
		return ""
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(raw) != 16 {
		return ""
	}
	var mid [16]byte
	copy(mid[:], raw)
	return evidence.AppSpecificID(mid, appID)
}

// prune deletes records older than the retention, oldest first, and
// never the newest MinRecords.
func (a *Agent) prune() error {
	recs, err := a.Store.Records()
	if err != nil || len(recs) <= MinRecords {
		return err
	}
	cutoff := a.Now().AddDate(0, 0, -a.Config.RetentionDays)
	for _, r := range recs[:len(recs)-MinRecords] {
		raw, err := state.ReadRecord(r)
		if err != nil {
			return err
		}
		var env evidence.Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return fmt.Errorf("record %d: %w", r.Sequence, err)
		}
		var st struct {
			Predicate struct {
				Record evidence.RecordInfo `json:"record"`
			} `json:"predicate"`
		}
		p, err := base64.StdEncoding.DecodeString(env.Payload)
		if err == nil {
			err = json.Unmarshal(p, &st)
		}
		if err != nil {
			return fmt.Errorf("record %d: %w", r.Sequence, err)
		}
		if !st.Predicate.Record.Created.Before(cutoff) {
			break
		}
		if err := a.Store.Remove(r); err != nil {
			return err
		}
	}
	return nil
}

// Run cycles until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	t := time.NewTicker(time.Duration(a.Config.Interval))
	defer t.Stop()
	for {
		if err := a.Cycle(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
