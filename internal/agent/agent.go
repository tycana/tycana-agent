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
	"time"

	"tycana.ai/agent/internal/baseline"
	"tycana.ai/agent/internal/collect"
	"tycana.ai/agent/internal/evidence"
	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/state"
	"tycana.ai/agent/internal/updates"
)

// HaltFile stops collection and signing while it exists (safety model
// 5.4, path B). /etc/tycana is root-owned, so only root can make it.
const HaltFile = "/etc/tycana/halt"

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
	Updates  *updates.Report  `json:"updates,omitempty"`
	Restart  *collect.Restart `json:"restart,omitempty"`
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

	key        *evidence.Key
	prevKeyID  string
	seq        uint64
	prevDigest string
	cycle      uint64
	storeErrs  []evidence.CollectError
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
	inv, as, errs := a.Collect(ctx, start)
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
	a.Log.Info("signed records", "cycle", a.cycle, "sequence", a.seq, "errors", len(errs), "seconds", a.Now().Sub(start).Seconds())
	return a.prune()
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
