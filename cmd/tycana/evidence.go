package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"tycana.ai/agent/internal/agent"
	"tycana.ai/agent/internal/evidence"
	"tycana.ai/agent/internal/state"
	"tycana.ai/agent/internal/updates"
)

const evidenceUsage = `Usage: tycana evidence export [--state-dir DIR] [--since DATE] > bundle.json
       tycana evidence verify [--key PUBLIC-KEY] BUNDLE

export writes the signed records that tycanad keeps on this host, with the
public keys that signed them, as one JSON bundle on standard output, and a
readable summary on standard error. Only root and the tycana user can read
the records.

verify checks every signature and the chain of a bundle, and reads nothing
on the host. Without --key it trusts the keys in the bundle and says so;
with --key it trusts only that public key (PEM), for example one you kept
from an earlier export.
`

func runEvidence(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, evidenceUsage)
		return 2
	}
	switch args[0] {
	case "export":
		return runExport(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, evidenceUsage)
		return 0
	}
	fmt.Fprintf(stderr, "tycana evidence: unknown command %q\n\n%s", args[0], evidenceUsage)
	return 2
}

func runExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana evidence export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("state-dir", state.DefaultDir, "tycanad's state directory")
	since := fs.String("since", "", "only records created on or after this date (YYYY-MM-DD, UTC)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tycana evidence export: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	var from time.Time
	if *since != "" {
		t, err := time.Parse("2006-01-02", *since)
		if err != nil {
			fmt.Fprintf(stderr, "tycana evidence export: --since: %v\n", err)
			return 2
		}
		from = t
	}
	b, err := exportBundle(state.Reader(*dir), from, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "tycana evidence export: %v\n", err)
		if errors.Is(err, os.ErrPermission) {
			fmt.Fprintln(stderr, "Only root and the tycana user can read the records. Run the command with sudo.")
		}
		return 1
	}
	enc := json.NewEncoder(stdout)
	if err := enc.Encode(b); err != nil {
		fmt.Fprintf(stderr, "tycana evidence export: %v\n", err)
		return 1
	}
	r, src, ids, err := b.Verify(nil)
	if err != nil {
		fmt.Fprintf(stderr, "tycana evidence export: %v\n", err)
		return 1
	}
	writeEvidenceSummary(stderr, b, r, src, ids)
	return 0
}

func exportBundle(st *state.Store, from, now time.Time) (*evidence.Bundle, error) {
	recs, err := st.Records()
	if err != nil {
		return nil, err
	}
	keys, err := st.PublicKeys()
	if err != nil {
		return nil, err
	}
	b := &evidence.Bundle{Format: evidence.BundleFormat, Exported: now.UTC().Truncate(time.Second)}
	for id, pem := range keys {
		b.Keys = append(b.Keys, evidence.BundleKey{KeyID: id, PublicKey: string(pem)})
	}
	for _, r := range recs {
		raw, err := state.ReadRecord(r)
		if err != nil {
			return nil, err
		}
		if !from.IsZero() {
			h, err := header(raw)
			if err == nil && h.Record.Created.Before(from) {
				continue
			}
		}
		b.Records = append(b.Records, json.RawMessage(strings.TrimSpace(string(raw))))
	}
	if len(b.Records) == 0 {
		return nil, errors.New("no records in " + st.Dir())
	}
	return b, nil
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tycana evidence verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "trust only this public key (PEM file)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, evidenceUsage)
		return 2
	}
	var pinned []byte
	if *keyFile != "" {
		var err error
		if pinned, err = os.ReadFile(*keyFile); err != nil {
			fmt.Fprintf(stderr, "tycana evidence verify: %v\n", err)
			return 1
		}
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "tycana evidence verify: %v\n", err)
		return 1
	}
	defer func() { _ = f.Close() }()
	b, err := evidence.ReadBundle(f)
	if err != nil {
		fmt.Fprintf(stderr, "tycana evidence verify: %v\n", err)
		return 1
	}
	r, src, ids, err := b.Verify(pinned)
	if err != nil {
		fmt.Fprintf(stderr, "tycana evidence verify: %v\n", err)
		return 1
	}
	writeEvidenceSummary(stdout, b, r, src, ids)
	if !r.OK() {
		return 1
	}
	return 0
}

// header decodes a record's header without checking its signature.
func header(raw []byte) (evidence.Header, error) {
	var h evidence.Header
	_, pred, err := predicate(raw)
	if err == nil {
		err = json.Unmarshal(pred, &h)
	}
	return h, err
}

func predicate(raw []byte) (string, json.RawMessage, error) {
	var env evidence.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", nil, err
	}
	p, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return "", nil, err
	}
	var st evidence.Statement
	if err := json.Unmarshal(p, &st); err != nil {
		return "", nil, err
	}
	return st.PredicateType, st.Predicate, nil
}

// latest returns the newest host-inventory and host-assessment records
// of the bundle, decoded. Only records that verified are read.
type latestState struct {
	Header     evidence.Header
	Inventory  agent.HostInventory
	Assessment agent.HostAssessment
	HaveInv    bool
	HaveAssess bool
}

func latest(b *evidence.Bundle, r evidence.ChainReport) latestState {
	var ls latestState
	if r.Records == 0 {
		return ls
	}
	for i := len(b.Records) - 1; i >= 0 && (!ls.HaveInv || !ls.HaveAssess); i-- {
		typ, pred, err := predicate(b.Records[i])
		if err != nil {
			continue
		}
		switch typ {
		case evidence.PredicateType(evidence.TypeHostInventory):
			if !ls.HaveInv && json.Unmarshal(pred, &ls.Inventory) == nil {
				ls.HaveInv = true
				if !ls.HaveAssess {
					_ = json.Unmarshal(pred, &ls.Header)
				}
			}
		case evidence.PredicateType(evidence.TypeHostAssessment):
			if !ls.HaveAssess && json.Unmarshal(pred, &ls.Assessment) == nil {
				ls.HaveAssess = true
				if !ls.HaveInv {
					_ = json.Unmarshal(pred, &ls.Header)
				}
			}
		}
	}
	return ls
}

func writeEvidenceSummary(w io.Writer, b *evidence.Bundle, r evidence.ChainReport, src evidence.KeySource, ids []string) {
	ls := latest(b, r)
	h := ls.Header.Host
	if h.Hostname != "" {
		fmt.Fprintf(w, "Host: %s (%s %s), host id %s.\n", safe(h.Hostname), safe(h.OS), safe(h.OSVersion), safe(h.ID))
	}
	fmt.Fprintf(w, "Records: %d in the bundle, %d verify", len(b.Records), r.Records)
	if r.Records > 0 {
		fmt.Fprintf(w, ", sequence %d to %d, %s to %s UTC", r.First, r.Last,
			r.From.UTC().Format("2006-01-02 15:04"), r.To.UTC().Format("2006-01-02 15:04"))
	}
	fmt.Fprintln(w, ".")
	for _, id := range ids {
		switch src {
		case evidence.KeyPinned:
			fmt.Fprintf(w, "Key: %s, the key you gave.\n", id)
		default:
			fmt.Fprintf(w, "Key: %s, from the bundle, not checked against a known key.\n", id)
		}
	}
	switch {
	case r.OK():
		fmt.Fprintf(w, "Chain: complete. Every record from %d to %d is present, signed, and names the record before it.\n", r.First, r.Last)
	default:
		fmt.Fprintf(w, "Chain: NOT complete. %d problems:\n", len(r.Breaks)+len(r.Invalid))
		for _, x := range r.Invalid {
			fmt.Fprintf(w, "  - %s\n", x)
		}
		for _, x := range r.Breaks {
			fmt.Fprintf(w, "  - %s\n", x)
		}
	}
	if ls.HaveInv || ls.HaveAssess {
		fmt.Fprintf(w, "\nLatest state, signed %s UTC:\n", ls.Header.Record.Created.UTC().Format("2006-01-02 15:04"))
		writeState(w, ls)
	}
	fmt.Fprintln(w, "\nA valid signature shows that nobody without this host's key changed a record after the\n"+
		"agent signed it. It does not show that the host reported the truth: root on the host can\n"+
		"read the key.")
}

func writeState(w io.Writer, ls latestState) {
	if inv := ls.Inventory.Inventory; inv != nil {
		k := inv.Kernel
		fmt.Fprintf(w, "  Packages: %d installed (%s). Kernel: running %s", len(inv.Packages), inv.PackageDB.Format, k.Running.Release)
		if k.NewestInstalled != "" && k.NewestInstalled != k.Running.Release {
			fmt.Fprintf(w, ", newest installed %s", k.NewestInstalled)
		}
		fmt.Fprintln(w, ".")
	}
	if u := ls.Assessment.Updates; u != nil {
		n, sec := 0, 0
		for _, x := range u.Updates {
			if x.State == updates.Phased || x.State == updates.Held {
				continue
			}
			n++
			if x.Security {
				sec++
			}
		}
		fmt.Fprintf(w, "  Updates: %d to install now, %d of them security.\n", n, sec)
	}
	if rs := ls.Assessment.Restart; rs != nil {
		fmt.Fprintf(w, "  Restart: %s (%d services inferred, %d possible, %d unknown).\n", rs.Host.State, rs.Host.Inferred, rs.Host.Possible, rs.Host.Unknown)
	}
	if bl := ls.Assessment.Baseline; bl != nil {
		if bc := bl.Benchmark; bc != nil {
			fmt.Fprintf(w, "  Baseline: Tycana checks %d of the %d automated recommendations of the benchmark (%d percent).\n",
				bc.Checked, bc.Automated, bc.Checked*100/max(bc.Automated, 1))
		}
		s := bl.Score
		fmt.Fprintf(w, "  Score of the checked rules: %.1f%% (%d of %d evaluated checks pass), target %.0f%%.\n",
			s.Percent, s.Passed, s.Passed+s.Failed, s.Target)
	}
	for _, e := range ls.Header.Errors {
		fmt.Fprintf(w, "  Not collected: %s: %s\n", e.Source, safe(e.Error))
	}
	a := ls.Header.Agent
	fmt.Fprintf(w, "  Agent: version %s, self-check %s.\n", a.Version, a.SelfCheck)
}

func jsonEncode(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }
