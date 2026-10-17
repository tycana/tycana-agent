package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tycana.ai/agent/evidence"
	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/state"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newAgent(t *testing.T, dir string, c *clock) *Agent {
	t.Helper()
	root := t.TempDir() + "/"
	if err := os.MkdirAll(root+"etc", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"etc/machine-id", []byte("000102030405060708090a0b0c0d0e0f\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{
		Store: st, Config: Config{Interval: Duration(time.Hour), RetentionDays: 1},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: c.now, Root: root,
		HaltPath: filepath.Join(root, "halt"), Version: "1.0.0", Commit: "abc",
		Check: SelfCheck{SHA256: "aa", Result: CheckNone},
		Collect: func(context.Context, time.Time) (HostInventory, HostAssessment, []evidence.CollectError) {
			return HostInventory{Inventory: &inventory.Snapshot{Schema: "test"}}, HostAssessment{},
				[]evidence.CollectError{{Source: "updates", Error: "apt failed"}}
		},
	}
	if err := a.Init(); err != nil {
		t.Fatal(err)
	}
	return a
}

func verify(t *testing.T, dir string) evidence.ChainReport {
	t.Helper()
	st := state.Reader(dir)
	recs, err := st.Records()
	if err != nil {
		t.Fatal(err)
	}
	pem, err := st.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, der, err := evidence.ParsePublic(pem)
	if err != nil {
		t.Fatal(err)
	}
	var raws [][]byte
	for _, r := range recs {
		b, err := state.ReadRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, b)
	}
	id := evidence.KeyID(der)
	return evidence.VerifyChain(raws, map[string]*ecdsa.PublicKey{id: pub}, map[string][]byte{id: der})
}

func TestCyclesMakeOneChain(t *testing.T) {
	dir := t.TempDir()
	c := &clock{time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	a := newAgent(t, dir, c)
	for range 3 {
		if err := a.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
		c.t = c.t.Add(time.Hour)
	}
	r := verify(t, dir)
	if !r.OK() || r.Records != 6 || r.Last != 6 {
		t.Fatalf("%+v", r)
	}
	// A new process continues the chain and the cycle count.
	b := newAgent(t, dir, c)
	if err := b.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := verify(t, dir); !r.OK() || r.Records != 8 {
		t.Fatalf("after restart: %+v", r)
	}
	recs, _ := state.Reader(dir).Records()
	raw, _ := state.ReadRecord(recs[7])
	var env evidence.Envelope
	_ = json.Unmarshal(raw, &env)
	if !strings.Contains(mustPayload(t, env), `"cycle":4`) || !strings.Contains(mustPayload(t, env), `"apt failed"`) {
		t.Errorf("record 8: %s", mustPayload(t, env))
	}
}

func mustPayload(t *testing.T, env evidence.Envelope) string {
	t.Helper()
	b, err := decodeB64(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHalt(t *testing.T) {
	dir := t.TempDir()
	a := newAgent(t, dir, &clock{time.Now()})
	// A dangling symbolic link counts.
	if err := os.Symlink("/nonexistent", a.HaltPath); err != nil {
		t.Fatal(err)
	}
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if recs, _ := a.Store.Records(); len(recs) != 0 {
		t.Fatalf("halted agent wrote %d records", len(recs))
	}
	// The halt file appears during collection: nothing is signed.
	_ = os.Remove(a.HaltPath)
	collect := a.Collect
	a.Collect = func(ctx context.Context, now time.Time) (HostInventory, HostAssessment, []evidence.CollectError) {
		_ = os.WriteFile(a.HaltPath, nil, 0o600)
		return collect(ctx, now)
	}
	if err := a.Cycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if recs, _ := a.Store.Records(); len(recs) != 0 {
		t.Fatalf("agent signed after the halt file appeared: %d records", len(recs))
	}
	// The halt ends: the first cycle's two records name it, the next do not.
	a.Collect = collect
	_ = os.Remove(a.HaltPath)
	m, err := a.Store.HaltMarker()
	if err != nil || m == nil || m.To.Before(m.From) {
		t.Fatalf("marker %+v %v", m, err)
	}
	for range 2 {
		if err := a.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	recs, _ := a.Store.Records()
	for i, r := range recs {
		raw, _ := state.ReadRecord(r)
		var env evidence.Envelope
		_ = json.Unmarshal(raw, &env)
		if has := strings.Contains(mustPayload(t, env), `"halted":{"from"`); has != (i < 2) {
			t.Errorf("record %d: halted %v", r.Sequence, has)
		}
	}
	if m, _ := a.Store.HaltMarker(); m != nil {
		t.Errorf("marker not cleared: %+v", m)
	}
}

func TestKeyIsKeptAndReplacedOnlyWhenBroken(t *testing.T) {
	dir := t.TempDir()
	c := &clock{time.Now()}
	a := newAgent(t, dir, c)
	_ = a.Cycle(context.Background())
	first := a.key.ID
	// A forged last record: the key stays, and the next record says so.
	recs, _ := a.Store.Records()
	last := recs[len(recs)-1]
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"keyid":"` + first + `","sig":"AA=="}]}`))
	_ = zw.Close()
	if err := os.WriteFile(last.Path, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	b := newAgent(t, dir, c)
	if b.key.ID != first {
		t.Fatal("a forged record replaced the key")
	}
	_ = b.Cycle(context.Background())
	recs, _ = b.Store.Records()
	raw, _ := state.ReadRecord(recs[len(recs)-1])
	var env evidence.Envelope
	_ = json.Unmarshal(raw, &env)
	if p := mustPayload(t, env); !strings.Contains(p, `"source":"store"`) || !strings.Contains(p, "record 2 does not verify") {
		t.Errorf("no store error: %s", p)
	}
	// A key file that does not parse is replaced; the chain names the old key.
	if err := os.WriteFile(filepath.Join(dir, "key", "host.key"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := newAgent(t, dir, c)
	if d.key.ID == first || d.prevKeyID != first {
		t.Fatalf("new key %s, previous %s", d.key.ID, d.prevKeyID)
	}
	// An unreadable key file stops the agent.
	if os.Getuid() != 0 {
		_ = os.Chmod(filepath.Join(dir, "key", "host.key"), 0)
		st, _ := state.Open(dir)
		e := &Agent{Store: st, Log: d.Log, Now: c.now}
		if err := e.Init(); err == nil || !errors.Is(err, os.ErrPermission) {
			t.Errorf("unreadable key: %v", err)
		}
	}
}

func TestPruneKeepsNewestRecords(t *testing.T) {
	dir := t.TempDir()
	c := &clock{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	a := newAgent(t, dir, c)
	for range MinRecords {
		_ = a.Cycle(context.Background())
		c.t = c.t.Add(time.Hour)
	}
	// All records are older than the retention now, but the newest 50
	// stay.
	c.t = c.t.AddDate(0, 1, 0)
	_ = a.Cycle(context.Background())
	recs, _ := a.Store.Records()
	if len(recs) != MinRecords || recs[len(recs)-1].Sequence != 2*MinRecords+2 {
		t.Fatalf("%d records, last %d", len(recs), recs[len(recs)-1].Sequence)
	}
	if r := verify(t, dir); len(r.Breaks) != 0 || len(r.Invalid) != 0 || r.First != MinRecords+3 {
		t.Errorf("%+v", r)
	}
}

func TestSelfCheckPrevious(t *testing.T) {
	sc := SelfCheck{SHA256: "aa", Result: CheckNone}
	sc.ComparePrevious(PreviousAgent{Version: "1.0.0", Commit: "c", BinarySHA256: "bb"}, "1.0.0", "c")
	if sc.Result != CheckPreviousMismatch {
		t.Errorf("mismatch: %+v", sc)
	}
	sc = SelfCheck{SHA256: "aa", Result: CheckNone}
	sc.ComparePrevious(PreviousAgent{Version: "1.0.0", Commit: "c", BinarySHA256: "aa"}, "1.0.0", "c")
	if sc.Result != CheckPrevious {
		t.Errorf("match: %+v", sc)
	}
	sc = SelfCheck{SHA256: "aa", Result: CheckNone}
	sc.ComparePrevious(PreviousAgent{Version: "0.9.0", BinarySHA256: "bb"}, "1.0.0", "c")
	if sc.Result != CheckNone {
		t.Errorf("new version: %+v", sc)
	}
}

func TestConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	c, err := LoadConfig(p)
	if err != nil || time.Duration(c.Interval) != DefaultInterval || c.RetentionDays != DefaultRetentionDays {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for body, ok := range map[string]bool{
		"interval: 2h\nretention_days: 90\n": true,
		"interval: 1m\n":                     false,
		"retention_days: -1\n":               false,
		"apply: yes\n":                       false,
		"":                                   true,
	} {
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := LoadConfig(p); (err == nil) != ok {
			t.Errorf("%q: %v", body, err)
		}
	}
}
