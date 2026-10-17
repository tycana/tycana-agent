package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tycana.ai/agent/internal/agent"
	"tycana.ai/agent/internal/evidence"
	"tycana.ai/agent/internal/inventory"
	"tycana.ai/agent/internal/state"
)

func signedStore(t *testing.T, cycles int) string {
	t.Helper()
	dir := t.TempDir()
	st, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	a := &agent.Agent{
		Store: st, Config: agent.Config{RetentionDays: 30}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return now }, Root: t.TempDir() + "/", HaltPath: filepath.Join(dir, "halt"),
		Version: "test", Check: agent.SelfCheck{SHA256: "aa", Result: agent.CheckNone},
		Collect: func(context.Context, time.Time) (agent.HostInventory, agent.HostAssessment, []evidence.CollectError) {
			return agent.HostInventory{Inventory: &inventory.Snapshot{Schema: "t"}}, agent.HostAssessment{}, nil
		},
	}
	if err := a.Init(); err != nil {
		t.Fatal(err)
	}
	for range cycles {
		if err := a.Cycle(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Hour)
	}
	return dir
}

func TestEvidenceExportVerify(t *testing.T) {
	dir := signedStore(t, 3)
	var bundle, summary bytes.Buffer
	if code := run([]string{"evidence", "export", "--state-dir", dir}, &bundle, &summary); code != 0 {
		t.Fatalf("export: %d %s", code, summary.String())
	}
	if !strings.Contains(summary.String(), "Chain: complete") || !strings.Contains(summary.String(), "not checked against a known key") {
		t.Errorf("summary:\n%s", summary.String())
	}
	file := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(file, bundle.Bytes(), 0o600)
	var out, errb bytes.Buffer
	if code := run([]string{"evidence", "verify", file}, &out, &errb); code != 0 {
		t.Fatalf("verify: %d %s %s", code, out.String(), errb.String())
	}
	// The key the store holds, given by the verifier.
	pub := filepath.Join(dir, "key", "host.pub")
	out.Reset()
	if code := run([]string{"evidence", "verify", "--key", pub, file}, &out, &errb); code != 0 || !strings.Contains(out.String(), "the key you gave") {
		t.Fatalf("pinned: %d %s", code, out.String())
	}
	// Another key: nothing verifies.
	other := signedStore(t, 1)
	out.Reset()
	if code := run([]string{"evidence", "verify", "--key", filepath.Join(other, "key", "host.pub"), file}, &out, &errb); code != 1 || !strings.Contains(out.String(), "NOT complete") {
		t.Errorf("wrong key: %d %s", code, out.String())
	}
	// A record removed from the middle.
	b, err := evidence.ReadBundle(bytes.NewReader(bundle.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	b.Records = append(b.Records[:2], b.Records[3:]...)
	cut := filepath.Join(t.TempDir(), "cut.json")
	var w bytes.Buffer
	_ = jsonEncode(&w, b)
	_ = os.WriteFile(cut, w.Bytes(), 0o600)
	out.Reset()
	if code := run([]string{"evidence", "verify", cut}, &out, &errb); code != 1 || !strings.Contains(out.String(), "sequence 4 follows 2") {
		t.Errorf("gap: %d %s", code, out.String())
	}
	// One changed character in a signed record.
	bad := bytes.Replace(bundle.Bytes(), []byte(`"payload":"eyJf`), []byte(`"payload":"eyJg`), 1)
	_ = os.WriteFile(file, bad, 0o600)
	out.Reset()
	if code := run([]string{"evidence", "verify", file}, &out, &errb); code != 1 {
		t.Errorf("tampered: %d %s", code, out.String())
	}
}
