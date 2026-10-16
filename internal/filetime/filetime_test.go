package filetime

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreated(t *testing.T) {
	before := time.Now().Add(-time.Second)
	name := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(name, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, src, err := Created(name)
	if err != nil {
		t.Fatal(err)
	}
	if src != Birth && src != Change {
		t.Errorf("source %q", src)
	}
	if got.Before(before) || got.After(time.Now().Add(time.Second)) {
		t.Errorf("created %v, test started %v", got, before)
	}
	if _, _, err := Created(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file: no error")
	}
}
