package baseline

import (
	"path/filepath"
	"syscall"
	"testing"
)

// Fable review, 2026-10-16: a FIFO named by a baseline must not block the
// run.
func TestLiveReadRefusesNonRegular(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(p, 0o600); err != nil {
		t.Skip(err)
	}
	if _, err := liveRead(p); err == nil {
		t.Fatal("read a FIFO")
	}
	if _, err := liveRead("/proc/sys/kernel/ostype"); err != nil {
		t.Errorf("/proc/sys: %v", err)
	}
}
