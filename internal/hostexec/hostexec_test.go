package hostexec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var sh = []string{"/bin/sh", "/usr/bin/sh"}

// TestRegistryIsReadOnly lists every command the agent can run. A change
// here is a change to what Tycana does on a host: review it against
// ADR 0017 (read-only verbs only).
func TestRegistryIsReadOnly(t *testing.T) {
	want := map[ID]string{
		AptSimulateUpgrade:     "/usr/bin/apt-get --simulate --quiet -o Debug::NoLocking=true -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= -o Dir::Bin::ischroot=/usr/bin/false upgrade",
		AptSimulateDistUpgrade: "/usr/bin/apt-get --simulate --quiet -o Debug::NoLocking=true -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= -o Dir::Bin::ischroot=/usr/bin/false dist-upgrade",
		AptCachePolicy:         "/usr/bin/apt-cache -o Debug::NoLocking=true -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= -o Dir::Bin::ischroot=/usr/bin/false policy [names]",
		DnfCheckUpdate:         "/usr/bin/dnf --cacheonly --quiet check-update",
		DnfUpdateinfo:          "/usr/bin/dnf --cacheonly --quiet updateinfo list --available",
	}
	if len(registry) != len(want) {
		t.Errorf("registry has %d commands, test lists %d", len(registry), len(want))
	}
	for id, spec := range registry {
		got := strings.Join(slices.Concat(spec.Paths[:1], spec.Args), " ")
		if spec.Extra != nil {
			got += " [names]"
		}
		if got != want[id] {
			t.Errorf("%s:\n got %s\nwant %s", id, got, want[id])
		}
	}
}

func TestEnvironmentIsFixed(t *testing.T) {
	t.Setenv("TYCANA_TEST_SECRET", "leak")
	res, err := run(context.Background(), Spec{Paths: []string{"/usr/bin/env"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(res.Stdout)), "\n")
	slices.Sort(got)
	want := slices.Sorted(slices.Values(Env))
	if !slices.Equal(got, want) {
		t.Errorf("child environment:\n got %q\nwant %q", got, want)
	}
}

func TestStdinIsClosed(t *testing.T) {
	res, err := run(context.Background(), Spec{Paths: []string{"/usr/bin/cat"}, Timeout: 5 * time.Second}, nil)
	if err != nil || len(res.Stdout) != 0 {
		t.Fatalf("cat with closed stdin: %v, %q", err, res.Stdout)
	}
}

func TestExitStatus(t *testing.T) {
	spec := Spec{Paths: sh, Args: []string{"-c", "echo out; echo err >&2; exit 100"}, OKExit: []int{100}}
	res, err := run(context.Background(), spec, nil)
	if err != nil || res.ExitCode != 100 || string(res.Stdout) != "out\n" || string(res.Stderr) != "err\n" {
		t.Fatalf("accepted status: %v %+v", err, res)
	}
	spec.Args = []string{"-c", "echo bad >&2; exit 3"}
	_, err = run(context.Background(), spec, nil)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 3 || ee.Stderr != "bad" {
		t.Fatalf("rejected status: %v", err)
	}
}

func TestTimeoutKillsTheGroup(t *testing.T) {
	// The background sleep holds stdout open; only a group kill (or the
	// wait delay) ends the run early.
	spec := Spec{Paths: sh, Args: []string{"-c", "sleep 30 & sleep 30"}, Timeout: 200 * time.Millisecond}
	start := time.Now()
	_, err := run(context.Background(), spec, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
	if d := time.Since(start); d > waitDelay {
		t.Errorf("took %v; the group was not killed", d)
	}
}

func TestOutputCap(t *testing.T) {
	spec := Spec{Paths: []string{"/usr/bin/yes"}, MaxStdout: 1024, Timeout: 10 * time.Second}
	res, err := run(context.Background(), spec, nil)
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("want ErrOutputTooLarge, got %v", err)
	}
	if len(res.Stdout) != 1024 {
		t.Errorf("kept %d bytes, want 1024", len(res.Stdout))
	}
}

func TestExtraArguments(t *testing.T) {
	if _, err := run(context.Background(), Spec{Paths: []string{"/usr/bin/true"}}, []string{"x"}); err == nil {
		t.Error("a Spec without a validator accepted an extra argument")
	}
	check := registry[AptCachePolicy].Extra
	for _, bad := range []string{"-o", "--option=x", "a b", "", "Foo", "a;b", "../x", "p:"} {
		if check([]string{"bash", bad}) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if err := check([]string{"libc6:amd64", "g++-13", "libstdc++6", "linux-image-6.8.0-142-generic"}); err != nil {
		t.Error(err)
	}
	if check(make([]string, maxNames+1)) == nil {
		t.Error("accepted more than maxNames names")
	}
}

func TestUntrustedProgramIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: the file is root-owned")
	}
	if _, err := run(context.Background(), Spec{Paths: []string{p}}, nil); err == nil || !strings.Contains(err.Error(), "not owned by root") {
		t.Fatalf("want refusal, got %v", err)
	}
}

func TestNotInstalled(t *testing.T) {
	_, err := run(context.Background(), Spec{Paths: []string{"/nonexistent/tycana-test"}}, nil)
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("want ErrNotInstalled, got %v", err)
	}
	if _, err := Run(context.Background(), "no-such-command"); err == nil {
		t.Error("Run accepted an unregistered ID")
	}
}
