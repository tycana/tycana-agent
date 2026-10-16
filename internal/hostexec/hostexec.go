package hostexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"time"
)

// Defaults for a Spec that leaves them zero.
const (
	DefaultTimeout   = 2 * time.Minute
	DefaultMaxStdout = 32 << 20
	maxStderr        = 1 << 20
	waitDelay        = 2 * time.Second
	nobodyID         = 65534
)

// Env is the complete environment of every command. Nothing is inherited.
var Env = []string{
	"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	"LC_ALL=C",
	"LANG=C",
	"HOME=/nonexistent",
}

// ErrOutputTooLarge reports that a command wrote more than its cap; it
// was killed and its output is incomplete.
var ErrOutputTooLarge = errors.New("hostexec: output exceeded the size cap")

// ErrNotInstalled reports that none of a Spec's paths exists on this host.
var ErrNotInstalled = errors.New("hostexec: command not installed")

// Spec describes one command the agent may run.
type Spec struct {
	// Paths are absolute candidates; the first that exists is used.
	Paths []string
	// Args are the fixed arguments after the program name.
	Args []string
	// Extra validates arguments the caller appends. Nil means the caller
	// may append none.
	Extra func([]string) error
	// OKExit lists exit statuses that are results, not failures. Empty
	// means only 0.
	OKExit []int
	// Timeout and MaxStdout default to DefaultTimeout and DefaultMaxStdout.
	Timeout   time.Duration
	MaxStdout int
}

// Result is the outcome of one command.
type Result struct {
	Path     string
	Args     []string
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// ExitError reports a command that ran and exited with a status its Spec
// does not accept. The Result is still returned for diagnosis.
type ExitError struct {
	Path   string
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("hostexec: %s exited %d: %s", e.Path, e.Code, e.Stderr)
}

// Run runs the registered command id with optional extra arguments.
func Run(ctx context.Context, id ID, extra ...string) (Result, error) {
	spec, ok := registry[id]
	if !ok {
		return Result{}, fmt.Errorf("hostexec: unknown command %q", id)
	}
	return run(ctx, spec, extra)
}

// Available reports whether the registered command id is installed and
// acceptable (root-owned, not writable by others).
func Available(id ID) bool {
	spec, ok := registry[id]
	if !ok {
		return false
	}
	_, err := resolve(spec.Paths)
	return err == nil
}

func run(ctx context.Context, spec Spec, extra []string) (Result, error) {
	if len(extra) > 0 {
		if spec.Extra == nil {
			return Result{}, errors.New("hostexec: command takes no extra arguments")
		}
		if err := spec.Extra(extra); err != nil {
			return Result{}, err
		}
	}
	path, err := resolve(spec.Paths)
	if err != nil {
		return Result{}, err
	}
	timeout := spec.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	maxOut := spec.MaxStdout
	if maxOut == 0 {
		maxOut = DefaultMaxStdout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := slices.Concat(spec.Args, extra)
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // path and leading args come from the fixed registry; extra args are validated
	cmd.Env = Env
	cmd.Dir = "/"
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if os.Geteuid() == 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: nobodyID, Gid: nobodyID, Groups: []uint32{}}
	}
	cmd.Cancel = func() error {
		// Kill the whole group: apt and dnf can start helpers.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = waitDelay
	stdout := &capped{limit: maxOut, over: cancel}
	stderr := &capped{limit: maxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	start := time.Now()
	runErr := cmd.Run()
	res := Result{Path: path, Args: args, Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(), Duration: time.Since(start)}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	switch {
	case stdout.exceeded:
		return res, ErrOutputTooLarge
	case ctx.Err() != nil:
		return res, fmt.Errorf("hostexec: %s: %w", path, ctx.Err())
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return res, fmt.Errorf("hostexec: %s: %w", path, runErr)
	}
	if res.ExitCode == 0 || slices.Contains(spec.OKExit, res.ExitCode) {
		return res, nil
	}
	return res, &ExitError{Path: path, Code: res.ExitCode, Stderr: string(bytes.TrimSpace(firstLine(res.Stderr)))}
}

// resolve returns the first candidate path that exists and is safe to run.
func resolve(paths []string) (string, error) {
	var refused error
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if err := trusted(p, fi); err != nil {
			refused = err
			continue
		}
		return p, nil
	}
	if refused != nil {
		return "", refused
	}
	return "", fmt.Errorf("%w: %v", ErrNotInstalled, paths)
}

// trusted refuses a program that someone other than root could have
// replaced.
func trusted(path string, fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("hostexec: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("hostexec: %s is writable by group or others", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return fmt.Errorf("hostexec: %s is not owned by root", path)
	}
	return nil
}

func firstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[:i]
	}
	return b
}

// capped keeps up to limit bytes. Past the limit it discards the rest,
// keeps draining the pipe so the child cannot block, and calls over once.
type capped struct {
	buf      bytes.Buffer
	limit    int
	exceeded bool
	over     func()
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.limit - c.buf.Len()
	if len(p) <= room {
		return c.buf.Write(p)
	}
	if room > 0 {
		c.buf.Write(p[:room])
	}
	if !c.exceeded {
		c.exceeded = true
		if c.over != nil {
			c.over()
		}
	}
	return len(p), nil
}
