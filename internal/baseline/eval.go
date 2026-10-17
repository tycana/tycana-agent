package baseline

import (
	"errors"
	"fmt"
	"io/fs"
	"time"
)

// Host is what the checks read. Production fills it from the live host
// (Collect); tests fill it from fixtures.
type Host struct {
	// Root is the host's root directory. Production uses "/".
	Root string
	// Stat returns a file's mode, owner, and type without following a
	// final symlink. Paths are absolute.
	Stat func(path string) (Meta, error)
	// ReadFile returns a file's content (at most 4 MiB).
	ReadFile func(path string) ([]byte, error)
	// ReadDir lists a directory.
	ReadDir func(path string) ([]fs.DirEntry, error)
	// PackageFormat is "deb" or "rpm".
	PackageFormat string
	// Packages maps each installed package name to its versions.
	Packages map[string][]string
	// Units holds systemd's properties for the units the checks name,
	// keyed by unit name. A unit systemd does not know has LoadState
	// "not-found".
	Units map[string]map[string]string
	// Wanted is every unit multi-user.target depends on, directly or
	// not (systemctl list-dependencies --all). Nil when not read.
	Wanted []string
	// Mounts is the mount table the agent sees (/proc/self/mountinfo).
	// Inside the tycanad unit it is the sandbox's table: systemd adds
	// options and mounts there (see mount.go).
	Mounts []Mount
	// Overflow is the kernel's overflow uid and gid. An owner that reads
	// as an overflow id is one the agent's user namespace cannot map.
	OverflowUID, OverflowGID uint32
	// Sandboxed is true when Mounts is a systemd sandbox's table, where
	// options can be added (set from the table itself).
	Sandboxed bool
	// UserNS is true when the agent runs in a user namespace that does
	// not map every id (a container, or a unit with PrivateUsers=yes;
	// tycanad has neither since ADR 0024). Only then is an overflow id
	// ambiguous.
	UserNS bool
	// Container is true inside a container (systemd-detect-virt's rule:
	// /run/systemd/container or /.dockerenv or /run/.containerenv).
	Container bool
}

// Meta is a file's mode, owner, and type.
type Meta struct {
	Mode     uint32
	UID, GID uint32
	// Type is "file", "dir", "symlink", or "other".
	Type string
}

// Mount is one line of a mountinfo table.
type Mount struct {
	// Root is the mount's root within its file system; systemd's
	// PrivateTmp bind mounts have a root under /tmp/systemd-private-*.
	Root   string
	Target string
	FSType string
	Source string
	// Options are the per-mount options and the super-block options.
	Options []string
}

// errUnknown marks a probe outcome the agent cannot decide.
type unknownError struct{ msg string }

func (e *unknownError) Error() string { return e.msg }

func unknownf(format string, a ...any) error {
	return &unknownError{msg: fmt.Sprintf(format, a...)}
}

// contentError marks a faulty check (Status Error).
type contentError struct{ msg string }

func (e *contentError) Error() string { return e.msg }

func contentf(format string, a ...any) error {
	return &contentError{msg: fmt.Sprintf(format, a...)}
}

// Evaluate runs every check of b against h. Exceptions, if any, are
// applied last; target is the policy's target percent (0 means
// DefaultTarget).
func Evaluate(b *Baseline, h *Host, exc []Exception, target float64, now time.Time) Report {
	if target == 0 {
		target = DefaultTarget
	}
	r := Report{
		Baseline: b.Name, Title: b.Title, Source: b.Source,
		Collected: now.UTC(), NotCovered: b.NotCovered,
	}
	for i := range b.Checks {
		r.Results = append(r.Results, evaluate(&b.Checks[i], h))
	}
	applyExceptions(r.Results, exc, now)
	r.Score = score(r.Results, len(b.NotCovered), target)
	return r
}

func evaluate(c *Check, h *Host) Result {
	res := Result{ID: c.ID, Title: c.Title, Severity: c.Severity, Refs: c.Refs}
	for _, w := range c.When {
		ok, why, err := w.holds(h)
		if err != nil {
			res.Status, res.Reason = classify(err)
			res.Reason = "applicability: " + res.Reason
			return res
		}
		if !ok {
			res.Status, res.Reason = NotApplicable, why
			return res
		}
	}
	var pass bool
	var why string
	var err error
	switch {
	case c.File != nil:
		pass, why, err = c.File.eval(h)
	case c.Sysctl != nil:
		pass, why, err = c.Sysctl.eval(h)
	case c.Package != nil:
		pass, why, err = c.Package.eval(h)
	case c.Service != nil:
		pass, why, err = c.Service.eval(h)
	case c.SSHD != nil:
		pass, why, err = c.SSHD.eval(h)
	case c.Mount != nil:
		pass, why, err = c.Mount.eval(h)
	case c.KernelModule != nil:
		pass, why, err = c.KernelModule.eval(h)
	}
	switch {
	case err != nil:
		res.Status, res.Reason = classify(err)
	case pass:
		res.Status, res.Reason = Pass, why
	default:
		res.Status, res.Reason = Fail, why
	}
	return res
}

// classify maps a probe error to Unknown or Error. A permission error
// from the file system is Unknown: the agent's user cannot read it.
func classify(err error) (Status, string) {
	var ce *contentError
	if errors.As(err, &ce) {
		return Error, ce.msg
	}
	var ue *unknownError
	if errors.As(err, &ue) {
		return Unknown, ue.msg
	}
	if errors.Is(err, fs.ErrPermission) {
		return Unknown, "not readable without privilege: " + err.Error()
	}
	return Unknown, err.Error()
}
