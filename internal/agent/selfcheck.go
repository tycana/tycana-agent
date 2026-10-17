package agent

import (
	"bufio"
	"crypto/md5" //nolint:gosec // dpkg's md5sums files hold MD5 only
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"tycana.ai/agent/internal/inventory/rpm"
)

// Self-check results (ADR 0025, item 6).
const (
	CheckDpkg             = "package:dpkg"
	CheckRPM              = "package:rpm"
	CheckPrevious         = "previous-record"
	CheckPreviousMismatch = "previous-record-mismatch"
	CheckUnknown          = "unknown"
	CheckNone             = "none"
)

// ErrBinaryChanged is a binary that differs from what its package
// installed. tycanad exits with status 3 on it and does not restart.
var ErrBinaryChanged = errors.New("the agent binary differs from the one its package installed")

// SelfCheck is the outcome of the start-up check.
type SelfCheck struct {
	SHA256 string
	Result string
	// Detail says what was compared, or why nothing was.
	Detail string
}

// CheckBinary hashes exe and compares it with the package database under
// root. It returns ErrBinaryChanged only on a package-database mismatch.
// When no package owns exe, Result is CheckNone; the caller then compares
// with the last record.
func CheckBinary(root, exe string) (SelfCheck, error) {
	var sc SelfCheck
	sum, err := fileHash(exe, sha256.New())
	if err != nil {
		return sc, fmt.Errorf("self-check: %w", err)
	}
	sc.SHA256 = sum
	path, err := filepath.EvalSymlinks(exe)
	if err != nil {
		path = exe
	}
	// dpkg: the package whose .list names the path, then its md5sums.
	if pkg, err := dpkgOwner(root, path); err == nil && pkg != "" {
		want, err := dpkgMD5(root, pkg, path)
		if err != nil {
			// Recorded, not fatal (ADR 0025): the comparison cannot run.
			sc.Result, sc.Detail = CheckUnknown, err.Error()
			return sc, nil //nolint:nilerr // recorded in sc
		}
		got, err := fileHash(exe, md5.New()) //nolint:gosec // dpkg's digest
		if err != nil {
			return sc, fmt.Errorf("self-check: %w", err)
		}
		sc.Result, sc.Detail = CheckDpkg, "md5 from dpkg package "+pkg
		if got != want {
			return sc, fmt.Errorf("%w: %s has MD5 %s, dpkg package %s recorded %s", ErrBinaryChanged, path, got, pkg, want)
		}
		return sc, nil
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		sc.Result, sc.Detail = CheckUnknown, err.Error()
		return sc, nil
	}
	// rpm.
	if dir, err := rpmDir(root); err == nil {
		fd, err := rpm.LookupFile(root, dir, path)
		switch {
		case errors.Is(err, rpm.ErrNotOwned):
		case err != nil:
			sc.Result, sc.Detail = CheckUnknown, err.Error()
			return sc, nil //nolint:nilerr // recorded in sc
		default:
			h := map[string]func() hash.Hash{"sha256": sha256.New, "sha512": sha512.New, "sha384": sha512.New384, "md5": md5.New}[fd.Algorithm]
			if h == nil || fd.Digest == "" {
				sc.Result, sc.Detail = CheckUnknown, fmt.Sprintf("rpm package %s records digest %q (%s)", fd.Package, fd.Digest, fd.Algorithm)
				return sc, nil
			}
			got, err := fileHash(exe, h())
			if err != nil {
				return sc, fmt.Errorf("self-check: %w", err)
			}
			sc.Result, sc.Detail = CheckRPM, fd.Algorithm+" from rpm package "+fd.Package
			if got != fd.Digest {
				return sc, fmt.Errorf("%w: %s has %s %s, rpm package %s recorded %s", ErrBinaryChanged, path, fd.Algorithm, got, fd.Package, fd.Digest)
			}
			return sc, nil
		}
	}
	sc.Result, sc.Detail = CheckNone, "no package owns "+path
	return sc, nil
}

// ComparePrevious applies the last record's binary hash when no package
// owns the binary. A mismatch is recorded, never fatal: the record is
// writable by the agent's own user.
func (sc *SelfCheck) ComparePrevious(prev PreviousAgent, version, commit string) {
	if sc.Result != CheckNone || prev.Version == "" || version == "dev" || prev.Version != version || prev.Commit != commit {
		return
	}
	if prev.BinarySHA256 == sc.SHA256 {
		sc.Result, sc.Detail = CheckPrevious, "same binary as the last record of this version"
		return
	}
	sc.Result = CheckPreviousMismatch
	sc.Detail = fmt.Sprintf("the last record of version %s has binary %s, this one is %s", version, prev.BinarySHA256, sc.SHA256)
}

// PreviousAgent is the part of a previous record's agent field the
// self-check reads.
type PreviousAgent struct {
	Version, Commit, BinarySHA256 string
}

func fileHash(path string, h hash.Hash) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the agent's own binary
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func dpkgOwner(root, path string) (string, error) {
	info := filepath.Join(root, "var/lib/dpkg/info")
	lists, err := filepath.Glob(filepath.Join(info, "*.list"))
	if err != nil {
		return "", err
	}
	if len(lists) == 0 {
		return "", fs.ErrNotExist
	}
	for _, l := range lists {
		found, err := fileHasLine(l, path)
		if err != nil {
			return "", err
		}
		if found {
			return strings.TrimSuffix(filepath.Base(l), ".list"), nil
		}
	}
	return "", nil
}

func fileHasLine(file, line string) (bool, error) {
	f, err := os.Open(file) //nolint:gosec // dpkg's info files
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		if sc.Text() == line {
			return true, nil
		}
	}
	return false, sc.Err()
}

func dpkgMD5(root, pkg, path string) (string, error) {
	f, err := os.Open(filepath.Join(root, "var/lib/dpkg/info", pkg+".md5sums")) //nolint:gosec // dpkg's info files
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	rel := strings.TrimPrefix(path, "/")
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if ok && name == rel {
			return sum, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("dpkg package %s has no MD5 for %s", pkg, path)
}

func rpmDir(root string) (string, error) {
	return rpm.Locate(os.DirFS(root))
}
