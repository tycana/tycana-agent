package rpm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"time"

	"tycana.ai/agent/internal/sqlitero"
)

// DBFile is the name of rpm's SQLite database inside the database
// directory.
const DBFile = "rpmdb.sqlite"

// SearchPath lists database directories in the order they are probed,
// relative to the filesystem root. rpm 4.17 moved the default from
// /var/lib/rpm to /usr/lib/sysimage/rpm; distributions that moved keep a
// symlink at the old place, so the new place is probed first.
var SearchPath = []string{"usr/lib/sysimage/rpm", "var/lib/rpm", "usr/share/rpm"}

// ErrNotFound means no rpm database directory held rpmdb.sqlite.
var ErrNotFound = errors.New("no rpm database found")

// ErrUnsupportedBackend means a database directory holds a BerkeleyDB
// (Packages) or NDB (Packages.db) database, which rpm 4.16+ no longer
// writes by default and the agent does not read.
var ErrUnsupportedBackend = errors.New("rpm database uses a backend the agent does not read")

// Package is one header of the rpm database. Strings are as stored; a
// missing tag is "" (or zero) and rpm prints it as "(none)".
type Package struct {
	// Instance is the header number, rpm's %{DBINSTANCE}. Packages are
	// returned in this order, which is the order rpm -qa prints.
	Instance int64
	Name     string
	EVR      EVR
	Arch     string // "" for gpg-pubkey entries
	// SourceRPM is the %{SOURCERPM} tag, "" for gpg-pubkey entries.
	SourceRPM string
	Summary   string // the C-locale summary
	// Size is %{SIZE} (or %{LONGSIZE} when the package is over 4 GiB).
	Size uint64
	// HasSize is false when neither size tag is present.
	HasSize bool
	// InstallTime is when rpm installed the header; zero when absent.
	InstallTime time.Time
	// BuildTime is when the package was built; zero when absent.
	BuildTime time.Time
	// InstallTID identifies the rpm transaction that installed it.
	InstallTID uint64
	// SigMD5 is the header+payload MD5 rpm calls the pkgid, lower-case
	// hex, "" when absent.
	SigMD5          string
	Vendor          string
	License         string
	ModularityLabel string
}

// Database is the read package database.
type Database struct {
	// Dir is the database directory, relative to the root it was found
	// under, for example "var/lib/rpm".
	Dir string
	// Packages in header-number order.
	Packages []Package
	// Immutable reports that the database was read without locking
	// (its write-ahead log was empty), see package sqlitero.
	Immutable bool
	// Retries counts reads that were repeated because the database
	// changed underneath them.
	Retries int
}

// Locate finds the database directory under fsys. It returns
// ErrNotFound when none of SearchPath holds rpmdb.sqlite, and
// ErrUnsupportedBackend when a directory holds an older backend instead.
func Locate(fsys fs.FS) (string, error) {
	var old string
	for _, dir := range SearchPath {
		if _, err := fs.Stat(fsys, path.Join(dir, DBFile)); err == nil {
			return dir, nil
		}
		for _, f := range []string{"Packages", "Packages.db"} {
			if old == "" {
				if _, err := fs.Stat(fsys, path.Join(dir, f)); err == nil {
					old = path.Join(dir, f)
				}
			}
		}
	}
	if old != "" {
		return "", fmt.Errorf("%w: /%s", ErrUnsupportedBackend, old)
	}
	return "", fmt.Errorf("%w (looked for %s under /%v)", ErrNotFound, DBFile, SearchPath)
}

// maxRetries bounds how often a read is repeated when the database
// changes during it, which happens when rpm or dnf is writing.
const maxRetries = 3

// ReadDatabase reads the database in dir under root. root is a directory
// on the local filesystem ("/" in production) because SQLite opens files
// by path.
func ReadDatabase(root, dir string) (*Database, error) {
	db := &Database{Dir: dir}
	for {
		pkgs, immutable, err := readOnce(filepath.Join(root, filepath.FromSlash(dir), DBFile))
		if err == nil {
			db.Packages, db.Immutable = pkgs, immutable
			return db, nil
		}
		if !errors.Is(err, errChanged) || db.Retries >= maxRetries {
			return nil, err
		}
		db.Retries++
	}
}

var errChanged = errors.New("rpm database changed while it was being read")

func readOnce(file string) ([]Package, bool, error) {
	d, err := sqlitero.Open(file)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = d.Close() }() // read-only
	rows, err := d.QueryContext(context.Background(), "SELECT hnum, blob FROM Packages ORDER BY hnum")
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", file, err)
	}
	defer func() { _ = rows.Close() }()
	var pkgs []Package
	for rows.Next() {
		var hnum int64
		var blob []byte
		if err := rows.Scan(&hnum, &blob); err != nil {
			return nil, false, fmt.Errorf("%s: %w", file, err)
		}
		h, err := parseHeader(blob)
		if err != nil {
			return nil, false, fmt.Errorf("%s: header %d: %w", file, hnum, err)
		}
		pkgs = append(pkgs, fromHeader(hnum, h))
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("%s: %w", file, err)
	}
	if d.Changed() {
		return nil, false, errChanged
	}
	return pkgs, d.Immutable, nil
}

func fromHeader(hnum int64, h header) Package {
	p := Package{Instance: hnum}
	p.Name, _ = h.str(tagName)
	p.EVR.Version, _ = h.str(tagVersion)
	p.EVR.Release, _ = h.str(tagRelease)
	if e, ok := h.num(tagEpoch); ok {
		p.EVR.Epoch, p.EVR.HasEpoch = uint32(e), true //nolint:gosec // rpm stores the epoch as int32
	}
	p.Arch, _ = h.str(tagArch)
	p.SourceRPM, _ = h.str(tagSourceRPM)
	p.Summary = h.i18n(tagSummary, "C")
	if n, ok := h.num(tagLongSize); ok {
		p.Size, p.HasSize = n, true
	} else if n, ok := h.num(tagSize); ok {
		p.Size, p.HasSize = n, true
	}
	if n, ok := h.num(tagInstallTime); ok {
		p.InstallTime = time.Unix(int64(n), 0).UTC() //nolint:gosec // 32-bit seconds
	}
	if n, ok := h.num(tagBuildTime); ok {
		p.BuildTime = time.Unix(int64(n), 0).UTC() //nolint:gosec // 32-bit seconds
	}
	p.InstallTID, _ = h.num(tagInstallTID)
	if b, ok := h.bin(tagSigMD5); ok {
		p.SigMD5 = hex.EncodeToString(b)
	}
	p.Vendor, _ = h.str(tagVendor)
	p.License, _ = h.str(tagLicense)
	p.ModularityLabel, _ = h.str(tagModularityLabel)
	return p
}
