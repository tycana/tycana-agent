// Package inventory assembles a host inventory snapshot from the package
// database, os-release, and kernel state. Everything here reads; nothing
// writes or executes (ADR 0017).
package inventory

import (
	"errors"
	"fmt"
	"io/fs"
	"time"

	"tycana.ai/agent/internal/inventory/dpkg"
	"tycana.ai/agent/internal/inventory/kernel"
	"tycana.ai/agent/internal/inventory/osrelease"
)

// Schema names the snapshot format. Bump it on any incompatible change.
const Schema = "tycana.inventory/v0"

// Snapshot is one point-in-time inventory of a host.
type Snapshot struct {
	Schema      string         `json:"schema"`
	CollectedAt time.Time      `json:"collected_at"`
	OS          osrelease.Info `json:"os"`
	Kernel      kernel.Info    `json:"kernel"`
	PackageDB   PackageDB      `json:"package_db"`
	Packages    []Package      `json:"packages"`
}

// PackageDB describes where the package list came from.
type PackageDB struct {
	Format     string `json:"format"` // "deb"; "rpm" lands later in M1
	Path       string `json:"path"`
	NativeArch string `json:"native_arch,omitempty"`
	// JournalReplayed is the number of dpkg updates/ journal files applied
	// on top of the status file. Non-zero means dpkg was mid-run.
	JournalReplayed int `json:"journal_replayed"`
}

// Package is one installed (or partly installed) package, in a shape
// shared by deb and rpm. For deb, Version is the upstream version and
// Release the Debian revision; EVR is the full version as dpkg prints it.
type Package struct {
	Name          string `json:"name"`
	Arch          string `json:"arch"`
	EVR           string `json:"evr"`
	Epoch         uint32 `json:"epoch"`
	Version       string `json:"version"`
	Release       string `json:"release,omitempty"`
	SourceName    string `json:"source_name"`
	SourceEVR     string `json:"source_evr"`
	State         string `json:"state"`
	Want          string `json:"want,omitempty"`
	Flag          string `json:"flag,omitempty"`
	MultiArch     string `json:"multi_arch,omitempty"`
	Summary       string `json:"summary,omitempty"`
	InstalledSize string `json:"installed_size_kib,omitempty"`
}

// ErrNoPackageDB means no supported package database was found.
var ErrNoPackageDB = errors.New("no supported package database found")

// Collect builds a snapshot from the filesystem rooted at fsys, which in
// production is os.DirFS("/"). It also returns the raw dpkg database so
// callers can render native formats from the same read.
func Collect(fsys fs.FS, now time.Time) (*Snapshot, *dpkg.Database, error) {
	osInfo, err := osrelease.Read(fsys)
	if err != nil {
		return nil, nil, fmt.Errorf("os-release: %w", err)
	}
	if _, err := fs.Stat(fsys, dpkg.DefaultAdminDir+"/status"); err != nil {
		return nil, nil, fmt.Errorf("%w (looked for /%s/status)", ErrNoPackageDB, dpkg.DefaultAdminDir)
	}
	db, err := dpkg.ReadDatabase(fsys, dpkg.DefaultAdminDir)
	if err != nil {
		return nil, nil, fmt.Errorf("dpkg database: %w", err)
	}
	s := &Snapshot{
		Schema:      Schema,
		CollectedAt: now.UTC(),
		OS:          osInfo,
		PackageDB: PackageDB{
			Format:          "deb",
			Path:            "/" + dpkg.DefaultAdminDir,
			NativeArch:      db.NativeArch,
			JournalReplayed: db.UpdatesApplied,
		},
		Packages: make([]Package, 0, len(db.Packages)),
	}
	var cands []kernel.Candidate
	for _, p := range db.Packages {
		s.Packages = append(s.Packages, Package{
			Name:          p.Name,
			Arch:          p.Architecture,
			EVR:           evr(p.Version),
			Epoch:         p.Version.Epoch,
			Version:       p.Version.Upstream,
			Release:       p.Version.Revision,
			SourceName:    p.SourceName,
			SourceEVR:     evr(p.SourceVersion),
			State:         p.State,
			Want:          p.Want,
			Flag:          p.Flag,
			MultiArch:     p.MultiArch,
			Summary:       p.Summary,
			InstalledSize: p.InstalledSize,
		})
		if p.State == "installed" {
			cands = append(cands, kernel.Candidate{Name: p.Name, Version: evr(p.Version), Release: kernel.DebianRelease(p.Name)})
		}
	}
	s.Kernel, err = kernel.Collect(fsys, cands, compareDeb)
	if err != nil {
		return nil, nil, fmt.Errorf("kernel: %w", err)
	}
	return s, db, nil
}

func evr(v dpkg.Version) string {
	if v.Upstream == "" {
		return ""
	}
	return v.String()
}

// compareDeb orders two version strings that came out of a parsed dpkg
// database, so they always parse.
func compareDeb(a, b string) int {
	va, errA := dpkg.ParseVersion(a)
	vb, errB := dpkg.ParseVersion(b)
	if errA != nil || errB != nil {
		return 0
	}
	return dpkg.Compare(va, vb)
}
