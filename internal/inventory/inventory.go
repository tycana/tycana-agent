// Package inventory assembles a host inventory snapshot from the package
// database, os-release, and kernel state. Everything here reads; nothing
// writes or executes (ADR 0017).
package inventory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"time"

	"tycana.ai/agent/debversion"
	"tycana.ai/agent/internal/inventory/dpkg"
	"tycana.ai/agent/internal/inventory/kernel"
	"tycana.ai/agent/internal/inventory/osrelease"
	"tycana.ai/agent/internal/inventory/rpm"
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
	Format     string `json:"format"` // "deb" or "rpm"
	Path       string `json:"path"`
	NativeArch string `json:"native_arch,omitempty"`
	// JournalReplayed is the number of dpkg updates/ journal files applied
	// on top of the status file. Non-zero means dpkg was mid-run.
	JournalReplayed int `json:"journal_replayed,omitempty"`
	// Retries counts rpm database reads repeated because the database
	// changed underneath them. Non-zero means rpm or dnf was running.
	Retries int `json:"retries,omitempty"`
	// Notes are facts about the read worth showing an operator, such as
	// a second package database on the host. They are not errors.
	Notes []string `json:"notes,omitempty"`
}

// Package is one installed (or partly installed) package, in a shape
// shared by deb and rpm. For deb, Version is the upstream version and
// Release the Debian revision; EVR is the full version as dpkg prints it.
// For rpm, EVR is as rpm's %{EVR} prints it.
type Package struct {
	Name       string `json:"name"`
	Arch       string `json:"arch"` // "" for rpm's gpg-pubkey entries
	EVR        string `json:"evr"`
	Epoch      uint32 `json:"epoch"`
	Version    string `json:"version"`
	Release    string `json:"release,omitempty"`
	SourceName string `json:"source_name"`
	// SourceEVR is the source package's version. For deb it includes the
	// epoch; for rpm it is version-release only, because the header does
	// not record the source package's epoch.
	SourceEVR string `json:"source_evr"`
	State     string `json:"state"`
	Want      string `json:"want,omitempty"`
	Flag      string `json:"flag,omitempty"`
	MultiArch string `json:"multi_arch,omitempty"`
	Summary   string `json:"summary,omitempty"`
	// InstalledSizeBytes is the size the package manager recorded: dpkg's
	// Installed-Size in KiB times 1024, rpm's SIZE tag.
	InstalledSizeBytes int64 `json:"installed_size_bytes,omitempty"`
	// InstalledAt is when rpm installed the package. dpkg does not record
	// it in the database; the history command has it from dpkg.log.
	InstalledAt time.Time `json:"installed_at,omitzero"`
	// PackageID is rpm's pkgid (the header+payload MD5). Empty for deb.
	PackageID string `json:"package_id,omitempty"`
	// Vendor and License are rpm header tags, empty for deb.
	Vendor  string `json:"vendor,omitempty"`
	License string `json:"license,omitempty"`
	// ModularityLabel marks an rpm installed from a module stream.
	ModularityLabel string `json:"modularity_label,omitempty"`
}

// ErrNoPackageDB means no supported package database was found.
var ErrNoPackageDB = errors.New("no supported package database found")

// Native holds the raw database behind a snapshot, so callers can render
// the native tool's output from the same read. Exactly one field is set.
type Native struct {
	Dpkg *dpkg.Database
	RPM  *rpm.Database
}

// Collect builds a snapshot of the host rooted at root, which in
// production is "/". The root is a path rather than an fs.FS because
// rpm's database is SQLite, which opens files by path.
func Collect(root string, now time.Time) (*Snapshot, *Native, error) {
	fsys := os.DirFS(root)
	osInfo, err := osrelease.Read(fsys)
	if err != nil {
		return nil, nil, fmt.Errorf("os-release: %w", err)
	}
	s := &Snapshot{Schema: Schema, CollectedAt: now.UTC(), OS: osInfo}

	_, dpkgErr := fs.Stat(fsys, dpkg.DefaultAdminDir+"/status")
	rpmDir, rpmErr := rpm.Locate(fsys)
	hasDpkg, hasRPM := dpkgErr == nil, rpmErr == nil
	var native Native
	switch {
	case hasDpkg && hasRPM:
		// Both databases exist: rpm installed on Debian, or dpkg on
		// Fedora. The distribution family decides which one is the
		// host's; the other is noted.
		if debianFamily(osInfo) {
			s.PackageDB.Notes = append(s.PackageDB.Notes, "an rpm database also exists at /"+rpmDir+"; it is not the host's package manager")
		} else {
			s.PackageDB.Notes = append(s.PackageDB.Notes, "a dpkg database also exists at /"+dpkg.DefaultAdminDir+"; it is not the host's package manager")
			hasDpkg = false
		}
	case !hasDpkg && !hasRPM:
		if errors.Is(rpmErr, rpm.ErrUnsupportedBackend) {
			return nil, nil, fmt.Errorf("%w: %w", ErrNoPackageDB, rpmErr)
		}
		return nil, nil, fmt.Errorf("%w (looked for /%s/status and %s under /%v)", ErrNoPackageDB, dpkg.DefaultAdminDir, rpm.DBFile, rpm.SearchPath)
	}

	var cands []kernel.Candidate
	var cmp func(a, b string) int
	if hasDpkg {
		native.Dpkg, err = dpkg.ReadDatabase(fsys, dpkg.DefaultAdminDir)
		if err != nil {
			return nil, nil, fmt.Errorf("dpkg database: %w", err)
		}
		cands = fromDpkg(s, native.Dpkg)
		cmp = compareDeb
	} else {
		native.RPM, err = rpm.ReadDatabase(root, rpmDir)
		if err != nil {
			return nil, nil, fmt.Errorf("rpm database: %w", err)
		}
		cands = fromRPM(s, native.RPM)
		cmp = compareRPM
	}
	s.Kernel, err = kernel.Collect(fsys, cands, cmp)
	if err != nil {
		return nil, nil, fmt.Errorf("kernel: %w", err)
	}
	return s, &native, nil
}

func debianFamily(o osrelease.Info) bool {
	for _, id := range append([]string{o.ID}, o.IDLike...) {
		if id == "debian" || id == "ubuntu" {
			return true
		}
	}
	return false
}

func fromDpkg(s *Snapshot, db *dpkg.Database) []kernel.Candidate {
	s.PackageDB.Format = "deb"
	s.PackageDB.Path = "/" + dpkg.DefaultAdminDir
	s.PackageDB.NativeArch = db.NativeArch
	s.PackageDB.JournalReplayed = db.UpdatesApplied
	s.Packages = make([]Package, 0, len(db.Packages))
	var cands []kernel.Candidate
	for _, p := range db.Packages {
		kib, _ := strconv.ParseInt(p.InstalledSize, 10, 64)
		s.Packages = append(s.Packages, Package{
			Name:               p.Name,
			Arch:               p.Architecture,
			EVR:                evr(p.Version),
			Epoch:              p.Version.Epoch,
			Version:            p.Version.Upstream,
			Release:            p.Version.Revision,
			SourceName:         p.SourceName,
			SourceEVR:          evr(p.SourceVersion),
			State:              p.State,
			Want:               p.Want,
			Flag:               p.Flag,
			MultiArch:          p.MultiArch,
			Summary:            p.Summary,
			InstalledSizeBytes: kib * 1024,
		})
		if p.State == "installed" {
			cands = append(cands, kernel.Candidate{Name: p.Name, Version: evr(p.Version), Release: kernel.DebianRelease(p.Name)})
		}
	}
	return cands
}

func fromRPM(s *Snapshot, db *rpm.Database) []kernel.Candidate {
	s.PackageDB.Format = "rpm"
	s.PackageDB.Path = "/" + db.Dir
	s.PackageDB.Retries = db.Retries
	s.Packages = make([]Package, 0, len(db.Packages))
	var cands, fallbacks []kernel.Candidate
	for _, p := range db.Packages {
		srcName, srcVR, _ := rpm.SourceRPM(p.SourceRPM)
		s.Packages = append(s.Packages, Package{
			Name:               p.Name,
			Arch:               p.Arch,
			EVR:                p.EVR.String(),
			Epoch:              p.EVR.Epoch,
			Version:            p.EVR.Version,
			Release:            p.EVR.Release,
			SourceName:         srcName,
			SourceEVR:          srcVR,
			State:              "installed",
			Summary:            p.Summary,
			InstalledSizeBytes: int64(min(p.Size, 1<<62)),
			InstalledAt:        p.InstallTime,
			PackageID:          p.SigMD5,
			Vendor:             p.Vendor,
			License:            p.License,
			ModularityLabel:    p.ModularityLabel,
		})
		if s.PackageDB.NativeArch == "" && p.Name == "rpm" {
			s.PackageDB.NativeArch = p.Arch
		}
		rel, fallback := kernel.RPMRelease(p.Name, p.EVR.Version, p.EVR.Release, p.Arch)
		if rel == "" {
			continue
		}
		c := kernel.Candidate{Name: p.Name, Version: p.EVR.String(), Release: rel}
		if fallback {
			fallbacks = append(fallbacks, c)
		} else {
			cands = append(cands, c)
		}
	}
	// "kernel" and "kernel-uek" carry the image only where no -core
	// package does.
	for _, f := range fallbacks {
		dup := false
		for _, c := range cands {
			if c.Release == f.Release {
				dup = true
				break
			}
		}
		if !dup {
			cands = append(cands, f)
		}
	}
	return cands
}

func evr(v debversion.Version) string {
	if v.Upstream == "" {
		return ""
	}
	return v.String()
}

// compareDeb orders two version strings that came out of a parsed dpkg
// database, so they always parse.
func compareDeb(a, b string) int {
	va, errA := debversion.ParseVersion(a)
	vb, errB := debversion.ParseVersion(b)
	if errA != nil || errB != nil {
		return 0
	}
	return debversion.Compare(va, vb)
}

func compareRPM(a, b string) int {
	return rpm.Compare(rpm.ParseEVR(a), rpm.ParseEVR(b))
}
