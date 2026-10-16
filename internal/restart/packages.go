package restart

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// PackageChange is when a package last changed on this host.
type PackageChange struct {
	Name    string    `json:"name"`
	Changed time.Time `json:"changed"`
	// Coarse is true when Changed has whole seconds only (rpm's install
	// time). A unit that started within that second may have started
	// before the change, so it counts as started before it.
	Coarse bool `json:"coarse,omitempty"`
}

// after reports whether the package changed after a unit started at t.
func (c PackageChange) after(t time.Time) bool {
	if c.Coarse {
		return t.Before(c.Changed.Add(time.Second))
	}
	return c.Changed.After(t)
}

// DpkgChanges reads when each dpkg package last changed: the mtime of its
// /var/lib/dpkg/info/<package>.list, which dpkg rewrites when it unpacks
// the package. On tycana-ubuntu2404 (2026-10-16) it was 17 to 20 ms after
// the package's files were created, and matched dpkg.log to the second,
// with nanoseconds and no time-zone conversion. Unlike dpkg.log it does
// not rotate away.
func DpkgChanges(root string) ([]PackageChange, error) {
	dir := filepath.Join(root, "var", "lib", "dpkg", "info")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []PackageChange
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".list")
		if !ok || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, PackageChange{Name: name, Changed: fi.ModTime().UTC()})
	}
	slices.SortFunc(out, func(a, b PackageChange) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
