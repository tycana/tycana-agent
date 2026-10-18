package exposure

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"slices"

	"tycana.ai/agent/internal/inventory/dpkg"
	"tycana.ai/agent/internal/inventory/rpm"
	"tycana.ai/agent/internal/restart"
)

// SetuidFile is a file with the setuid bit that a package owns.
type SetuidFile struct {
	Path    string `json:"path"`
	Package string `json:"package"`
	// Mode is the permission bits on the host, in octal ("4755").
	Mode string `json:"mode"`
}

// owners is one pass over the package database: the owners of the wanted
// canonical paths, and every packaged file that has the setuid bit on
// the host.
type owners struct {
	of     map[string][]string
	setuid []SetuidFile
	files  int
}

// errNoDB means the host has neither a dpkg nor an rpm database.
var errNoDB = errors.New("no package database")

// readOwners walks the files of every installed package once. Package
// paths are made canonical through their directory (on a /usr-merged
// host dpkg still lists /lib/x86_64-linux-gnu/libc.so.6), so they match
// the closures, whose paths are canonical. Each packaged path is
// lstat'ed for the setuid bit: rpm records the mode the package gave,
// dpkg none, and the host's mode is the one that counts.
func readOwners(r *restart.Resolver, format, rpmDir string, want map[string]bool) (*owners, error) {
	o := &owners{of: map[string][]string{}}
	dirs := map[string]string{}
	add := func(pkg, p string) {
		o.files++
		dir, base := path.Split(p)
		cd, ok := dirs[dir]
		if !ok {
			c, err := r.Canonical(path.Clean(dir))
			if err != nil {
				c = ""
			}
			cd, dirs[dir] = c, c
		}
		if cd == "" {
			return
		}
		cp := path.Join(cd, base)
		if want[cp] && !slices.Contains(o.of[cp], pkg) {
			o.of[cp] = append(o.of[cp], pkg)
		}
		fi, err := os.Lstat(r.Host(cp))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode()&fs.ModeSetuid == 0 {
			return
		}
		if !slices.ContainsFunc(o.setuid, func(s SetuidFile) bool { return s.Path == cp && s.Package == pkg }) {
			o.setuid = append(o.setuid, SetuidFile{Path: cp, Package: pkg, Mode: octal(fi.Mode())})
		}
	}
	var err error
	switch format {
	case "deb":
		err = dpkg.WalkFiles(os.DirFS(r.Host("/")), dpkg.DefaultAdminDir, func(f dpkg.File) error {
			add(f.Package, f.Path)
			return nil
		})
	case "rpm":
		err = rpm.WalkFiles(r.Host("/"), rpmDir, func(f rpm.File) error {
			// Directories, links, and ghost entries cannot be setuid
			// programs or closure files; regular files only.
			if f.Mode&0o170000 == 0o100000 {
				add(f.Package, f.Path)
			}
			return nil
		})
	default:
		err = errNoDB
	}
	slices.SortFunc(o.setuid, func(a, b SetuidFile) int {
		if a.Path != b.Path {
			return compare(a.Path, b.Path)
		}
		return compare(a.Package, b.Package)
	})
	return o, err
}

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// octal is "4755" for a setuid program: the permission, setuid, setgid,
// and sticky bits.
func octal(m fs.FileMode) string {
	v := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		v |= 0o1000
	}
	const digits = "01234567"
	b := []byte{digits[v>>9&7], digits[v>>6&7], digits[v>>3&7], digits[v&7]}
	return string(b)
}
