package sockdiag

import (
	"errors"
	"io/fs"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxCgroups bounds the walk of the cgroup tree.
const maxCgroups = 100000

// CgroupPaths maps the id of each cgroup v2 directory under mount (its
// inode number, which INET_DIAG_CGROUP_ID carries) to its path from the
// root, "/system.slice/ssh.service". It reads directory entries only;
// under ProtectControlGroups=yes the tree is read-only and still
// readable.
func CgroupPaths(mount string) (map[uint64]string, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(mount, &st); err != nil {
		return nil, err
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New(mount + " is not a cgroup v2 file system (cgroup v1 is not supported)")
	}
	out := map[uint64]string{}
	err := filepath.WalkDir(mount, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// A cgroup removed during the walk.
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil //nolint:nilerr // removed during the walk
		}
		sys, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		rel, _ := filepath.Rel(mount, p)
		out[sys.Ino] = path.Clean("/" + filepath.ToSlash(rel))
		if len(out) > maxCgroups {
			return errors.New("more than 100000 cgroups")
		}
		return nil
	})
	return out, err
}

// UnitOf returns the systemd unit a cgroup path belongs to: the first
// path element that names a service, scope, or socket. "/init.scope" is
// PID 1. "" for the root cgroup and for slices alone.
func UnitOf(cg string) string {
	for _, p := range strings.Split(cg, "/") {
		if strings.HasSuffix(p, ".service") || strings.HasSuffix(p, ".scope") || strings.HasSuffix(p, ".socket") {
			return p
		}
	}
	return ""
}
