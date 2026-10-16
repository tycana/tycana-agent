// Package filetime reads when a file came into existence, and its mode and
// owner. It is the only package besides internal/hostexec that may make
// raw system calls (tools/nowrite), and it makes two, statx and lstat.
// Both read metadata and change nothing.
package filetime

import (
	"time"

	"golang.org/x/sys/unix"
)

// Source says which timestamp Created returned.
type Source string

const (
	// Birth is the inode's creation time (statx btime).
	Birth Source = "birth"
	// Change is the inode's status change time (ctime), used where the
	// file system records no birth time. chmod and chown also move it.
	Change Source = "change"
)

// Created returns the birth time of the file at name, or its change time
// when the file system does not record birth. Symlinks are not followed.
func Created(name string) (time.Time, Source, error) {
	var st unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, name, unix.AT_SYMLINK_NOFOLLOW|unix.AT_STATX_DONT_SYNC,
		unix.STATX_BTIME|unix.STATX_CTIME, &st)
	if err != nil {
		return time.Time{}, "", err
	}
	if st.Mask&unix.STATX_BTIME != 0 {
		return stamp(st.Btime), Birth, nil
	}
	return stamp(st.Ctime), Change, nil
}

func stamp(t unix.StatxTimestamp) time.Time {
	return time.Unix(t.Sec, int64(t.Nsec)).UTC()
}

// Meta is the part of a file's inode that baseline checks compare.
type Meta struct {
	// Mode is the permission bits with setuid, setgid, and sticky
	// (st_mode & 07777).
	Mode uint32
	UID  uint32
	GID  uint32
	// Type is "file", "dir", "symlink", or "other".
	Type string
}

// Lstat returns the mode, owner, and type of the file at name, without
// following a final symlink. Inside the tycanad unit (PrivateUsers=yes)
// owners other than root and the agent's own user read as the kernel's
// overflow ids; Overflow returns them.
func Lstat(name string) (Meta, error) {
	var st unix.Stat_t
	if err := unix.Lstat(name, &st); err != nil {
		return Meta{}, err
	}
	m := Meta{Mode: st.Mode & 0o7777, UID: st.Uid, GID: st.Gid}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		m.Type = "file"
	case unix.S_IFDIR:
		m.Type = "dir"
	case unix.S_IFLNK:
		m.Type = "symlink"
	default:
		m.Type = "other"
	}
	return m, nil
}
