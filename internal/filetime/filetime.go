// Package filetime reads when a file came into existence. It is the only
// package besides internal/hostexec that may make raw system calls
// (tools/nowrite), and it makes one: statx, which reads metadata and
// changes nothing.
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
