package history

import (
	"errors"
	"io/fs"
	"path"
	"strings"
	"time"
)

// Zone is the time zone used to read the logs' local timestamps. dpkg and
// apt write wall-clock time with no offset, so the zone is the host's
// zone now. Lines written before the host's zone changed (a cloud image
// built in UTC and booted elsewhere, say) are off by the difference, and
// nothing in the logs can reveal that; LocalTime keeps the raw value.
type Zone struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	loc    *time.Location
}

func hostZone(fsys fs.FS) (Zone, error) {
	const link = "etc/localtime"
	name, file := "local", link
	// /etc/localtime is usually an absolute symlink. Resolve it inside
	// fsys ourselves: following it through the OS would leave the root
	// when fsys is a mounted image or a test fixture.
	if target, err := fs.ReadLink(fsys, link); err == nil {
		if after, ok := cutAfter(target, "zoneinfo/"); ok {
			name = after
		}
		if path.IsAbs(target) {
			file = strings.TrimPrefix(path.Clean(target), "/")
		} else {
			file = path.Join(path.Dir(link), target)
		}
	} else if tz, err := fs.ReadFile(fsys, "etc/timezone"); err == nil {
		name = strings.TrimSpace(string(tz))
	}
	data, err := fs.ReadFile(fsys, file)
	if errors.Is(err, fs.ErrNotExist) {
		return Zone{Name: "UTC", Source: "default (no /etc/localtime)", loc: time.UTC}, nil
	}
	if err != nil {
		return Zone{}, err
	}
	loc, err := time.LoadLocationFromTZData(name, data)
	if err != nil {
		return Zone{}, err
	}
	return Zone{Name: name, Source: "/" + file, loc: loc}, nil
}

func cutAfter(s, sep string) (string, bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return "", false
	}
	return s[i+len(sep):], true
}

// parse reads a local timestamp, tolerating apt's double space.
func (z Zone) parse(date, clock string) (time.Time, error) {
	return time.ParseInLocation("2006-01-02 15:04:05", date+" "+clock, z.loc)
}

// ambiguous reports whether a local time falls within an hour of a zone
// offset change, where wall-clock times repeat or are skipped.
func (z Zone) ambiguous(t time.Time) bool {
	_, before := t.Add(-time.Hour).In(z.loc).Zone()
	_, after := t.Add(time.Hour).In(z.loc).Zone()
	return before != after
}

// local formats a UTC instant as the host's local wall-clock time, the
// way the logs would have written it.
func (z Zone) local(t time.Time) string {
	return t.In(z.loc).Format("2006-01-02 15:04:05")
}
