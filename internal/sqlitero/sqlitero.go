// Package sqlitero opens SQLite database files for reading only. It is the
// only package in the agent allowed to import the SQLite driver
// (tools/nowrite enforces this), so every database the agent touches,
// rpmdb.sqlite and dnf's history.sqlite today, goes through the same
// read-only discipline (ADR 0017).
//
// Two open modes are used:
//
//   - immutable, when the database's write-ahead log is empty or absent.
//     SQLite then takes no locks, opens no shared-memory file, and writes
//     nothing. rpm truncates rpmdb.sqlite-wal every time it closes the
//     database, so this is the normal case for the package database.
//   - read-only, when the write-ahead log holds frames. SQLite reads the
//     log through its shared-memory index, which it opens read-only when
//     the agent cannot write it (the unit's sandbox and an ordinary user
//     both cannot). dnf leaves frames in history.sqlite-wal.
//
// A database can change under an immutable read. Callers compare
// Changed() after reading and read again if it reports true.
package sqlitero

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver; pure Go, no cgo
)

// walHeaderBytes is the size of a write-ahead log with no frames.
const walHeaderBytes = 32

// DB is an open read-only database.
type DB struct {
	*sql.DB
	// Path is the absolute path of the database file.
	Path string
	// Immutable reports that the database was opened without locking.
	Immutable bool
	// WALBytes is the size of the write-ahead log at open time.
	WALBytes int64

	stamp stamp
}

type stamp struct {
	size, walSize int64
	mod, walMod   time.Time
}

// Open opens the database file at path for reading.
func Open(path string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	st, err := stat(abs)
	if err != nil {
		return nil, err
	}
	d := &DB{Path: abs, WALBytes: st.walSize, stamp: st, Immutable: st.walSize <= walHeaderBytes}
	u := url.URL{Scheme: "file", Path: abs}
	q := "mode=ro&_pragma=query_only(1)"
	if d.Immutable {
		q += "&immutable=1"
	}
	d.DB, err = sql.Open("sqlite", u.String()+"?"+q)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	var n int
	if err := d.QueryRowContext(context.Background(), "SELECT count(*) FROM sqlite_master").Scan(&n); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	return d, nil
}

// Changed reports whether the database or its write-ahead log changed
// size or modification time since Open.
func (d *DB) Changed() bool {
	st, err := stat(d.Path)
	return err != nil || st != d.stamp
}

func stat(path string) (stamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return stamp{}, err
	}
	s := stamp{size: fi.Size(), mod: fi.ModTime()}
	wal, err := os.Stat(path + "-wal")
	switch {
	case err == nil:
		s.walSize, s.walMod = wal.Size(), wal.ModTime()
	case errors.Is(err, fs.ErrNotExist):
	default:
		return stamp{}, err
	}
	return s, nil
}
