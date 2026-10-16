package sqlitero

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// create writes a small database in the given journal mode and returns
// its path. In WAL mode the connection is left open so the log keeps its
// frames, as dnf leaves history.sqlite.
func create(t *testing.T, wal bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if wal {
		if _, err := db.ExecContext(context.Background(), "PRAGMA journal_mode=WAL"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
	}
	if _, err := db.ExecContext(context.Background(), "CREATE TABLE t(x); INSERT INTO t VALUES (1), (2)"); err != nil {
		t.Fatal(err)
	}
	if !wal {
		_ = db.Close()
	}
	return path
}

func TestOpenModes(t *testing.T) {
	for _, wal := range []bool{false, true} {
		path := create(t, wal)
		d, err := Open(path)
		if err != nil {
			t.Fatalf("wal=%v: %v", wal, err)
		}
		var n int
		if err := d.QueryRowContext(context.Background(), "SELECT count(*) FROM t").Scan(&n); err != nil || n != 2 {
			t.Errorf("wal=%v: count %d, err %v", wal, n, err)
		}
		if d.Immutable == wal {
			t.Errorf("wal=%v: immutable=%v, want the opposite (wal bytes %d)", wal, d.Immutable, d.WALBytes)
		}
		if _, err := d.ExecContext(context.Background(), "INSERT INTO t VALUES (3)"); err == nil {
			t.Errorf("wal=%v: a write succeeded on a read-only handle", wal)
		}
		if d.Changed() {
			t.Errorf("wal=%v: Changed() before any change", wal)
		}
		_ = d.Close()
	}
}

func TestChangedAndMissing(t *testing.T) {
	path := create(t, false)
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if err := os.WriteFile(path+"-wal", make([]byte, 64), 0o644); err != nil {
		t.Fatal(err)
	}
	if !d.Changed() {
		t.Error("a new write-ahead log was not noticed")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing.sqlite")); err == nil || !strings.Contains(err.Error(), "missing.sqlite") {
		t.Errorf("missing file: err = %v", err)
	}
	notDB := filepath.Join(t.TempDir(), "x.sqlite")
	if err := os.WriteFile(notDB, []byte("this is not a database, not even close\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(notDB); err == nil {
		t.Error("a text file opened as a database")
	}
}
