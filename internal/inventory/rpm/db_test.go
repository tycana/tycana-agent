package rpm

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

// writeDB creates an rpmdb.sqlite with the given blobs in dir/sub.
func writeDB(t *testing.T, root, sub string, blobs ...[]byte) {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(sub))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, DBFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "CREATE TABLE 'Packages' (hnum INTEGER PRIMARY KEY AUTOINCREMENT,blob BLOB NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	for i, b := range blobs {
		// Leave gaps in hnum, as a database with removed packages has.
		if _, err := db.ExecContext(ctx, "INSERT INTO Packages(hnum, blob) VALUES (?, ?)", 2*i+1, b); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLocate(t *testing.T) {
	cases := []struct {
		files   []string
		wantDir string
		wantErr error
	}{
		{[]string{"var/lib/rpm/rpmdb.sqlite"}, "var/lib/rpm", nil},
		{[]string{"usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite"}, "usr/lib/sysimage/rpm", nil},
		{[]string{"usr/share/rpm/rpmdb.sqlite"}, "usr/share/rpm", nil},
		{[]string{"var/lib/rpm/Packages"}, "", ErrUnsupportedBackend},
		{[]string{"var/lib/rpm/Packages.db"}, "", ErrUnsupportedBackend},
		{[]string{"var/lib/rpm/Packages", "usr/lib/sysimage/rpm/rpmdb.sqlite"}, "usr/lib/sysimage/rpm", nil},
		{[]string{"var/lib/dpkg/status"}, "", ErrNotFound},
		{nil, "", ErrNotFound},
	}
	for _, c := range cases {
		fsys := fstest.MapFS{}
		for _, f := range c.files {
			fsys[f] = &fstest.MapFile{}
		}
		dir, err := Locate(fsys)
		if dir != c.wantDir || !errors.Is(err, c.wantErr) {
			t.Errorf("Locate(%v) = %q, %v; want %q, %v", c.files, dir, err, c.wantDir, c.wantErr)
		}
	}
}

func TestReadDatabaseAndQuery(t *testing.T) {
	root := t.TempDir()
	writeDB(t, root, "var/lib/rpm", samplePackage(t), samplePubkey(t))
	db, err := ReadDatabase(root, "var/lib/rpm")
	if err != nil {
		t.Fatal(err)
	}
	if db.Dir != "var/lib/rpm" || !db.Immutable || db.Retries != 0 || len(db.Packages) != 2 {
		t.Fatalf("db = %+v", db)
	}
	if db.Packages[0].Instance != 1 || db.Packages[1].Instance != 3 || db.Packages[1].Name != "gpg-pubkey" {
		t.Errorf("order/instances: %+v", db.Packages)
	}
	var out bytes.Buffer
	if err := db.WriteQuery(&out); err != nil {
		t.Fatal(err)
	}
	want := "bash\t1\t5.1.8\t9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\t1786337864\t1700000000\t7700000\t6dabf1be9c0bad3cff22de1ee5c4aa55\tThe GNU Bourne Again shell\n" +
		"gpg-pubkey\t0\tb86b3716\t61e69f29\t(none)\t(none)\t1786338009\t1642503977\t0\t(none)\tAlmaLinux OS 9 <packager@almalinux.org> public key\n"
	if out.String() != want {
		t.Errorf("query output:\n got %q\nwant %q", out.String(), want)
	}
}

func TestReadDatabaseErrors(t *testing.T) {
	root := t.TempDir()
	writeDB(t, root, "var/lib/rpm", samplePackage(t), []byte("not a header"))
	if _, err := ReadDatabase(root, "var/lib/rpm"); err == nil || !strings.Contains(err.Error(), "header 3") || !errors.Is(err, errMalformed) {
		t.Errorf("corrupt header: err = %v", err)
	}
	if _, err := ReadDatabase(t.TempDir(), "var/lib/rpm"); err == nil {
		t.Error("missing database: no error")
	}
}
