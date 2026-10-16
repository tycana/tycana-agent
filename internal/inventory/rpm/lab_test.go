package rpm

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// materialize copies a lab fixture's root/ tree to a temp directory,
// decompressing *.gz files, because SQLite opens databases by path and
// the rpm fixture is committed gzipped.
func materialize(t *testing.T, fixtureRoot string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(fixtureRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(fixtureRoot, p)
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, out)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".gz") {
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				return err
			}
			if data, err = io.ReadAll(zr); err != nil {
				return err
			}
			out = strings.TrimSuffix(out, ".gz")
		}
		return os.WriteFile(out, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// labFixtures returns testdata/lab/* directories captured from an rpm
// host by scripts/lab-rpm.sh.
func labFixtures(t *testing.T) []string {
	t.Helper()
	dirs, err := filepath.Glob("../../../testdata/lab/*")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, "expected", "rpm-qa.tsv")); err == nil {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		t.Fatal("no rpm lab fixtures under testdata/lab")
	}
	return out
}

// TestLabRPMQuery is the M1 acceptance test kept in CI: for every captured
// host, our rendering of the database is byte-identical to what
// rpm -qa --qf printed on that host.
func TestLabRPMQuery(t *testing.T) {
	for _, dir := range labFixtures(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			root := materialize(t, filepath.Join(dir, "root"))
			dbDir, err := Locate(os.DirFS(root))
			if err != nil {
				t.Fatal(err)
			}
			db, err := ReadDatabase(root, dbDir)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if err := db.WriteQuery(&got); err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(dir, "expected", "rpm-qa.tsv"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				g, w := strings.Split(got.String(), "\n"), strings.Split(string(want), "\n")
				for i := 0; i < len(g) && i < len(w); i++ {
					if g[i] != w[i] {
						t.Fatalf("line %d differs\n got: %q\nwant: %q", i+1, g[i], w[i])
					}
				}
				t.Fatalf("got %d lines, want %d", len(g), len(w))
			}
			if !db.Immutable || db.Retries != 0 {
				t.Errorf("fixture read: immutable=%v retries=%d", db.Immutable, db.Retries)
			}
		})
	}
}
