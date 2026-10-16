package dpkg

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// labFixtures returns testdata/lab/* directories captured from a dpkg host
// by scripts/lab-dpkg.sh.
func labFixtures(t *testing.T) []string {
	t.Helper()
	dirs, err := filepath.Glob("../../../testdata/lab/*")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, "root", DefaultAdminDir, "status")); err == nil {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		t.Fatal("no dpkg lab fixtures under testdata/lab")
	}
	return out
}

// TestLabDpkgQuery is the M1 acceptance test kept in CI: for every captured
// host, our rendering of the database is byte-identical to what
// dpkg-query -W printed on that host, and agrees with every row of dpkg -l.
func TestLabDpkgQuery(t *testing.T) {
	for _, dir := range labFixtures(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			db, err := ReadDatabase(os.DirFS(filepath.Join(dir, "root")), DefaultAdminDir)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if err := db.WriteQuery(&got); err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(dir, "expected", "dpkg-query.tsv"))
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

			listing, err := os.ReadFile(filepath.Join(dir, "expected", "dpkg-l.txt"))
			if err != nil {
				t.Fatal(err)
			}
			rows := dpkgListRows(listing)
			if len(rows) != len(db.Packages) {
				t.Fatalf("dpkg -l has %d rows, database has %d packages", len(rows), len(db.Packages))
			}
			for i, p := range db.Packages {
				ours := []string{strings.TrimRight(p.StatusAbbrev(), " "), db.BinaryPackage(p), p.Version.String(), p.Architecture}
				if strings.Join(rows[i], " ") != strings.Join(ours, " ") {
					t.Errorf("dpkg -l row %d: %q, ours %q", i+1, rows[i], ours)
				}
			}
		})
	}
}

// dpkgListRows returns the first four columns of each package row of
// "dpkg -l" output: status, name, version, architecture.
func dpkgListRows(b []byte) [][]string {
	var rows [][]string
	sc := bufio.NewScanner(bytes.NewReader(b))
	body := false
	for sc.Scan() {
		if body {
			if f := strings.Fields(sc.Text()); len(f) >= 4 {
				rows = append(rows, f[:4])
			}
		}
		if strings.HasPrefix(sc.Text(), "+++-") {
			body = true
		}
	}
	return rows
}
