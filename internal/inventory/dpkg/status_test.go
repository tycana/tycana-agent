package dpkg

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func TestReadDatabaseSynthetic(t *testing.T) {
	db, err := ReadDatabase(os.DirFS("testdata/synthetic"), DefaultAdminDir)
	if err != nil {
		t.Fatal(err)
	}
	if db.NativeArch != "amd64" {
		t.Errorf("NativeArch = %q, want amd64", db.NativeArch)
	}
	if db.UpdatesApplied != 2 {
		t.Errorf("UpdatesApplied = %d, want 2 (0000 and 0001, not tmp.i)", db.UpdatesApplied)
	}
	var got bytes.Buffer
	if err := db.WriteQuery(&got); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/synthetic/expected-query.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("WriteQuery mismatch\n--- got\n%s--- want\n%s", got.String(), want)
	}
}

func TestReadDatabaseErrors(t *testing.T) {
	cases := map[string]string{
		"no package":      "Status: install ok installed\n",
		"bad status":      "Package: a\nStatus: install ok\n",
		"unknown want":    "Package: a\nStatus: frobnicate ok installed\n",
		"bad version":     "Package: a\nStatus: install ok installed\nVersion: 1.0-\n",
		"bad source ver":  "Package: a\nStatus: install ok installed\nVersion: 1\nSource: b (x:1)\n",
		"orphan continue": " leading continuation\n",
		"not a field":     "Package: a\njunk line\n",
		"duplicate field": "Package: a\nPackage: b\nStatus: install ok installed\n",
	}
	for name, status := range cases {
		fsys := fstest.MapFS{"var/lib/dpkg/status": {Data: []byte(status)}}
		if _, err := ReadDatabase(fsys, DefaultAdminDir); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if _, err := ReadDatabase(fstest.MapFS{}, DefaultAdminDir); err == nil {
		t.Error("missing status file: want error")
	}
}

func TestReadDatabaseNoUpdatesDir(t *testing.T) {
	fsys := fstest.MapFS{"var/lib/dpkg/status": {Data: []byte(
		"Package: dpkg\nStatus: install ok installed\nArchitecture: arm64\nVersion: 1.22.6\n" +
			"Description: x\n continued\n")}}
	db, err := ReadDatabase(fsys, DefaultAdminDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Packages) != 1 || db.NativeArch != "arm64" || db.Packages[0].Summary != "x" {
		t.Errorf("got %+v", db)
	}
}

func TestStatusAbbrevCoversAllStates(t *testing.T) {
	for w := range wants {
		for f := range flags {
			for s := range states {
				a := Package{Want: w, Flag: f, State: s}.StatusAbbrev()
				if len(a) != 3 || strings.ContainsRune(a, 0) {
					t.Errorf("StatusAbbrev(%s %s %s) = %q", w, f, s, a)
				}
			}
		}
	}
}

// Found on tycana-ubuntu2404, 2026-10-15: libgdbm6t64's Description has a
// trailing blank on its first line, and dpkg-query prints it.
func TestSummaryKeepsTrailingBlankBeforeContinuation(t *testing.T) {
	status := "Package: dpkg\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1 \n" +
		"Description: first line \n second line  \n\n" +
		"Package: b\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\nDescription:   only line  \n"
	db, err := ReadDatabase(fstest.MapFS{"var/lib/dpkg/status": {Data: []byte(status)}}, DefaultAdminDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Packages[1].Summary; got != "first line " {
		t.Errorf("multi-line summary = %q, want %q", got, "first line ")
	}
	if got := db.Packages[0].Summary; got != "only line" {
		t.Errorf("single-line summary = %q, want %q", got, "only line")
	}
}
