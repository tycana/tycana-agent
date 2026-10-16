package history

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
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

// infoTransaction is one block of "dnf history info" output.
type infoTransaction struct {
	id      int
	cmdline string
	result  string
	begin   string
	altered []string // "Action nevra @repo" as dnf prints them, spaces collapsed
	output  int
}

// parseInfo reads expected/dnf-history-info.txt.
func parseInfo(t *testing.T, path string) []infoTransaction {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []infoTransaction
	var cur *infoTransaction
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		key, val, _ := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch {
		case key == "Transaction ID":
			id, _ := strconv.Atoi(val)
			out = append(out, infoTransaction{id: id})
			cur = &out[len(out)-1]
			section = ""
		case cur == nil:
		case key == "Command Line":
			cur.cmdline = val
		case key == "Return-Code":
			cur.result = val
		case key == "Begin time":
			cur.begin = val
		case key == "Packages Altered":
			section = "packages"
		case key == "Scriptlet output":
			section = "output"
		case strings.HasPrefix(line, "    ") && section == "packages":
			cur.altered = append(cur.altered, strings.Join(strings.Fields(line), " "))
		case strings.HasPrefix(line, "   ") && section == "output":
			cur.output++
		}
	}
	return out
}

// TestLabDnfHistory checks the captured dnf database against what dnf
// itself printed on the same host: every transaction, its command line,
// result, and every package line.
func TestLabDnfHistory(t *testing.T) {
	dir := "../../testdata/lab/alma9"
	root := materialize(t, filepath.Join(dir, "root"))
	h, err := Collect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Sources) != 1 || h.Sources[0] != "/"+DnfHistory || h.Zone.Name != "America/New_York" {
		t.Fatalf("sources %v, zone %+v", h.Sources, h.Zone)
	}
	want := parseInfo(t, filepath.Join(dir, "expected", "dnf-history-info.txt"))
	if len(want) == 0 || len(want) != len(h.Transactions) {
		t.Fatalf("%d transactions, dnf printed %d", len(h.Transactions), len(want))
	}
	for i, w := range want {
		tr := h.Transactions[i]
		if tr.ID != w.id || tr.Source != "dnf" || tr.Commandline != w.cmdline || len(tr.Output) != w.output {
			t.Errorf("transaction %d: id %d cmdline %q output %d; dnf printed id %d %q output %d", i, tr.ID, tr.Commandline, len(tr.Output), w.id, w.cmdline, w.output)
		}
		if (w.result == "Success") != (tr.State == "done") {
			t.Errorf("transaction %d: state %q, dnf printed %q", w.id, tr.State, w.result)
		}
		// "Fri Oct 16 12:17:32 2026" in UTC.
		if got := tr.Start.UTC().Format("Mon Jan _2 15:04:05 2006"); got != w.begin {
			t.Errorf("transaction %d: begin %q, dnf printed %q", w.id, got, w.begin)
		}
		var got []string
		for _, c := range tr.Changes {
			nevra := func(evr string) string { return c.Package + "-" + evr + "." + c.Arch }
			switch c.Kind {
			case KindInstall:
				got = append(got, "Install "+nevra(c.To)+" @"+c.Repo)
			case KindRemove:
				got = append(got, "Removed "+nevra(c.From)+" @"+c.Repo)
			case KindReasonChange:
				got = append(got, "Reason Change "+nevra(c.To)+" @"+c.Repo)
			case KindUpgrade, KindDowngrade, KindReinstall:
				verb := map[string]string{KindUpgrade: "Upgrade", KindDowngrade: "Downgrade", KindReinstall: "Reinstall"}[c.Kind]
				got = append(got, verb+" "+nevra(c.To)+" @"+c.Repo, strings.TrimSuffix(verb, "e")+"ed "+nevra(c.From)+" @@System")
			default:
				t.Errorf("transaction %d: unexpected kind %q", w.id, c.Kind)
			}
		}
		if strings.Join(got, "\n") != strings.Join(w.altered, "\n") {
			t.Errorf("transaction %d packages:\n got %q\nwant %q", w.id, got, w.altered)
		}
	}
	// The out-of-band rpm -e between transactions 6 and 7 on the VM.
	var marked []int
	for _, tr := range h.Transactions {
		if tr.OutOfBandBefore {
			marked = append(marked, tr.ID)
		}
	}
	if len(marked) != 1 || marked[0] != 7 {
		t.Errorf("out-of-band transactions %v, want [7]", marked)
	}
	for i, c := range h.Changes {
		if c.Source != "dnf" || (i > 0 && c.Time.Before(h.Changes[i-1].Time)) || c.Transaction < 0 || c.Transaction >= len(h.Transactions) {
			t.Errorf("change %d: %+v", i, c)
		}
	}
}
