package history

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dnfSchema is the part of libdnf's swdb schema the reader uses.
const dnfSchema = `
CREATE TABLE trans (id INTEGER PRIMARY KEY AUTOINCREMENT, dt_begin INTEGER NOT NULL, dt_end INTEGER,
  rpmdb_version_begin TEXT, rpmdb_version_end TEXT, releasever TEXT NOT NULL, user_id INTEGER NOT NULL,
  cmdline TEXT, state INTEGER NOT NULL, comment TEXT DEFAULT '', persistence INTEGER DEFAULT 0);
CREATE TABLE item (id INTEGER PRIMARY KEY, item_type INTEGER NOT NULL);
CREATE TABLE rpm (item_id INTEGER UNIQUE NOT NULL, name TEXT NOT NULL, epoch INTEGER NOT NULL,
  version TEXT NOT NULL, release TEXT NOT NULL, arch TEXT NOT NULL);
CREATE TABLE repo (id INTEGER PRIMARY KEY, repoid TEXT NOT NULL);
CREATE TABLE trans_item (id INTEGER PRIMARY KEY AUTOINCREMENT, trans_id INTEGER, item_id INTEGER,
  repo_id INTEGER, action INTEGER NOT NULL, reason INTEGER NOT NULL, state INTEGER NOT NULL);
`

const dnfLinkTables = `
CREATE TABLE item_replaced_by (trans_item_id INTEGER, by_trans_item_id INTEGER, PRIMARY KEY (trans_item_id, by_trans_item_id));
CREATE TABLE console_output (id INTEGER PRIMARY KEY, trans_id INTEGER, file_descriptor INTEGER NOT NULL, line TEXT NOT NULL);
`

// writeDnf creates var/lib/dnf/history.sqlite under root from SQL.
func writeDnf(t *testing.T, root, schema, data string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(DnfHistory))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(context.Background(), schema+data); err != nil {
		t.Fatal(err)
	}
}

const dnfData = `
INSERT INTO repo VALUES (1, 'baseos'), (2, '@System');
INSERT INTO item VALUES (1,0),(2,0),(3,0),(4,0),(5,0),(6,0),(7,0),(8,0);
INSERT INTO rpm VALUES (1,'nano',0,'5.6.1','7.el9','x86_64'), (2,'libnftnl',0,'1.2.6','4.el9_4','x86_64'),
  (3,'curl',0,'7.76.1','40.el9_8.8','x86_64'), (4,'curl',0,'7.76.1','40.el9','x86_64'),
  (5,'openssl',1,'3.5.8','2.el9_8','x86_64'), (6,'openssl',1,'3.5.5','6.el9_8','x86_64'),
  (7,'newname',0,'2','1.el9','noarch'), (8,'oldname',0,'1','1.el9','noarch');
-- 1: install nano (user) and libnftnl (dependency), with scriptlet output
INSERT INTO trans VALUES (1, 1792153251, 1792153251, 'aaa', 'bbb', '9', 1000, '-y install nano', 1, '', 1);
INSERT INTO trans_item VALUES (1, 1, 1, 1, 1, 2, 1), (2, 1, 2, 1, 1, 1, 1);
-- 2: upgrade curl (linked pair), upgrade openssl (unlinked pair), obsolete oldname by newname
INSERT INTO trans VALUES (2, 1792153300, 1792153301, 'bbb', 'ccc', '9', 1000, '-y upgrade', 1, '', 1);
INSERT INTO trans_item VALUES (3, 2, 3, 1, 6, 2, 1), (4, 2, 4, 2, 7, 2, 1), (5, 2, 5, 1, 6, 1, 1), (6, 2, 6, 2, 7, 1, 1),
  (7, 2, 7, 1, 4, 2, 1), (8, 2, 8, 2, 5, 2, 1);
-- 3: an rpm -e happened in between; this remove then failed and never ended
INSERT INTO trans VALUES (3, 1792153400, NULL, 'ddd', NULL, '9', -1, '-y remove nano', 2, '', 1);
INSERT INTO trans_item VALUES (9, 3, 1, 2, 8, 2, 2);
-- 4: reason change only, no command line
INSERT INTO trans VALUES (4, 1792153500, 1792153500, 'ddd', 'ddd', '9', 1000, NULL, 1, '', 0);
INSERT INTO trans_item VALUES (10, 4, 2, 1, 11, 2, 1);
`

const dnfLinks = `
INSERT INTO item_replaced_by VALUES (4, 3), (8, 7);
INSERT INTO console_output VALUES (1, 1, 1, 'first line'), (2, 1, 2, 'second line');
`

func TestDnfSynthetic(t *testing.T) {
	root := t.TempDir()
	writeDnf(t, root, dnfSchema+dnfLinkTables, dnfData+dnfLinks)
	h, err := Collect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Sources) != 1 || h.Sources[0] != "/var/lib/dnf/history.sqlite" || len(h.Transactions) != 4 {
		t.Fatalf("sources %v, %d transactions", h.Sources, len(h.Transactions))
	}
	tr := h.Transactions
	if tr[0].Source != "dnf" || tr[0].ID != 1 || tr[0].State != "done" || *tr[0].RequestedByUID != 1000 ||
		!tr[0].Start.Equal(time.Unix(1792153251, 0)) || tr[0].LocalStart != "2026-10-16 12:20:51" || tr[0].ReleaseVer != "9" {
		t.Errorf("transaction 1: %+v", tr[0])
	}
	if strings.Join(tr[0].Output, "|") != "first line|second line" {
		t.Errorf("output: %v", tr[0].Output)
	}
	want := map[int]string{
		0: "install nano:x86_64 ->5.6.1-7.el9 user baseos done; install libnftnl:x86_64 ->1.2.6-4.el9_4 dependency(auto) baseos done",
		1: "upgrade curl:x86_64 7.76.1-40.el9->7.76.1-40.el9_8.8 user baseos done; upgrade openssl:x86_64 1:3.5.5-6.el9_8->1:3.5.8-2.el9_8 dependency(auto) baseos done; " +
			"install newname:noarch ->2-1.el9 user baseos done; remove oldname:noarch 1-1.el9-> user @System done",
		2: "remove nano:x86_64 5.6.1-7.el9-> user @System error",
		3: "reason-change libnftnl:x86_64 ->1.2.6-4.el9_4 user baseos done",
	}
	for i, w := range want {
		if got := describe(tr[i].Changes); got != w {
			t.Errorf("transaction %d changes:\n got %s\nwant %s", i+1, got, w)
		}
	}
	if tr[1].OutOfBandBefore || !tr[2].OutOfBandBefore || tr[3].OutOfBandBefore {
		t.Errorf("out-of-band flags: %v %v %v", tr[1].OutOfBandBefore, tr[2].OutOfBandBefore, tr[3].OutOfBandBefore)
	}
	if tr[2].State != "error" || !tr[2].End.IsZero() || tr[2].RequestedByUID != nil || tr[2].LocalEnd != "" {
		t.Errorf("failed transaction: %+v", tr[2])
	}
	if tr[3].Commandline != "" {
		t.Errorf("reason change cmdline %q", tr[3].Commandline)
	}

	// The dpkg-shaped change list carries the same facts.
	if len(h.Changes) != 8 {
		t.Fatalf("%d changes", len(h.Changes))
	}
	c := h.Changes[2]
	if c.Source != "dnf" || c.Kind != KindUpgrade || c.Package != "curl" || c.From != "7.76.1-40.el9" || c.To != "7.76.1-40.el9_8.8" ||
		c.EndState != "installed" || c.EndVersion != c.To || c.Transaction != 1 || !c.Time.Equal(tr[1].End) || c.LocalTime != "2026-10-16 12:21:41" {
		t.Errorf("change: %+v", c)
	}
	if c := h.Changes[6]; c.Kind != KindRemove || c.EndState != "error" || c.EndVersion != "" || !c.Time.Equal(tr[2].Start) {
		t.Errorf("failed remove: %+v", c)
	}
	if c := h.Changes[5]; c.Kind != KindRemove || c.EndState != "not-installed" || c.From != "1-1.el9" {
		t.Errorf("obsoleted: %+v", c)
	}
	s := h.Since(time.Unix(1792153400, 0))
	if len(s.Transactions) != 2 || len(s.Changes) != 2 || s.Changes[0].Transaction != 0 || s.Changes[1].Transaction != 1 {
		t.Errorf("Since: %d transactions, %+v", len(s.Transactions), s.Changes)
	}
}

func describe(cs []TransactionChange) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		auto := ""
		if c.Automatic {
			auto = "(auto)"
		}
		parts = append(parts, c.Kind+" "+c.Package+":"+c.Arch+" "+c.From+"->"+c.To+" "+c.Reason+auto+" "+c.Repo+" "+c.State)
	}
	return strings.Join(parts, "; ")
}

// Older libdnf databases have no item_replaced_by or console_output
// tables; pairs then fold by name and arch.
func TestDnfOldSchema(t *testing.T) {
	root := t.TempDir()
	writeDnf(t, root, dnfSchema, dnfData)
	h, err := Collect(root)
	if err != nil {
		t.Fatal(err)
	}
	got := describe(h.Transactions[1].Changes)
	want := "upgrade curl:x86_64 7.76.1-40.el9->7.76.1-40.el9_8.8 user baseos done; upgrade openssl:x86_64 1:3.5.5-6.el9_8->1:3.5.8-2.el9_8 dependency(auto) baseos done; " +
		"install newname:noarch ->2-1.el9 user baseos done; remove oldname:noarch 1-1.el9-> user @System done"
	if got != want {
		t.Errorf("old schema:\n got %s\nwant %s", got, want)
	}
	if len(h.Transactions[0].Output) != 0 {
		t.Errorf("output without a console_output table: %v", h.Transactions[0].Output)
	}
}

func TestDnfNotAHistoryDatabase(t *testing.T) {
	root := t.TempDir()
	writeDnf(t, root, "CREATE TABLE other (x);", "")
	if _, err := Collect(root); err == nil || !strings.Contains(err.Error(), "not a dnf history database") {
		t.Errorf("err = %v", err)
	}
}

// A host with both package managers' records keeps them in time order
// with the links intact.
func TestDnfAndAptMerged(t *testing.T) {
	root := t.TempDir()
	writeDnf(t, root, dnfSchema+dnfLinkTables, dnfData+dnfLinks)
	logs := map[string]string{
		"var/log/apt/history.log": "Start-Date: 2026-10-16  12:20:00\nInstall: zzz:amd64 (1)\nEnd-Date: 2026-10-16  12:20:01\n" +
			"\nStart-Date: 2026-10-16  12:30:00\nInstall: yyy:amd64 (1)\nEnd-Date: 2026-10-16  12:30:01\n",
		"var/log/dpkg.log": "2026-10-16 12:20:00 install zzz:amd64 <none> 1\n2026-10-16 12:20:00 status installed zzz:amd64 1\n" +
			"2026-10-16 12:30:00 install yyy:amd64 <none> 1\n2026-10-16 12:30:00 status installed yyy:amd64 1\n",
	}
	for name, data := range logs {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h, err := Collect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Transactions) != 6 || len(h.Changes) != 10 {
		t.Fatalf("%d transactions, %d changes", len(h.Transactions), len(h.Changes))
	}
	var order []string
	for _, tr := range h.Transactions {
		order = append(order, tr.Source)
	}
	if got := strings.Join(order, ","); got != "apt,dnf,dnf,dnf,dnf,apt" {
		t.Errorf("transaction order %s", got)
	}
	for i, c := range h.Changes {
		tr := h.Transactions[c.Transaction]
		if (c.Source == "dpkg") != (tr.Source == "apt") || (i > 0 && c.Time.Before(h.Changes[i-1].Time)) {
			t.Errorf("change %d (%s %s) linked to %s transaction at %v", i, c.Source, c.Package, tr.Source, tr.Start)
		}
		if c.Source == "dnf" && c.Package == "curl" && tr.ID != 2 {
			t.Errorf("curl linked to dnf transaction %d", tr.ID)
		}
	}
}
