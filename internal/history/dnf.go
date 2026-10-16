package history

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"tycana.ai/agent/internal/sqlitero"
)

// DnfHistory is dnf's transaction database, relative to the root. It is
// libdnf's "swdb" (schema 1.x, dnf 4 on RHEL 8 and 9, and dnf 5 keeps the
// same tables). Group and environment items are not read.
const DnfHistory = "var/lib/dnf/history.sqlite"

// KindReasonChange is a dnf transaction that changed only why a package
// is installed (user request or dependency), not the package itself.
const KindReasonChange = "reason-change"

// dnfAction maps trans_item.action (libdnf TransactionItemAction) to a
// change kind. old marks the "ed" side of a pair: Upgraded is the version
// an Upgrade replaced. Old sides fold into their replacement's From.
var dnfAction = map[int]struct {
	kind string
	old  bool
}{
	1:  {KindInstall, false},
	2:  {KindDowngrade, false},
	3:  {KindDowngrade, true},
	4:  {KindInstall, false}, // Obsolete: the new package
	5:  {KindRemove, false},  // Obsoleted: the package it replaced, a different name
	6:  {KindUpgrade, false},
	7:  {KindUpgrade, true},
	8:  {KindRemove, false},
	9:  {KindReinstall, false},
	10: {KindReinstall, true},
	11: {KindReasonChange, false},
}

// dnfReason maps trans_item.reason (libdnf TransactionItemReason).
var dnfReason = map[int]string{1: "dependency", 2: "user", 3: "clean", 4: "weak-dependency", 5: "group"}

// dnfState maps trans.state and trans_item.state (libdnf TransactionState).
var dnfState = map[int]string{1: "done", 2: "error"}

type dnfItem struct {
	id, trans, action, reason, state int
	repo, name, arch                 string
	evr                              string
}

// readDnf reads dnf's history database. Transactions come back in id
// order; each Change's Transaction field indexes that slice.
func readDnf(file string, z Zone) ([]Transaction, []Change, error) {
	d, err := sqlitero.Open(file)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = d.Close() }() // read-only

	tables := map[string]bool{}
	ctx := context.Background()
	rows, err := d.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type = 'table'")
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		tables[n] = true
	}
	if err := rows.Close(); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	for _, t := range []string{"trans", "trans_item", "rpm"} {
		if !tables[t] {
			return nil, nil, fmt.Errorf("%s: no %s table; not a dnf history database", file, t)
		}
	}

	var trans []Transaction
	index := map[int]int{} // dnf transaction id -> position
	rows, err = d.QueryContext(ctx, `SELECT id, dt_begin, COALESCE(dt_end, 0), COALESCE(rpmdb_version_begin, ''),
		COALESCE(rpmdb_version_end, ''), COALESCE(releasever, ''), user_id, COALESCE(cmdline, ''), state
		FROM trans ORDER BY id`)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	for rows.Next() {
		var id, begin, end, uid, state int64
		var t Transaction
		if err := rows.Scan(&id, &begin, &end, &t.RPMDBBefore, &t.RPMDBAfter, &t.ReleaseVer, &uid, &t.Commandline, &state); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		t.Source, t.ID = "dnf", int(id)
		t.Start = time.Unix(begin, 0).UTC()
		t.LocalStart = z.local(t.Start)
		if end != 0 {
			t.End = time.Unix(end, 0).UTC()
			t.LocalEnd = z.local(t.End)
		}
		if uid >= 0 {
			u := int(uid)
			t.RequestedByUID = &u
		}
		t.State = dnfState[int(state)]
		t.Changes = []TransactionChange{}
		if n := len(trans); n > 0 && t.RPMDBBefore != "" && trans[n-1].RPMDBAfter != "" && t.RPMDBBefore != trans[n-1].RPMDBAfter {
			t.OutOfBandBefore = true
		}
		index[t.ID] = len(trans)
		trans = append(trans, t)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}

	var items []dnfItem
	byID := map[int]int{} // trans_item id -> position in items
	rows, err = d.QueryContext(ctx, `SELECT ti.id, ti.trans_id, COALESCE(r.repoid, ''), ti.action, ti.reason, ti.state,
		p.name, p.epoch, p.version, p.release, p.arch
		FROM trans_item ti JOIN rpm p ON p.item_id = ti.item_id LEFT JOIN repo r ON r.id = ti.repo_id
		ORDER BY ti.trans_id, ti.id`)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}
	for rows.Next() {
		var it dnfItem
		var epoch int64
		var version, release string
		if err := rows.Scan(&it.id, &it.trans, &it.repo, &it.action, &it.reason, &it.state, &it.name, &epoch, &version, &release, &it.arch); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		it.evr = version + "-" + release
		if epoch > 0 {
			it.evr = strconv.FormatInt(epoch, 10) + ":" + it.evr
		}
		byID[it.id] = len(items)
		items = append(items, it)
	}
	if err := rows.Close(); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", file, err)
	}

	// replaced maps a new-side item to the old-side item it replaced.
	replaced := map[int]int{}
	folded := map[int]bool{}
	if tables["item_replaced_by"] {
		rows, err = d.QueryContext(ctx, "SELECT trans_item_id, by_trans_item_id FROM item_replaced_by")
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		for rows.Next() {
			var old, by int
			if err := rows.Scan(&old, &by); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", file, err)
			}
			// Only "ed" sides fold: an Obsoleted package has a
			// different name and stays a removal of its own.
			if i, ok := byID[old]; ok && dnfAction[items[i].action].old {
				replaced[by] = old
				folded[old] = true
			}
		}
		if err := rows.Close(); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file, err)
		}
	}

	if tables["console_output"] {
		rows, err = d.QueryContext(ctx, "SELECT trans_id, line FROM console_output ORDER BY id")
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file, err)
		}
		for rows.Next() {
			var tid int
			var line string
			if err := rows.Scan(&tid, &line); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", file, err)
			}
			if i, ok := index[tid]; ok {
				trans[i].Output = append(trans[i].Output, line)
			}
		}
		if err := rows.Close(); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", file, err)
		}
	}

	// Old sides without a link (older libdnf, or a database written
	// mid-transaction) fold into the same transaction's new side with
	// the same name and arch when there is exactly one; otherwise they
	// are reported as removals, which is what rpm did to them.
	for i, it := range items {
		a := dnfAction[it.action]
		if !a.old || folded[it.id] {
			continue
		}
		var match []int
		for j, other := range items {
			if other.trans == it.trans && j != i && !dnfAction[other.action].old && dnfAction[other.action].kind == a.kind && other.name == it.name && other.arch == it.arch {
				match = append(match, other.id)
			}
		}
		if len(match) == 1 {
			if _, taken := replaced[match[0]]; !taken {
				replaced[match[0]] = it.id
				folded[it.id] = true
			}
		}
	}

	var changes []Change
	for _, it := range items {
		a, known := dnfAction[it.action]
		ti, ok := index[it.trans]
		if !known || !ok || folded[it.id] {
			continue
		}
		tc := TransactionChange{
			Kind: a.kind, Package: it.name, Arch: it.arch, Repo: it.repo,
			Reason: dnfReason[it.reason], State: dnfState[it.state],
		}
		tc.Automatic = tc.Reason == "dependency" || tc.Reason == "weak-dependency"
		switch {
		case a.kind == KindRemove || a.old:
			tc.From = it.evr
		default:
			tc.To = it.evr
			if old, ok := replaced[it.id]; ok {
				tc.From = items[byID[old]].evr
			}
		}
		t := &trans[ti]
		t.Changes = append(t.Changes, tc)

		c := Change{
			Source: "dnf", Time: t.End, Kind: tc.Kind, Package: tc.Package, Arch: tc.Arch,
			From: tc.From, To: tc.To, Transaction: ti,
		}
		if c.Time.IsZero() {
			c.Time = t.Start
		}
		c.LocalTime = z.local(c.Time)
		switch tc.State {
		case "done":
			c.EndState, c.EndVersion = "installed", tc.To
			if tc.Kind == KindRemove {
				c.EndState, c.EndVersion = "not-installed", ""
			}
		case "error":
			c.EndState = "error"
		}
		changes = append(changes, c)
	}
	if d.Changed() {
		return nil, nil, fmt.Errorf("%s: changed while it was being read; try again", file)
	}
	return trans, changes, nil
}
