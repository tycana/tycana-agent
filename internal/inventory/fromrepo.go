package inventory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"tycana.ai/agent/internal/sqlitero"
)

// dnfHistory is dnf's transaction database (libdnf's swdb), relative to
// the root.
const dnfHistory = "var/lib/dnf/history.sqlite"

// fromRepos fills Package.FromRepo on an rpm host from dnf's history: the
// repository of the newest completed transaction that installed the
// version now installed (tycana-hq ADR 0034). Packages that came with the
// OS image, or from rpm without dnf, have no entry. A host without the
// database is not an error.
func fromRepos(root string, s *Snapshot) error {
	file := filepath.Join(root, dnfHistory)
	if _, err := os.Stat(file); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	d, err := sqlitero.Open(file)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }() // read-only
	// trans_item.action (libdnf TransactionItemAction): 1 install,
	// 2 downgrade, 4 obsolete (the new package), 6 upgrade, 9 reinstall;
	// state 1 is done.
	rows, err := d.QueryContext(context.Background(), `SELECT p.name, p.arch, p.epoch, p.version, p.release, COALESCE(r.repoid, '')
		FROM trans_item ti JOIN rpm p ON p.item_id = ti.item_id LEFT JOIN repo r ON r.id = ti.repo_id
		WHERE ti.action IN (1, 2, 4, 6, 9) AND ti.state = 1
		ORDER BY ti.trans_id, ti.id`)
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	defer func() { _ = rows.Close() }()
	repo := map[[3]string]string{}
	for rows.Next() {
		var name, arch, version, release, id string
		var epoch int64
		if err := rows.Scan(&name, &arch, &epoch, &version, &release, &id); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		evr := version + "-" + release
		if epoch > 0 {
			evr = strconv.FormatInt(epoch, 10) + ":" + evr
		}
		repo[[3]string{name, arch, evr}] = id
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	for i := range s.Packages {
		p := &s.Packages[i]
		evr := p.Version + "-" + p.Release
		if p.Epoch > 0 {
			evr = strconv.FormatUint(uint64(p.Epoch), 10) + ":" + evr
		}
		if id := repo[[3]string{p.Name, p.Arch, evr}]; id != "" {
			p.FromRepo = id
		}
	}
	return nil
}
