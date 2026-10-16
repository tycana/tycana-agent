package history

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Log locations relative to the filesystem root.
const (
	DpkgLog    = "var/log/dpkg.log"
	AptHistory = "var/log/apt/history.log"
)

// History is the host's package transaction record.
type History struct {
	Zone         Zone          `json:"zone"`
	Sources      []string      `json:"sources"`
	Transactions []Transaction `json:"transactions"`
	Changes      []Change      `json:"changes"`
}

// Collect reads dpkg.log and apt's history.log with their rotations, and
// dnf's history database, from the host rooted at root ("/" in
// production; a path, because SQLite opens files by path). Missing logs
// are not an error: minimal images often have none.
func Collect(root string) (*History, error) {
	fsys := os.DirFS(root)
	z, err := hostZone(fsys)
	if err != nil {
		return nil, err
	}
	h := &History{Zone: z, Sources: []string{}, Transactions: []Transaction{}, Changes: []Change{}}

	data, names, err := readAll(fsys, AptHistory)
	if err != nil {
		return nil, err
	}
	if h.Transactions, err = parseAptHistory(data, z); err != nil {
		return nil, err
	}
	h.Sources = append(h.Sources, absolute(names)...)

	data, names, err = readAll(fsys, DpkgLog)
	if err != nil {
		return nil, err
	}
	if h.Changes, err = parseDpkgLog(data, z); err != nil {
		return nil, err
	}
	h.Sources = append(h.Sources, absolute(names)...)
	if h.Transactions == nil {
		h.Transactions = []Transaction{}
	}
	if h.Changes == nil {
		h.Changes = []Change{}
	}
	for i := range h.Changes {
		h.Changes[i].Source = "dpkg"
	}
	link(h)

	if _, err := fs.Stat(fsys, DnfHistory); err == nil {
		trans, changes, err := readDnf(filepath.Join(root, filepath.FromSlash(DnfHistory)), z)
		if err != nil {
			return nil, err
		}
		base := len(h.Transactions)
		for i := range changes {
			changes[i].Transaction += base
		}
		merged := len(h.Transactions) > 0 || len(h.Changes) > 0
		h.Transactions = append(h.Transactions, trans...)
		h.Changes = append(h.Changes, changes...)
		h.Sources = append(h.Sources, "/"+DnfHistory)
		if merged {
			sortByTime(h)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return h, nil
}

// sortByTime orders transactions and changes by time when a host has
// records from both package managers, keeping each source's own order
// among equal times and the change-to-transaction links intact.
func sortByTime(h *History) {
	order := make([]int, len(h.Transactions))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return h.Transactions[order[a]].Start.Before(h.Transactions[order[b]].Start) })
	remap := make(map[int]int, len(order))
	sorted := make([]Transaction, len(order))
	for newIdx, oldIdx := range order {
		remap[oldIdx] = newIdx
		sorted[newIdx] = h.Transactions[oldIdx]
	}
	h.Transactions = sorted
	for i := range h.Changes {
		if n, ok := remap[h.Changes[i].Transaction]; ok {
			h.Changes[i].Transaction = n
		}
	}
	sort.SliceStable(h.Changes, func(a, b int) bool { return h.Changes[a].Time.Before(h.Changes[b].Time) })
}

// link attributes each dpkg change to the apt transaction whose window
// (whole seconds, as logged) contains it.
func link(h *History) {
	j := 0
	for i := range h.Changes {
		c := &h.Changes[i]
		for j < len(h.Transactions) && !h.Transactions[j].End.IsZero() && h.Transactions[j].End.Before(c.Time) {
			j++
		}
		for k := j; k < len(h.Transactions); k++ {
			t := h.Transactions[k]
			if t.Start.After(c.Time) {
				break
			}
			if !t.End.IsZero() && !t.End.Before(c.Time) {
				c.Transaction = k
				break
			}
		}
	}
}

// Since returns the changes and transactions at or after t.
func (h *History) Since(t time.Time) *History {
	out := &History{Zone: h.Zone, Sources: h.Sources, Transactions: []Transaction{}, Changes: []Change{}}
	remap := map[int]int{-1: -1}
	for i, tr := range h.Transactions {
		if !tr.Start.Before(t) || (!tr.End.IsZero() && !tr.End.Before(t)) {
			remap[i] = len(out.Transactions)
			out.Transactions = append(out.Transactions, tr)
		}
	}
	for _, c := range h.Changes {
		if c.Time.Before(t) {
			continue
		}
		n, ok := remap[c.Transaction]
		if !ok {
			n = -1
		}
		c.Transaction = n
		out.Changes = append(out.Changes, c)
	}
	return out
}

func absolute(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = "/" + n
	}
	return out
}
