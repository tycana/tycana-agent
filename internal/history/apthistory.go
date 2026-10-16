package history

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Transaction is one package-manager run: an apt run from
// /var/log/apt/history.log, or a dnf transaction from history.sqlite.
type Transaction struct {
	// Source is "apt" or "dnf".
	Source string `json:"source"`
	// ID is dnf's transaction id; apt has none.
	ID         int       `json:"id,omitempty"`
	Start      time.Time `json:"start"` // UTC
	End        time.Time `json:"end,omitzero"`
	LocalStart string    `json:"local_start"`
	LocalEnd   string    `json:"local_end,omitempty"`
	// Commandline is what was run, for example "apt-get upgrade" or
	// "/usr/bin/unattended-upgrade". It is data from the host: display
	// it, never interpret it.
	Commandline string `json:"commandline,omitempty"`
	// RequestedBy is the invoking user when apt ran under sudo or pkexec.
	// Absent for root shells, cron, and unattended-upgrades alike.
	RequestedBy    string              `json:"requested_by,omitempty"`
	RequestedByUID *int                `json:"requested_by_uid,omitempty"`
	Changes        []TransactionChange `json:"changes"`
	Error          string              `json:"error,omitempty"`

	// dnf only. State is "done", "error", or "" when dnf recorded no
	// result. RPMDBBefore and RPMDBAfter are dnf's checksums of the rpm
	// database around the transaction. OutOfBandBefore is set when
	// RPMDBBefore differs from the previous transaction's RPMDBAfter:
	// something other than dnf (rpm itself, say) changed packages in
	// between. Output is scriptlet output dnf kept; it is data from the
	// host, to display and never interpret.
	ReleaseVer      string   `json:"releasever,omitempty"`
	State           string   `json:"state,omitempty"`
	RPMDBBefore     string   `json:"rpmdb_before,omitempty"`
	RPMDBAfter      string   `json:"rpmdb_after,omitempty"`
	OutOfBandBefore bool     `json:"out_of_band_before,omitempty"`
	Output          []string `json:"output,omitempty"`
}

// TransactionChange is one package line of a transaction.
type TransactionChange struct {
	Kind    string `json:"kind"` // install, upgrade, downgrade, reinstall, remove, purge, reason-change
	Package string `json:"package"`
	Arch    string `json:"arch"` // apt logs arch-all packages under the native arch
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	// Automatic means the package manager pulled the package in as a
	// dependency rather than at the user's request.
	Automatic bool `json:"automatic,omitempty"`
	// Reason (dnf) is why the package is installed: user, dependency,
	// weak-dependency, group, clean. Repo is the repository it came
	// from, "@System" for packages already on the host. State is "done"
	// or "error" for the item.
	Reason string `json:"reason,omitempty"`
	Repo   string `json:"repo,omitempty"`
	State  string `json:"state,omitempty"`
}

var aptKinds = map[string]string{
	"install": KindInstall, "upgrade": KindUpgrade, "downgrade": KindDowngrade,
	"reinstall": KindReinstall, "remove": KindRemove, "purge": KindPurge,
}

// parseAptHistory reads history.log records, which are blank-line
// separated "Key: value" blocks starting with Start-Date.
func parseAptHistory(data []byte, z Zone) ([]Transaction, error) {
	var out []Transaction
	var cur *Transaction
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20) // one Upgrade line can list thousands of packages
	lineNo := 0
	for sc.Scan() {
		lineNo++
		key, val, ok := strings.Cut(sc.Text(), ": ")
		if !ok {
			continue
		}
		lk := strings.ToLower(key)
		if lk == "start-date" {
			f := strings.Fields(val)
			if len(f) != 2 {
				return nil, fmt.Errorf("history.log line %d: bad Start-Date %q", lineNo, val)
			}
			t, err := z.parse(f[0], f[1])
			if err != nil {
				return nil, fmt.Errorf("history.log line %d: %w", lineNo, err)
			}
			out = append(out, Transaction{Source: "apt", Start: t.UTC(), LocalStart: f[0] + " " + f[1], Changes: []TransactionChange{}})
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil {
			continue // fragment before the first record, e.g. after rotation
		}
		switch lk {
		case "end-date":
			f := strings.Fields(val)
			if len(f) == 2 {
				if t, err := z.parse(f[0], f[1]); err == nil {
					cur.End, cur.LocalEnd = t.UTC(), f[0]+" "+f[1]
				}
			}
		case "commandline":
			cur.Commandline = val
		case "requested-by":
			name, uid, _ := strings.Cut(val, " (")
			cur.RequestedBy = name
			if n, err := strconv.Atoi(strings.TrimSuffix(uid, ")")); err == nil {
				cur.RequestedByUID = &n
			}
		case "error":
			cur.Error = val
		default:
			kind, ok := aptKinds[lk]
			if !ok {
				continue
			}
			changes, err := parseAptPackages(kind, val)
			if err != nil {
				return nil, fmt.Errorf("history.log line %d: %w", lineNo, err)
			}
			cur.Changes = append(cur.Changes, changes...)
		}
	}
	return out, sc.Err()
}

// parseAptPackages splits "a:amd64 (1.0, automatic), b:amd64 (1.0, 2.0)".
// Debian versions cannot contain commas or parentheses, so "), " is a safe
// separator.
func parseAptPackages(kind, val string) ([]TransactionChange, error) {
	var out []TransactionChange
	for _, item := range strings.Split(strings.TrimSuffix(strings.TrimSpace(val), ")"), "), ") {
		pkg, inner, ok := strings.Cut(item, " (")
		if !ok {
			return nil, fmt.Errorf("%s entry %q: no version", kind, item)
		}
		name, arch, _ := strings.Cut(pkg, ":")
		c := TransactionChange{Kind: kind, Package: name, Arch: arch}
		parts := strings.Split(inner, ", ")
		if parts[len(parts)-1] == "automatic" {
			c.Automatic = true
			parts = parts[:len(parts)-1]
		}
		switch {
		case len(parts) == 2:
			c.From, c.To = parts[0], parts[1]
		case len(parts) == 1 && (kind == KindRemove || kind == KindPurge):
			c.From = parts[0]
		case len(parts) == 1:
			c.To = parts[0]
			if kind == KindReinstall {
				c.From = parts[0]
			}
		default:
			return nil, fmt.Errorf("%s entry %q: unexpected fields", kind, item)
		}
		out = append(out, c)
	}
	return out, nil
}
