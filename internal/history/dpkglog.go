package history

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"time"

	"tycana.ai/agent/debversion"
)

// Change kinds. dpkg logs downgrades and reinstalls as "upgrade"; we tell
// them apart by comparing versions with dpkg's rules.
const (
	KindInstall   = "install"
	KindUpgrade   = "upgrade"
	KindDowngrade = "downgrade"
	KindReinstall = "reinstall"
	KindRemove    = "remove"
	KindPurge     = "purge"
	KindDisappear = "disappear"
)

// Change is one package operation dpkg or dnf performed.
type Change struct {
	// Source is "dpkg" or "dnf".
	Source    string    `json:"source"`
	Time      time.Time `json:"time"`       // UTC
	LocalTime string    `json:"local_time"` // as logged
	// NearZoneChange is set when LocalTime is within an hour of a
	// daylight-saving switch, where the UTC conversion may be off by one.
	NearZoneChange bool   `json:"near_zone_change,omitempty"`
	Kind           string `json:"kind"`
	Package        string `json:"package"`
	Arch           string `json:"arch"`
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	// EndState is the last dpkg status recorded for this package before
	// its next operation: "installed" means an install or upgrade
	// completed; "half-configured" and friends mean it did not.
	EndState   string `json:"end_state"`
	EndVersion string `json:"end_version,omitempty"`
	// Transaction indexes History.Transactions: the apt run that was in
	// progress when dpkg made the change, or -1 if none was.
	Transaction int `json:"transaction"`
}

// parseDpkgLog turns dpkg.log lines into changes. Purges are taken from
// status lines, because dpkg writes no "purge" line for packages without
// conffiles: a purge is a move from config-files to not-installed.
func parseDpkgLog(data []byte, z Zone) ([]Change, error) {
	var out []Change
	open := map[string]int{}         // pkg:arch -> index of its latest change
	lastState := map[string]string{} // pkg:arch -> last status seen
	lastVer := map[string]string{}   // pkg:arch -> version on that status line
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		var key string
		switch f[2] {
		case "install", "upgrade", "remove", "purge", "disappear", "status":
			if len(f) < 6 {
				return nil, fmt.Errorf("dpkg.log line %d: too few fields", lineNo)
			}
		default: // startup, configure, trigproc, conffile: not operations
			continue
		}
		t, err := z.parse(f[0], f[1])
		if err != nil {
			return nil, fmt.Errorf("dpkg.log line %d: %w", lineNo, err)
		}
		mk := func(kind, pkgArch, from, to string) Change {
			name, arch, _ := strings.Cut(pkgArch, ":")
			return Change{
				Time: t.UTC(), LocalTime: f[0] + " " + f[1], NearZoneChange: z.ambiguous(t),
				Kind: kind, Package: name, Arch: arch, From: none(from), To: none(to), Transaction: -1,
			}
		}
		if f[2] == "status" {
			state, pkgArch, ver := f[3], f[4], none(f[5])
			key = pkgArch
			prev, prevVer := lastState[key], lastVer[key]
			lastState[key], lastVer[key] = state, ver
			if state == "not-installed" && prev == "config-files" {
				c := mk(KindPurge, pkgArch, prevVer, "")
				open[key] = len(out)
				out = append(out, c)
			}
			if i, ok := open[key]; ok {
				out[i].EndState, out[i].EndVersion = state, ver
			}
			continue
		}
		key = f[3]
		var c Change
		switch f[2] {
		case "upgrade":
			c = mk(upgradeKind(f[4], f[5]), f[3], f[4], f[5])
		case "purge":
			// The status line that follows records the purge; see above.
			continue
		default:
			c = mk(f[2], f[3], f[4], f[5])
		}
		open[key] = len(out)
		out = append(out, c)
	}
	return out, sc.Err()
}

func none(v string) string {
	if v == "<none>" {
		return ""
	}
	return v
}

func upgradeKind(from, to string) string {
	a, errA := debversion.ParseVersion(from)
	b, errB := debversion.ParseVersion(to)
	if errA != nil || errB != nil {
		return KindUpgrade
	}
	switch debversion.Compare(a, b) {
	case 1:
		return KindDowngrade
	case 0:
		return KindReinstall
	}
	return KindUpgrade
}
