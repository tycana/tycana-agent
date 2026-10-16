package updates

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"strings"
	"time"

	"tycana.ai/agent/internal/hostexec"
)

// Autopilot is what the host's own automatic updater will do: whether it
// runs, when, and which of the pending updates it installs. The agent
// applies the updater's rules to the updates the package manager reports
// today; the updater refreshes its package lists before it runs, so it
// can install more than this.
type Autopilot struct {
	// Tool is "unattended-upgrades" or "dnf-automatic".
	Tool      string `json:"tool"`
	Installed bool   `json:"installed"`
	// Runs is true when the tool is installed, set to install updates,
	// and started by an enabled, active timer.
	Runs bool `json:"runs"`
	// Why gives the reasons it does not run.
	Why []string `json:"why,omitempty"`
	// Timer is the timer that starts the install; NextRun its next
	// elapse (UTC), LastRun its last trigger.
	Timer   string    `json:"timer,omitempty"`
	NextRun time.Time `json:"next_run,omitzero"`
	LastRun time.Time `json:"last_run,omitzero"`
	// Origins (unattended-upgrades) are the allowed origins and patterns
	// after variable substitution; UpgradeType (dnf-automatic) is
	// "default" or "security".
	Origins     []string `json:"origins,omitempty"`
	UpgradeType string   `json:"upgrade_type,omitempty"`
	// Reboot is the tool's reboot rule: "never", or when it reboots.
	Reboot string `json:"reboot"`
	// Install is what it would install if it ran with today's lists;
	// Skip is what it leaves, and why.
	Install []Planned `json:"install"`
	Skip    []Skipped `json:"skip,omitempty"`
}

// Planned is one update the autopilot would install.
type Planned struct {
	Name string `json:"name"`
	Arch string `json:"arch"`
	From string `json:"from,omitempty"` // empty for a new package
	// To can be older than the package manager's candidate:
	// unattended-upgrades takes the newest version from an allowed
	// origin.
	To       string `json:"to"`
	Security bool   `json:"security"`
}

// Skipped is one pending update the autopilot leaves.
type Skipped struct {
	Name      string `json:"name"`
	Arch      string `json:"arch"`
	Candidate string `json:"candidate"`
	Reason    string `json:"reason"`
}

// Paths the autopilot reader checks. Variables for tests.
var (
	unattendedUpgradeBin = "/usr/bin/unattended-upgrade"
	dnfAutomaticBin      = "/usr/bin/dnf-automatic"
	dnfAutomaticConf     = "/etc/dnf/automatic.conf"
	dnfConf              = "/etc/dnf/dnf.conf"
)

// PredictAutopilot reads the host's automatic updater and sets
// r.Autopilot. distroID ("Ubuntu", "Debian") and codename ("noble")
// expand unattended-upgrades' ${distro_id} and ${distro_codename}.
func PredictAutopilot(ctx context.Context, r *Report, distroID, codename string) error {
	return predictAutopilot(ctx, hostexec.Run, r, distroID, codename)
}

func predictAutopilot(ctx context.Context, run runner, r *Report, distroID, codename string) error {
	timers, err := run(ctx, hostexec.SystemctlShowUpdaterTimers)
	if err != nil {
		return err
	}
	ts := parseTimers(timers.Stdout)
	switch r.Manager {
	case "apt":
		a := &Autopilot{Tool: "unattended-upgrades", Installed: exists(unattendedUpgradeBin)}
		if !a.Installed {
			a.Why = []string{"unattended-upgrades is not installed"}
			r.Autopilot = a
			return nil
		}
		cfg, err := run(ctx, hostexec.AptConfigDump)
		if err != nil {
			return err
		}
		global, err := run(ctx, hostexec.AptCachePolicy)
		if err != nil {
			return err
		}
		r.Autopilot = predictUnattended(r, parseAptConfig(cfg.Stdout), parseReleases(global.Stdout), ts, distroID, codename)
	case "dnf":
		a := &Autopilot{Tool: "dnf-automatic", Installed: exists(dnfAutomaticBin)}
		if !a.Installed {
			a.Why = []string{"dnf-automatic is not installed"}
			r.Autopilot = a
			return nil
		}
		conf, _ := os.ReadFile(dnfAutomaticConf)
		main, _ := os.ReadFile(dnfConf)
		r.Autopilot = predictDnfAutomatic(r, parseINI(conf), parseINI(main), ts)
	}
	return nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// timer is one timer from SystemctlShowUpdaterTimers.
type timer struct {
	ID, LoadState, UnitFileState, ActiveState string
	Next, Last                                time.Time
}

// active reports whether the timer will fire.
func (t timer) active() bool { return t.LoadState == "loaded" && t.ActiveState == "active" }

// state says why a timer will not fire.
func (t timer) state() string {
	switch {
	case t.ID == "" || t.LoadState == "not-found":
		return "not installed"
	case t.LoadState == "masked" || t.UnitFileState == "masked":
		return "masked"
	case t.ActiveState != "active":
		return t.ActiveState + " (" + t.UnitFileState + ")"
	}
	return "active"
}

// timeLayout parses "Sat 2026-10-17 10:08:39 UTC" with or without
// microseconds; hostexec runs systemctl with TZ=UTC.
const timeLayout = "Mon 2006-01-02 15:04:05 MST"

func parseTimers(b []byte) map[string]timer {
	out := map[string]timer{}
	for _, kv := range keyValueBlocks(b) {
		t := timer{ID: kv["Id"], LoadState: kv["LoadState"], UnitFileState: kv["UnitFileState"], ActiveState: kv["ActiveState"]}
		t.Next, _ = time.Parse(timeLayout, kv["NextElapseUSecRealtime"])
		t.Last, _ = time.Parse(timeLayout, kv["LastTriggerUSec"])
		if !t.Next.IsZero() {
			t.Next = t.Next.UTC()
		}
		if !t.Last.IsZero() {
			t.Last = t.Last.UTC()
		}
		out[t.ID] = t
	}
	return out
}

// keyValueBlocks splits systemctl show output into one map per unit.
func keyValueBlocks(b []byte) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			cur[k] = v
		}
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}
