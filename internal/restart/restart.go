// Package restart infers which running services still use a program or
// library that has been replaced on disk since they started, without
// privilege.
//
// The agent cannot read other processes' memory maps (ADR 0009, ADR
// 0019). It reads instead what any unprivileged user can: from systemd,
// each running service's main program and the time its main process
// started; from the ELF files, the objects the loader maps at start; from
// the file system, when each of those files was created. apt, dpkg, rpm
// and dnf install a new file and rename it over the old one, so a file
// created after the service started is one the service cannot be using:
// the service still maps the old, deleted copy.
//
// A finding is therefore "inferred", never "observed". Libraries opened
// later with dlopen are outside the closure. For the common kinds (NSS
// modules named in nsswitch.conf, PAM modules, OpenSSL providers and
// engines, SASL and gconv modules, Apache and nginx modules) the agent
// lists the module files, and the files of the modules' own closures,
// replaced since the earliest unit started. A unit that links the host
// library, or is the host program, becomes "possible" rather than "none".
// Interpreter modules are outside its view: a script's unit is "unknown".
package restart

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// Status is the verdict for one unit.
type Status string

const (
	// Inferred means a file the unit's program maps at start was created
	// after the unit started.
	Inferred Status = "inferred"
	// Possible means the closure is older than the unit, but a run-time
	// module its host library can load was replaced after the unit
	// started (Finding.Modules). Only root can tell whether the unit
	// loaded it.
	Possible Status = "possible"
	// None means every file in the closure, and every run-time module of
	// the listed kinds, is older than the unit. Other libraries loaded
	// later are not checked.
	None Status = "none"
	// Unknown means the agent cannot tell (see Finding.Reason).
	Unknown Status = "unknown"
)

// Snapshot is everything the analysis reads, collected from the host.
// It is the unit of test fixtures.
type Snapshot struct {
	Collected time.Time `json:"collected"`
	BootID    string    `json:"boot_id,omitempty"`
	Units     []Unit    `json:"units"`
	// Programs maps each unit's Exec path to its closure.
	Programs map[string]Program `json:"programs"`
	// Files maps each canonical path in a closure to its creation time.
	Files map[string]FileTime `json:"files"`
	// Modules lists run-time modules created after the earliest unit
	// started.
	Modules []Module `json:"modules,omitempty"`
	// Packages is when each installed package last changed (dpkg's info
	// files, rpm's install times). With it, a unit is "none" only when no
	// package changed after it started. Snapshots from before 2026-10-16
	// have none.
	Packages []PackageChange `json:"packages,omitempty"`
	// SSHProgram is the program an sshd login session runs: sshd itself,
	// or sshd-session from OpenSSH 9.8. Its closure is in Programs.
	SSHProgram string `json:"ssh_program,omitempty"`
}

// FileTime is when a file came into existence on this host.
type FileTime struct {
	Time time.Time `json:"time"`
	// Source is "birth" (statx btime) or "change" (ctime, when the file
	// system does not record birth; also moves on chmod and chown).
	Source string `json:"source"`
	Error  string `json:"error,omitempty"`
}

// Finding is the verdict for one unit.
type Finding struct {
	Unit    string    `json:"unit"`
	MainPID int       `json:"main_pid,omitempty"`
	Start   time.Time `json:"start"`
	Program string    `json:"program,omitempty"`
	Status  Status    `json:"status"`
	// Reason explains Unknown, and qualifies the other states.
	Reason string `json:"reason,omitempty"`
	// Replaced lists the closure files created after Start.
	Replaced []Replaced `json:"replaced,omitempty"`
	// Modules lists the run-time modules behind a Possible verdict.
	Modules []Replaced `json:"modules,omitempty"`
	// Changed names packages that changed after the unit started, at most
	// maxChanged of ChangedCount.
	Changed      []string `json:"changed_packages,omitempty"`
	ChangedCount int      `json:"changed_count,omitempty"`
}

// maxChanged bounds the package names listed for one unit.
const maxChanged = 20

// Replaced is one file a unit maps that has been replaced since.
type Replaced struct {
	Path    string    `json:"path"`
	Created time.Time `json:"created"`
}

// Report is the result for a host.
type Report struct {
	Collected time.Time `json:"collected"`
	Findings  []Finding `json:"findings"`
}

// Analyze compares each unit's start with the creation times of the files
// its program maps at start.
func Analyze(s Snapshot) Report {
	r := Report{Collected: s.Collected, Findings: []Finding{}}
	for _, u := range s.Units {
		f := Finding{Unit: u.ID, MainPID: u.MainPID, Start: u.Start}
		exec := u.Exec
		switch {
		case u.ID == "init.scope":
			f.Status, f.Reason = Unknown, "PID 1 re-executes itself only when systemd is updated; its start time does not show that"
		case strings.HasSuffix(u.ID, ".scope") && u.Service == "sshd" && s.SSHProgram != "":
			exec = s.SSHProgram
			f.Reason = "an sshd login session; sshd starts this program for each connection"
		case strings.HasSuffix(u.ID, ".scope") && u.Service != "":
			f.Status, f.Reason = Unknown, "a login session of PAM service "+quote(u.Service)+"; its programs are not visible without privilege"
		case strings.HasSuffix(u.ID, ".scope"):
			f.Status, f.Reason = Unknown, "a scope; its programs are not visible without privilege"
		case u.MainPID == 0:
			f.Status, f.Reason = Unknown, "no main process"
		case exec == "":
			f.Status, f.Reason = Unknown, "no ExecStart= program"
		}
		if f.Status == "" && u.Start.IsZero() {
			f.Status, f.Reason = Unknown, "no start time"
		}
		if f.Status == "" {
			judge(&f, u.Start, s.Programs[exec], s.Files)
		}
		if f.Status == None {
			possible(&f, u.Start, s.Programs[exec], s.Modules)
		}
		if len(s.Packages) > 0 {
			packageRule(&f, u.Start, s.Packages)
		}
		f.Program = exec
		r.Findings = append(r.Findings, f)
	}
	slices.SortFunc(r.Findings, func(a, b Finding) int { return strings.Compare(a.Unit, b.Unit) })
	return r
}

func judge(f *Finding, start time.Time, p Program, files map[string]FileTime) {
	if p.Path == "" {
		f.Status, f.Reason = Unknown, join(f.Reason, "program not readable: "+p.Error)
		return
	}
	var missing []string
	for _, c := range p.Closure {
		ft, ok := files[c]
		if !ok || ft.Error != "" || ft.Time.IsZero() {
			missing = append(missing, c)
			continue
		}
		if ft.Time.After(start) {
			f.Replaced = append(f.Replaced, Replaced{Path: c, Created: ft.Time})
		}
	}
	switch {
	case len(f.Replaced) > 0:
		f.Status = Inferred
	case p.Interpreter != "":
		f.Status = Unknown
		f.Reason = join(f.Reason, "a script run by "+p.Interpreter+"; the programs it starts and the modules it loads are not checked")
	case p.Error != "" || len(p.Unresolved) > 0 || len(missing) > 0:
		f.Status = Unknown
		f.Reason = join(f.Reason, incomplete(p, missing))
	default:
		f.Status = None
	}
}

// packageRule bounds every verdict by the package changes, with no list
// of applications (ADR 0020): a unit that started after the last change of
// every package cannot use a replaced file ("none"); a unit that started
// before some change may ("possible"), unless its closure already proves
// it does ("inferred"). Only a unit without a start time stays "unknown".
func packageRule(f *Finding, start time.Time, pkgs []PackageChange) {
	if start.IsZero() || f.Status == Inferred {
		return
	}
	var changed []PackageChange
	for _, c := range pkgs {
		if c.after(start) {
			changed = append(changed, c)
		}
	}
	if len(changed) == 0 {
		if f.Status != Possible { // module files replaced outside the package manager still count
			f.Status, f.Reason = None, "no package changed after it started"
		}
		return
	}
	slices.SortFunc(changed, func(a, b PackageChange) int { return b.Changed.Compare(a.Changed) })
	f.ChangedCount = len(changed)
	for _, c := range changed[:min(len(changed), maxChanged)] {
		f.Changed = append(f.Changed, c.Name)
	}
	f.Status = Possible
	f.Reason = join(f.Reason, fmt.Sprintf("%d packages changed after it started; it may use them", len(changed)))
}

// possible marks a unit whose closure is clean but whose host libraries
// can load a module replaced after it started.
func possible(f *Finding, start time.Time, p Program, mods []Module) {
	kinds := map[string]bool{}
	for _, m := range mods {
		hosted := slices.Contains(p.Sonames, m.Host) || m.Host == p.Path
		if !hosted || !m.Created.After(start) {
			continue
		}
		if !slices.ContainsFunc(f.Modules, func(r Replaced) bool { return r.Path == m.Path }) {
			f.Modules = append(f.Modules, Replaced{Path: m.Path, Created: m.Created})
		}
		kinds[m.Kind] = true
	}
	if len(f.Modules) > 0 {
		f.Status = Possible
		ks := slices.Sorted(maps.Keys(kinds))
		f.Reason = join(f.Reason, "it can load "+strings.Join(ks, ", ")+" modules replaced since it started; only root can see whether it did")
	}
}

func incomplete(p Program, missing []string) string {
	var parts []string
	if p.Error != "" {
		parts = append(parts, p.Error)
	}
	if len(p.Unresolved) > 0 {
		parts = append(parts, "libraries not found: "+strings.Join(p.Unresolved, ", "))
	}
	if len(missing) > 0 {
		parts = append(parts, "no file time for: "+strings.Join(missing, ", "))
	}
	return "closure incomplete: " + strings.Join(parts, "; ")
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

func quote(s string) string { return `"` + s + `"` }
