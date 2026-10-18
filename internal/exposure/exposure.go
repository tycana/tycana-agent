// Package exposure records, for each running unit, what the matcher needs
// to order a host's actions by how the software is used (tycana-hq ADR
// 0029, ADR 0032): the addresses and ports it listens on, the packages of
// the code it runs, its main program, and whether that program is an
// interpreter; and for the host, the packages that own a setuid file.
//
// It needs no privilege. The sockets and their cgroups come from the
// kernel's socket diagnostics (sock_diag), which every user can read;
// the main program from argv[0] of the unit's main process, which every
// user can read on a host without hidepid; the packages from the package
// database and the start-time ELF closures of the restart collector.
// Code loaded after start (dlopen, interpreter modules) is not seen, so
// the packages are a lower bound.
package exposure

import (
	"context"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"tycana.ai/agent/internal/restart"
	"tycana.ai/agent/internal/sockdiag"
)

// Report is the exposure part of a host-assessment record.
type Report struct {
	Collected time.Time `json:"collected"`
	// Sockets says whether the socket list was read. When it was not,
	// no unit has a Listen list, and the reason is in Error.
	Sockets SocketsRead `json:"sockets"`
	Units   []Unit      `json:"units"`
	// Unattributed are listening sockets that belong to no running unit
	// (PID 1, a socket unit whose service is not running, or a cgroup the
	// walk did not find).
	Unattributed []Listen     `json:"unattributed,omitempty"`
	Setuid       []SetuidFile `json:"setuid"`
	// PackageFiles is how many packaged paths the owner pass read.
	PackageFiles int      `json:"package_files"`
	Errors       []string `json:"errors,omitempty"`
}

// SocketsRead is the state of the socket read.
type SocketsRead struct {
	Read  bool   `json:"read"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

// Unit is one running service or scope.
type Unit struct {
	ID string `json:"id"`
	// Program is the start program (the first ExecStart=, or sshd's
	// session program for an sshd login scope).
	Program string `json:"program,omitempty"`
	// Main is the main process's program, from its command line.
	Main *MainProgram `json:"main,omitempty"`
	// Interpreter is the canonical path of the interpreter the unit runs
	// (Perl, Python, a shell, Java, ...): the agent sees it, not the
	// programs and modules it loads.
	Interpreter string `json:"interpreter,omitempty"`
	// Packages own the files of the code the unit maps at start: the
	// start program's closure (with the script itself, for a script)
	// joined with the main program's, except that a start script and its
	// interpreter are dropped when the main process is another packaged
	// program (ADR 0032 item 3).
	Packages []string `json:"packages"`
	// Unowned are closure files no package owns, at most maxUnowned of
	// UnownedCount.
	Unowned      []string `json:"unowned,omitempty"`
	UnownedCount int      `json:"unowned_count,omitempty"`
	// Incomplete says why the closure is not complete.
	Incomplete string   `json:"incomplete,omitempty"`
	Listen     []Listen `json:"listen,omitempty"`
}

// MainProgram is argv[0] of the main process when it is an absolute path
// to a regular file that a package owns. A process sets its own command
// line: this is what the service reports, not proof.
type MainProgram struct {
	Path     string `json:"path"`
	Resolved string `json:"resolved,omitempty"`
	Package  string `json:"package"`
	Source   string `json:"source"`
}

// Listen is one listening socket.
type Listen struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Port  uint16 `json:"port"`
	// Loopback is true when only the host itself can reach it.
	Loopback bool `json:"loopback"`
	// Via is the socket unit that holds the socket for this unit.
	Via string `json:"via,omitempty"`
	// Cgroup is set on an unattributed socket.
	Cgroup string `json:"cgroup,omitempty"`
	// Triggers are the units of a socket unit whose service is not
	// running.
	Triggers []string `json:"triggers,omitempty"`
}

const maxUnowned = 20

// interpreterName matches the base names of interpreter programs. An
// unversioned or versioned name ("python3", "python3.12", "perl5.36.0").
var interpreterName = regexp.MustCompile(`^(perl|python|sh|bash|dash|ksh|mksh|zsh|java|ruby|node|nodejs|php|lua|tclsh)[0-9.]*$`)

// work is one unit while the report is built.
type work struct {
	unit    Unit
	closure []string
	main    *restart.Program
}

// Host is where the collector reads. Production: Root "/", Proc
// "/proc", sockdiag for the sockets and the cgroup tree, and systemctl
// for the triggers of socket units.
type Host struct {
	Root     string
	Proc     string
	Cgroups  func() (map[uint64]string, error)
	Format   string // "deb" or "rpm", from the inventory
	RPMDir   string
	Sockets  func() ([]sockdiag.Socket, error)
	Triggers func(ctx context.Context, sockets []string) (map[string][]string, error)
}

// Collect builds the report from the restart snapshot of the same cycle.
func Collect(ctx context.Context, h Host, snap restart.Snapshot, now time.Time) *Report {
	rep := &Report{Collected: now.UTC(), Units: []Unit{}, Setuid: []SetuidFile{}}
	r := restart.NewResolver(h.Root)
	fail := func(what string, err error) { rep.Errors = append(rep.Errors, what+": "+err.Error()) }

	units := make([]work, 0, len(snap.Units))
	want := map[string]bool{}
	for _, u := range snap.Units {
		w := work{unit: Unit{ID: u.ID, Packages: []string{}}}
		exec := u.Exec
		if strings.HasSuffix(u.ID, ".scope") {
			exec = ""
			if u.Service == "sshd" {
				exec = snap.SSHProgram
			}
		}
		w.unit.Program = exec
		start, hasStart := snap.Programs[exec]
		if exec != "" && hasStart {
			w.closure = slices.Clone(start.Closure)
			if start.Interpreter != "" {
				// The script itself is code the unit runs; its package
				// counts with the interpreter's closure.
				w.unit.Interpreter = start.Interpreter
				w.closure = append(w.closure, start.Path)
			} else if interpreterName.MatchString(path.Base(start.Path)) {
				w.unit.Interpreter = start.Path
			}
			if s := incomplete(start); s != "" {
				w.unit.Incomplete = s
			}
		}
		if argv0, canon, ok := mainProgram(h.Proc, r, u.MainPID); ok && !strings.HasSuffix(u.ID, ".scope") {
			mp := MainProgram{Path: argv0, Source: "command line of the main process"}
			if canon != argv0 {
				mp.Resolved = canon
			}
			w.unit.Main = &mp
			want[canon] = true
			if canon != start.Path && canon != start.Interpreter {
				p := r.Program(canon)
				if !slices.Contains(p.Closure, canon) {
					p.Closure = append([]string{canon}, p.Closure...)
				}
				w.main = &p
			}
		}
		for _, c := range w.closure {
			want[c] = true
		}
		if w.main != nil {
			for _, c := range w.main.Closure {
				want[c] = true
			}
		}
		units = append(units, w)
	}

	own, err := readOwners(r, h.Format, h.RPMDir, want)
	if err != nil {
		fail("packages", err)
	}
	rep.Setuid, rep.PackageFiles = own.setuid, own.files

	for i := range units {
		w := &units[i]
		u := &w.unit
		if u.Main != nil {
			canon := u.Main.Path
			if u.Main.Resolved != "" {
				canon = u.Main.Resolved
			}
			pk := own.of[canon]
			if len(pk) == 0 {
				// ADR 0032: kept only when a package owns it.
				u.Main, w.main = nil, nil
			} else {
				u.Main.Package = pk[0]
			}
		}
		if w.main != nil {
			if u.Interpreter != "" && u.Interpreter == startInterpreter(snap, u.Program) {
				// The start program is a script, and its main process is
				// another packaged program: the script's interpreter has
				// exited (the pg_ctlcluster case). The unit runs the main
				// program.
				w.closure = nil
				u.Interpreter = ""
			}
			switch {
			case w.main.Interpreter != "":
				u.Interpreter = w.main.Interpreter
			case interpreterName.MatchString(path.Base(w.main.Path)):
				u.Interpreter = w.main.Path
			}
			w.closure = append(w.closure, w.main.Closure...)
			if s := incomplete(*w.main); s != "" && u.Incomplete == "" {
				u.Incomplete = s
			}
		}
		seen := map[string]bool{}
		for _, c := range w.closure {
			if seen[c] {
				continue
			}
			seen[c] = true
			pk := own.of[c]
			if len(pk) == 0 {
				u.UnownedCount++
				if len(u.Unowned) < maxUnowned {
					u.Unowned = append(u.Unowned, c)
				}
			}
			for _, p := range pk {
				if !slices.Contains(u.Packages, p) {
					u.Packages = append(u.Packages, p)
				}
			}
		}
		slices.Sort(u.Packages)
	}

	listen(ctx, h, rep, units, fail)
	for _, w := range units {
		rep.Units = append(rep.Units, w.unit)
	}
	slices.SortFunc(rep.Units, func(a, b Unit) int { return compare(a.ID, b.ID) })
	return rep
}

// startInterpreter is the interpreter of the unit's start program, when
// it is a script.
func startInterpreter(snap restart.Snapshot, exec string) string {
	return snap.Programs[exec].Interpreter
}

func incomplete(p restart.Program) string {
	var parts []string
	if p.Error != "" {
		parts = append(parts, p.Error)
	}
	if len(p.Unresolved) > 0 {
		parts = append(parts, "libraries not found: "+strings.Join(p.Unresolved, ", "))
	}
	return strings.Join(parts, "; ")
}

// listen gives each running unit its listening sockets. A socket that
// systemd holds for a socket unit carries the socket unit's cgroup; the
// units in its Triggers= get it, with Via set.
func listen(ctx context.Context, h Host, rep *Report, units []work, fail func(string, error)) {
	if h.Sockets == nil {
		rep.Sockets.Error = "not read"
		return
	}
	socks, err := h.Sockets()
	if err != nil {
		rep.Sockets.Error = err.Error()
		return
	}
	rep.Sockets.Read, rep.Sockets.Count = true, len(socks)
	var ids map[uint64]string
	if h.Cgroups != nil {
		if ids, err = h.Cgroups(); err != nil {
			fail("cgroups", err)
		}
	}
	byUnit := map[string]int{}
	for i, w := range units {
		byUnit[w.unit.ID] = i
	}
	type owned struct {
		s        sockdiag.Socket
		cg, unit string
	}
	var list []owned
	var socketUnits []string
	for _, s := range socks {
		cg := ids[s.CgroupID]
		u := sockdiag.UnitOf(cg)
		list = append(list, owned{s, cg, u})
		if strings.HasSuffix(u, ".socket") && !slices.Contains(socketUnits, u) {
			socketUnits = append(socketUnits, u)
		}
	}
	triggers := map[string][]string{}
	if len(socketUnits) > 0 && h.Triggers != nil {
		slices.Sort(socketUnits)
		if triggers, err = h.Triggers(ctx, socketUnits); err != nil {
			fail("socket units", err)
		}
	}
	for _, o := range list {
		l := Listen{Proto: o.s.Proto, Addr: o.s.Addr.String(), Port: o.s.Port, Loopback: o.s.Loopback()}
		targets, via := []string{o.unit}, ""
		if strings.HasSuffix(o.unit, ".socket") {
			targets, via = triggers[o.unit], o.unit
		}
		done := false
		for _, t := range targets {
			i, ok := byUnit[t]
			if !ok {
				continue
			}
			lt := l
			lt.Via = via
			if !slices.ContainsFunc(units[i].unit.Listen, func(x Listen) bool {
				return x.Proto == lt.Proto && x.Addr == lt.Addr && x.Port == lt.Port && x.Via == lt.Via
			}) {
				units[i].unit.Listen = append(units[i].unit.Listen, lt)
			}
			done = true
		}
		if done {
			continue
		}
		l.Cgroup = o.cg
		if via != "" {
			l.Triggers = targets
		}
		if !slices.ContainsFunc(rep.Unattributed, func(x Listen) bool {
			return x.Proto == l.Proto && x.Addr == l.Addr && x.Port == l.Port && x.Cgroup == l.Cgroup
		}) {
			rep.Unattributed = append(rep.Unattributed, l)
		}
	}
	for i := range units {
		slices.SortFunc(units[i].unit.Listen, lessListen)
	}
	slices.SortFunc(rep.Unattributed, lessListen)
}

func lessListen(a, b Listen) int {
	if a.Port != b.Port {
		return int(a.Port) - int(b.Port)
	}
	if c := compare(a.Proto, b.Proto); c != 0 {
		return c
	}
	return compare(a.Addr, b.Addr)
}

// ParseTriggers reads "systemctl show --property=Id,Triggers" output:
// blocks of Key=Value lines, in systemd's order, separated by blank
// lines.
func ParseTriggers(b []byte) map[string][]string {
	out := map[string][]string{}
	id, trig := "", []string(nil)
	flush := func() {
		if id != "" {
			out[id] = trig
		}
		id, trig = "", nil
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch k {
		case "":
			flush()
		case "Id":
			id = v
		case "Triggers":
			trig = strings.Fields(v)
		}
	}
	flush()
	return out
}
