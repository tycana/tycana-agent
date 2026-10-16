package restart

import (
	"context"
	"os"
	"strings"
	"time"

	"tycana.ai/agent/internal/filetime"
	"tycana.ai/agent/internal/hostexec"
)

// Collect reads the running units from systemd, the closures of their
// programs, and the creation times of those files.
func Collect(ctx context.Context, now time.Time) (Snapshot, error) {
	s := Snapshot{Collected: now.UTC()}
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		s.BootID = strings.TrimSpace(string(b))
	}
	res, err := hostexec.Run(ctx, hostexec.SystemctlShowRunning)
	if err != nil {
		return s, err
	}
	if s.Units, err = parseShow(res.Stdout); err != nil {
		return s, err
	}
	addSessions(ctx, s.Units)
	r := NewResolver("/")
	s.Programs, s.Files = closures(r, s.Units)
	for _, u := range s.Units {
		if u.Service == "sshd" {
			s.SSHProgram = addProgram(r, sshSessionProgram(r), s.Programs, s.Files)
			break
		}
	}
	return s, nil
}

// sshSessionPrograms are, in order, the programs an sshd connection runs:
// sshd-session (OpenSSH 9.8 and later, Debian and Red Hat paths), else
// sshd itself, which re-executes for each connection.
var sshSessionPrograms = []string{
	"/usr/lib/openssh/sshd-session",
	"/usr/libexec/openssh/sshd-session",
	"/usr/sbin/sshd",
}

func sshSessionProgram(r *Resolver) string {
	for _, p := range sshSessionPrograms {
		if _, err := os.Stat(r.host(p)); err == nil {
			return p
		}
	}
	return ""
}

// addSessions fills in the PAM service of login session scopes. It is
// best effort: a session can end between the two calls, and loginctl then
// fails for all of them. The scopes stay "unknown".
func addSessions(ctx context.Context, units []Unit) {
	var ids []string
	for _, u := range units {
		if id, ok := sessionID(u.ID); ok {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 || !hostexec.Available(hostexec.LoginctlShowSession) {
		return
	}
	res, err := hostexec.Run(ctx, hostexec.LoginctlShowSession, ids...)
	if err != nil {
		return
	}
	svc := parseSessions(res.Stdout)
	for i := range units {
		units[i].Service = svc[units[i].ID]
	}
}

// closures resolves each distinct program once and times every file.
func closures(r *Resolver, units []Unit) (map[string]Program, map[string]FileTime) {
	progs := map[string]Program{}
	files := map[string]FileTime{}
	for _, u := range units {
		addProgram(r, u.Exec, progs, files)
	}
	return progs, files
}

// addProgram resolves the program at exec once and times its files. It
// returns exec, or "" when exec is "".
func addProgram(r *Resolver, exec string, progs map[string]Program, files map[string]FileTime) string {
	if exec == "" {
		return ""
	}
	if _, ok := progs[exec]; ok {
		return exec
	}
	p := r.Program(exec)
	progs[exec] = p
	for _, c := range p.Closure {
		if _, ok := files[c]; !ok {
			files[c] = fileTime(r.host(c))
		}
	}
	return exec
}

// fileTime returns when a file came into existence.
func fileTime(name string) FileTime {
	t, src, err := filetime.Created(name)
	if err != nil {
		return FileTime{Error: err.Error()}
	}
	return FileTime{Time: t, Source: string(src)}
}
