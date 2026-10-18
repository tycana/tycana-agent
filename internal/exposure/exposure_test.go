package exposure

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"tycana.ai/agent/internal/restart"
	"tycana.ai/agent/internal/sockdiag"
)

// fakeHost is a Debian-like root with a merged /usr, dpkg lists, a
// setuid program, and /proc entries for two main processes.
func fakeHost(t *testing.T) (root, proc string) {
	t.Helper()
	root, proc = t.TempDir(), t.TempDir()
	write := func(p, data string, mode os.FileMode) {
		t.Helper()
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(full, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("usr/bin/perl", "not an ELF", 0o755)
	write("usr/lib/x86_64-linux-gnu/libc.so.6", "x", 0o755)
	write("usr/lib/postgresql/16/bin/postgres", "not an ELF", 0o755)
	write("usr/bin/pg_ctlcluster", "#!/usr/bin/perl\n", 0o755)
	write("usr/sbin/sshd", "x", 0o755)
	write("usr/opt-tool", "x", 0o755)
	write("usr/bin/sudo", "x", 0o755|os.ModeSetuid)
	write("usr/sbin/firewalld", "#!/usr/bin/perl\n", 0o755)
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	info := "var/lib/dpkg/info/"
	write(info+"perl-base.list", "/.\n/usr\n/usr/bin\n/usr/bin/perl\n", 0o644)
	write(info+"libc6:amd64.list", "/.\n/lib\n/lib/x86_64-linux-gnu\n/lib/x86_64-linux-gnu/libc.so.6\n", 0o644)
	write(info+"postgresql-16.list", "/usr/lib/postgresql/16/bin/postgres\n", 0o644)
	write(info+"postgresql-common.list", "/usr/bin/pg_ctlcluster\n", 0o644)
	write(info+"openssh-server.list", "/usr/sbin/sshd\n", 0o644)
	write(info+"sudo.list", "/usr/bin/sudo\n", 0o644)
	write(info+"firewalld.list", "/usr/sbin/firewalld\n", 0o644)
	cmd := func(pid, data string) {
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, pid, "cmdline"), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd("100", "/usr/lib/postgresql/16/bin/postgres\x00-D\x00/var/lib/postgresql/16/main\x00--password=secret\x00")
	cmd("200", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups")
	cmd("300", "/usr/opt-tool\x00")
	cmd("400", "/usr/bin/perl\x00/usr/sbin/firewalld\x00--nofork\x00")
	return root, proc
}

func snapshot() restart.Snapshot {
	return restart.Snapshot{
		Units: []restart.Unit{
			{ID: "postgresql@16-main.service", MainPID: 100, Exec: "/usr/bin/pg_ctlcluster"},
			{ID: "ssh.service", MainPID: 200, Exec: "/usr/sbin/sshd"},
			{ID: "opt.service", MainPID: 300, Exec: "/usr/opt-tool"},
			{ID: "session-3.scope", Service: "sshd"},
			{ID: "firewalld.service", MainPID: 400, Exec: "/usr/sbin/firewalld"},
		},
		Programs: map[string]restart.Program{
			"/usr/bin/pg_ctlcluster": {Path: "/usr/bin/pg_ctlcluster", Interpreter: "/usr/bin/perl",
				Closure: []string{"/usr/bin/perl", "/usr/lib/x86_64-linux-gnu/libc.so.6"}},
			"/usr/sbin/sshd": {Path: "/usr/sbin/sshd", Closure: []string{"/usr/sbin/sshd", "/usr/lib/x86_64-linux-gnu/libc.so.6"}},
			"/usr/opt-tool":  {Path: "/usr/opt-tool", Closure: []string{"/usr/opt-tool", "/usr/lib/x86_64-linux-gnu/libc.so.6"}},
			"/usr/sbin/firewalld": {Path: "/usr/sbin/firewalld", Interpreter: "/usr/bin/perl",
				Closure: []string{"/usr/bin/perl", "/usr/lib/x86_64-linux-gnu/libc.so.6"}},
		},
		SSHProgram: "/usr/sbin/sshd",
	}
}

func TestCollect(t *testing.T) {
	root, proc := fakeHost(t)
	h := Host{
		Root: root, Proc: proc, Format: "deb",
		Sockets: func() ([]sockdiag.Socket, error) {
			return []sockdiag.Socket{
				{Proto: "tcp", Addr: netip.MustParseAddr("::"), Port: 22, CgroupID: 1},
				{Proto: "tcp", Addr: netip.MustParseAddr("127.0.0.1"), Port: 5432, CgroupID: 2},
				{Proto: "tcp", Addr: netip.MustParseAddr("127.0.0.1"), Port: 5432, CgroupID: 2}, // SO_REUSEPORT twin
				{Proto: "udp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 111, CgroupID: 3},
				{Proto: "udp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 68, CgroupID: 99},
			}, nil
		},
		Cgroups: func() (map[uint64]string, error) {
			return map[uint64]string{
				1: "/system.slice/ssh.socket",
				2: "/system.slice/system-postgresql.slice/postgresql@16-main.service",
				3: "/system.slice/rpcbind.socket",
			}, nil
		},
		Triggers: func(_ context.Context, s []string) (map[string][]string, error) {
			if !slices.Equal(s, []string{"rpcbind.socket", "ssh.socket"}) {
				t.Errorf("triggers asked for %q", s)
			}
			return map[string][]string{"ssh.socket": {"ssh.service"}, "rpcbind.socket": {"rpcbind.service"}}, nil
		},
	}
	rep := Collect(context.Background(), h, snapshot(), time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC))
	if len(rep.Errors) != 0 || !rep.Sockets.Read || rep.Sockets.Count != 5 {
		t.Fatalf("errors %q, sockets %+v", rep.Errors, rep.Sockets)
	}
	units := map[string]Unit{}
	for _, u := range rep.Units {
		units[u.ID] = u
	}

	// The perl wrapper: the main process is postgres, so perl is not in
	// use and the unit is not an interpreter (ADR 0032 item 3).
	pg := units["postgresql@16-main.service"]
	if pg.Main == nil || pg.Main.Path != "/usr/lib/postgresql/16/bin/postgres" || pg.Main.Package != "postgresql-16" {
		t.Errorf("postgres main %+v", pg.Main)
	}
	if !slices.Equal(pg.Packages, []string{"postgresql-16"}) || pg.Interpreter != "" {
		t.Errorf("postgres packages %q interpreter %q", pg.Packages, pg.Interpreter)
	}
	if len(pg.Listen) != 1 || pg.Listen[0].Port != 5432 || !pg.Listen[0].Loopback || pg.Listen[0].Via != "" {
		t.Errorf("postgres listen %+v", pg.Listen)
	}

	// A rewritten process title names no file; the start program counts.
	ssh := units["ssh.service"]
	if ssh.Main != nil || !slices.Equal(ssh.Packages, []string{"libc6", "openssh-server"}) {
		t.Errorf("ssh main %+v packages %q", ssh.Main, ssh.Packages)
	}
	if len(ssh.Listen) != 1 || ssh.Listen[0].Via != "ssh.socket" || ssh.Listen[0].Loopback || ssh.Listen[0].Addr != "::" {
		t.Errorf("ssh listen %+v", ssh.Listen)
	}
	if s := units["session-3.scope"]; s.Program != "/usr/sbin/sshd" || s.Main != nil {
		t.Errorf("session %+v", s)
	}

	// A script whose main process is its interpreter: the script's
	// package and the interpreter's both count, and the unit is an
	// interpreter service.
	fw := units["firewalld.service"]
	if fw.Interpreter != "/usr/bin/perl" || fw.Main == nil || fw.Main.Package != "perl-base" ||
		!slices.Equal(fw.Packages, []string{"firewalld", "libc6", "perl-base"}) {
		t.Errorf("firewalld %+v", fw)
	}

	// A main program no package owns is not kept; the unowned file is
	// counted.
	opt := units["opt.service"]
	if opt.Main != nil || opt.UnownedCount != 1 || opt.Unowned[0] != "/usr/opt-tool" {
		t.Errorf("opt %+v", opt)
	}

	// rpcbind.service is not running: its socket stays unattributed with
	// the socket unit's triggers; the DHCP client's cgroup is unknown.
	if len(rep.Unattributed) != 2 || rep.Unattributed[0].Port != 68 || rep.Unattributed[1].Triggers[0] != "rpcbind.service" {
		t.Errorf("unattributed %+v", rep.Unattributed)
	}
	if len(rep.Setuid) != 1 || rep.Setuid[0] != (SetuidFile{Path: "/usr/bin/sudo", Package: "sudo", Mode: "4755"}) {
		t.Errorf("setuid %+v", rep.Setuid)
	}
}

// Nothing of a command line but argv[0] leaves mainProgram, and argv[0]
// only when it names a regular file by a clean absolute path.
func TestMainProgram(t *testing.T) {
	root, proc := fakeHost(t)
	r := restart.NewResolver(root)
	a, c, ok := mainProgram(proc, r, 100)
	if !ok || a != "/usr/lib/postgresql/16/bin/postgres" || c != a || strings.Contains(a+c, "secret") {
		t.Errorf("got %q %q %v", a, c, ok)
	}
	put := func(pid, data string) {
		_ = os.MkdirAll(filepath.Join(proc, pid), 0o755)
		_ = os.WriteFile(filepath.Join(proc, pid, "cmdline"), []byte(data), 0o644)
	}
	put("1", "/usr/bin/../bin/perl\x00")
	put("2", "perl\x00")
	put("3", "/usr/bin\x00")
	put("4", "/usr/bin/nonexistent\x00")
	put("5", "/lib/x86_64-linux-gnu/libc.so.6\x00")
	for _, pid := range []int{0, 1, 2, 3, 4, 200, 9999} {
		if a, _, ok := mainProgram(proc, r, pid); ok {
			t.Errorf("pid %d: %q accepted", pid, a)
		}
	}
	if a, c, ok := mainProgram(proc, r, 5); !ok || a != "/lib/x86_64-linux-gnu/libc.so.6" || c != "/usr/lib/x86_64-linux-gnu/libc.so.6" {
		t.Errorf("symlinked directory: %q %q %v", a, c, ok)
	}
}

func TestSocketsNotRead(t *testing.T) {
	root, proc := fakeHost(t)
	h := Host{Root: root, Proc: proc, Format: "deb", Sockets: func() ([]sockdiag.Socket, error) {
		return nil, errors.New("sock_diag: address family not supported by protocol")
	}}
	rep := Collect(context.Background(), h, snapshot(), time.Now())
	if rep.Sockets.Read || !strings.Contains(rep.Sockets.Error, "not supported") {
		t.Errorf("sockets %+v", rep.Sockets)
	}
	for _, u := range rep.Units {
		if len(u.Listen) > 0 {
			t.Errorf("%s has sockets", u.ID)
		}
	}
	if rep := Collect(context.Background(), Host{Root: root, Proc: proc, Format: "pkg"}, snapshot(), time.Now()); len(rep.Errors) == 0 {
		t.Error("an unknown package format must be an error")
	}
}

func TestParseTriggers(t *testing.T) {
	got := ParseTriggers([]byte("Triggers=ssh.service\nId=ssh.socket\n\nId=rpcbind.socket\nTriggers=rpcbind.service other.service\n"))
	if !slices.Equal(got["ssh.socket"], []string{"ssh.service"}) || len(got["rpcbind.socket"]) != 2 {
		t.Errorf("%q", got)
	}
}

func TestInterpreterName(t *testing.T) {
	for _, ok := range []string{"perl", "perl5.36.0", "python3", "python3.12", "bash", "dash", "sh", "java", "node", "ruby3.2"} {
		if !interpreterName.MatchString(ok) {
			t.Errorf("%s", ok)
		}
	}
	for _, bad := range []string{"postgres", "sshd", "nginx", "php-fpm8.3", "shellcheck", "javac"} {
		if interpreterName.MatchString(bad) {
			t.Errorf("%s matched", bad)
		}
	}
}
