package sockdiag

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
)

func TestUnitOf(t *testing.T) {
	for cg, want := range map[string]string{
		"/system.slice/ssh.socket": "ssh.socket",
		"/system.slice/system-postgresql.slice/postgresql@16-main.service":  "postgresql@16-main.service",
		"/user.slice/user-1000.slice/user@1000.service/app.slice/x.service": "user@1000.service",
		"/init.scope":   "init.scope",
		"/":             "",
		"/system.slice": "",
	} {
		if got := UnitOf(cg); got != want {
			t.Errorf("%s: %q, want %q", cg, got, want)
		}
	}
}

// The cgroup of a socket this test opens is the test's own cgroup.
func TestCgroupPathsLive(t *testing.T) {
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(self), "0::") {
		t.Skip("no cgroup v2")
	}
	want := strings.TrimSpace(strings.TrimPrefix(string(self), "0::"))
	ids, err := CgroupPaths("/sys/fs/cgroup")
	if err != nil {
		t.Skip(err)
	}
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = l.Close() }()
	socks, err := Listening()
	if err != nil {
		t.Skip(err)
	}
	port := uint16(l.Addr().(*net.TCPAddr).Port)
	for _, s := range socks {
		if s.Proto == "tcp" && s.Port == port {
			if got := ids[s.CgroupID]; got != want {
				t.Errorf("cgroup %q, want %q", got, want)
			}
			return
		}
	}
	t.Error("socket not found")
}
