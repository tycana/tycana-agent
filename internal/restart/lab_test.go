package restart

import (
	"bufio"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// labCases replay restart states of lab VMs on 2026-10-16
// (README in each directory) against the root ground truth captured at
// the same moment: the units whose processes mapped a deleted file in
// /proc/<pid>/maps.
//
// want records the measured result for backlog item B1 (the brief on the
// optional scanner). A change here changes what the brief reports.
var labCases = []struct {
	dir    string
	want   map[string]Status
	counts map[Status]int
}{
	{
		// After the VM's own unattended-upgrades run: libraries the
		// services link directly were replaced.
		dir: "ubuntu2404/restart",
		want: map[string]Status{
			"dbus.service":                Inferred,
			"systemd-logind.service":      Inferred,
			"session-4.scope":             Inferred,
			"user@1000.service":           Inferred,
			"unattended-upgrades.service": Unknown, // python3: libsystemd and libudev via modules
			"init.scope":                  Unknown,
		},
		counts: map[Status]int{Inferred: 4, Possible: 0, Unknown: 2, None: 17},
	},
	{
		// Only NSS and PAM modules were replaced: no stale unit links
		// them, so none can be inferred; every stale unit is possible.
		dir: "ubuntu2404/restart-modules",
		want: map[string]Status{
			"dbus.service":           Possible,
			"systemd-logind.service": Possible,
			"rsyslog.service":        Possible,
			"session-4.scope":        Possible,
			"user@1000.service":      Possible,
		},
		counts: map[Status]int{Inferred: 0, Possible: 19, Unknown: 2, None: 3},
	},
	{
		// Debian 12 after its ten pending security updates (libssl3,
		// libpcre2, libexpat1, python3.11, perl-base): libraries nearly
		// every daemon links. PID 1 did not re-execute and is stale.
		dir: "debian12/restart",
		want: map[string]Status{
			"dbus.service":                Inferred,
			"ssh.service":                 Inferred,
			"session-4.scope":             Inferred,
			"systemd-journald.service":    Inferred,
			"systemd-logind.service":      Inferred,
			"systemd-networkd.service":    Inferred,
			"systemd-resolved.service":    Inferred,
			"systemd-timesyncd.service":   Inferred,
			"systemd-udevd.service":       Inferred,
			"unattended-upgrades.service": Inferred, // python3.11 itself was replaced
			"user@1000.service":           Inferred,
			"init.scope":                  Unknown,
		},
		counts: map[Status]int{Inferred: 11, Possible: 0, Unknown: 1, None: 4},
	},
	{
		// AlmaLinux 9 after all 66 pending updates (glibc, systemd,
		// dbus-broker, openssh, pcre2, python3, kernel). The scriptlets
		// re-executed PID 1 and restarted journald, udevd and sshd.
		dir: "alma9/restart",
		want: map[string]Status{
			"NetworkManager.service":     Inferred,
			"auditd.service":             Inferred,
			"chronyd.service":            Inferred,
			"crond.service":              Inferred,
			"dbus-broker.service":        Inferred,
			"getty@tty1.service":         Inferred,
			"gssproxy.service":           Inferred,
			"irqbalance.service":         Inferred,
			"polkit.service":             Inferred,
			"rpcbind.service":            Inferred,
			"serial-getty@hvc0.service":  Inferred,
			"serial-getty@ttyS0.service": Inferred,
			"session-6.scope":            Inferred,
			"systemd-logind.service":     Inferred,
			"tuned.service":              Inferred, // python3.9 itself was replaced
			"user@1000.service":          Inferred,
			"init.scope":                 Unknown,
			"sshd.service":               None,
			"systemd-journald.service":   None,
		},
		counts: map[Status]int{Inferred: 16, Possible: 0, Unknown: 1, None: 7},
	},
	{
		// Debian 12, Apache with mod_ssl, then only libssl3 and openssl
		// updated. apache2 starts through apachectl, a shell script.
		dir: "debian12/restart-apache",
		want: map[string]Status{
			"apache2.service": Unknown,
			"ssh.service":     Inferred,
			"init.scope":      Unknown,
		},
		counts: map[Status]int{Inferred: 9, Possible: 0, Unknown: 3, None: 6},
	},
	{
		// AlmaLinux 9, httpd with mod_ssl, then only openssl-libs
		// reinstalled. httpd and polkit map libssl and libcrypto only
		// through run-time modules (mod_ssl, libnss_systemd).
		dir: "alma9/restart-httpd",
		want: map[string]Status{
			"httpd.service":  Possible,
			"polkit.service": Possible,
			"sshd.service":   Inferred,
			"tuned.service":  Unknown,
			"init.scope":     Unknown,
		},
		counts: map[Status]int{Inferred: 10, Possible: 10, Unknown: 2, None: 3},
	},
}

// TestLab checks the property the product promises: a unit the agent
// calls "inferred" is stale, and a stale unit is never "none".
func TestLab(t *testing.T) {
	for _, c := range labCases {
		t.Run(c.dir, func(t *testing.T) {
			dir := filepath.Join("..", "..", "testdata", "lab", c.dir)
			snap := readSnapshotFile(t, filepath.Join(dir, "snapshot.json"))
			stale := groundTruth(t, filepath.Join(dir, "deleted-maps.tsv"))

			got := map[string]Status{}
			counts := map[Status]int{}
			for _, f := range Analyze(snap).Findings {
				got[f.Unit] = f.Status
				counts[f.Status]++
				switch {
				case f.Status == Inferred && !stale[f.Unit]:
					t.Errorf("%s: inferred, but no process of it mapped a deleted file", f.Unit)
				case f.Status == None && stale[f.Unit]:
					t.Errorf("%s: none, but root saw it map a deleted file", f.Unit)
				}
			}
			for u := range stale {
				if _, ok := got[u]; !ok {
					t.Errorf("%s: stale per root, absent from the snapshot", u)
				}
			}
			for u, w := range c.want {
				if got[u] != w {
					t.Errorf("%s: %s, want %s", u, got[u], w)
				}
			}
			for _, st := range []Status{Inferred, Possible, Unknown, None} {
				if counts[st] != c.counts[st] {
					t.Errorf("%d %s, want %d", counts[st], st, c.counts[st])
				}
			}
		})
	}
}

func readSnapshotFile(t *testing.T, name string) Snapshot {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var s Snapshot
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// groundTruth reads deleted-maps.tsv (pid, cgroup, exe, deleted paths) and
// returns the units with a stale process: the innermost .service or .scope
// in the cgroup path. A process in a user manager's init.scope belongs to
// user@UID.service; one in a sub-cgroup (udev's "udev") to its unit.
func groundTruth(t *testing.T, name string) map[string]bool {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	stale := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) < 4 {
			continue
		}
		parts := strings.Split(strings.Trim(fields[1], "/"), "/")
		for i := len(parts) - 1; i >= 0; i-- {
			p := parts[i]
			if p == "init.scope" && i > 0 {
				continue
			}
			if strings.HasSuffix(p, ".service") || strings.HasSuffix(p, ".scope") {
				stale[p] = true
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(stale) == 0 {
		t.Fatal("empty ground truth")
	}
	t.Logf("stale per root: %v", slices.Sorted(maps.Keys(stale)))
	return stale
}
