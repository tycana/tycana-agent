package baseline

import (
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"
	"time"
)

// fake is an in-memory host. Paths absent from both maps do not exist.
type fake struct {
	files map[string]string // content; a key ending in "/" is a directory
	meta  map[string]Meta   // overrides; default root:root 0644 file / 0755 dir
	deny  map[string]bool   // EACCES on read and list
}

func (f *fake) host() *Host {
	h := &Host{Root: "/", PackageFormat: "deb", Packages: map[string][]string{}, Units: map[string]map[string]string{},
		OverflowUID: 65534, OverflowGID: 65534}
	h.Stat = func(p string) (Meta, error) {
		if m, ok := f.meta[p]; ok {
			return m, nil
		}
		if _, ok := f.files[p]; ok {
			return Meta{Mode: 0o644, Type: "file"}, nil
		}
		if _, ok := f.files[p+"/"]; ok {
			return Meta{Mode: 0o755, Type: "dir"}, nil
		}
		return Meta{}, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
	}
	h.ReadFile = func(p string) ([]byte, error) {
		if f.deny[p] {
			return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrPermission}
		}
		c, ok := f.files[p]
		if !ok {
			return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
		}
		return []byte(c), nil
	}
	h.ReadDir = func(p string) ([]fs.DirEntry, error) {
		if f.deny[p] {
			return nil, &fs.PathError{Op: "readdir", Path: p, Err: fs.ErrPermission}
		}
		if _, ok := f.files[p+"/"]; !ok {
			return nil, &fs.PathError{Op: "readdir", Path: p, Err: fs.ErrNotExist}
		}
		seen := map[string]bool{}
		var out []fs.DirEntry
		for k := range f.files {
			k = strings.TrimSuffix(k, "/")
			if path.Dir(k) == p && k != p && !seen[k] {
				seen[k] = true
				out = append(out, nameEntry(path.Base(k)))
			}
		}
		for k := range f.meta {
			if path.Dir(k) == p && !seen[k] {
				seen[k] = true
				out = append(out, nameEntry(path.Base(k)))
			}
		}
		slices.SortFunc(out, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
		return out, nil
	}
	return h
}

func run(t *testing.T, h *Host, c Check) Result {
	t.Helper()
	if c.ID == "" {
		c.ID = "t"
	}
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return evaluate(&c, h)
}

func want(t *testing.T, r Result, s Status, reason string) {
	t.Helper()
	if r.Status != s || !strings.Contains(r.Reason, reason) {
		t.Errorf("got %s (%s), want %s containing %q", r.Status, r.Reason, s, reason)
	}
}

func TestFileMode(t *testing.T) {
	f := &fake{files: map[string]string{"/etc/": "", "/etc/passwd": "", "/etc/ssh/": ""},
		meta: map[string]Meta{
			"/etc/shadow":        {Mode: 0o640, GID: 42, Type: "file"},
			"/etc/link":          {Mode: 0o777, Type: "symlink"},
			"/etc/ssh/a.conf":    {Mode: 0o600, Type: "file"},
			"/etc/ssh/b.conf":    {Mode: 0o644, Type: "file"},
			"/etc/ssh/sub":       {Mode: 0o777, Type: "dir"},
			"/etc/ssh/ignore.md": {Mode: 0o777, Type: "file"},
		}}
	h := f.host()
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/passwd"}, Mode: "0644"}}), Pass, "1 file")
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/passwd"}, Mode: "0600"}}), Fail, "/etc/passwd is 0644")
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/shadow"}, Mode: "0644"}}), Pass, "")
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/shadow"}, Mode: "0644", ExactMode: true}}), Fail, "0640")
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/missing"}, Mode: "0600"}}), Pass, "no matching file")
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/link"}, Mode: "0600"}}), Pass, "no matching file")
	// A directory with a name pattern: files only, subdirectories walked but not matched.
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/ssh/"}, FileRegex: `\.conf$`, Mode: "0600"}}), Fail, "/etc/ssh/b.conf is 0644")
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/ssh/"}, FileRegex: `.*`, Mode: "0644", Exclude: []string{"ignore.*"}}}), Pass, "2 file")
	// The directory itself.
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/ssh/"}, Mode: "0700"}}), Fail, "/etc/ssh is 0755")
}

func TestFileOwnerAndSandbox(t *testing.T) {
	f := &fake{
		files: map[string]string{
			"/etc/group":  "root:x:0:\nshadow:x:42:\nnopass::77:\n",
			"/etc/passwd": "root:x:0:0::/root:/bin/sh\n",
			"/var/log/":   "", "/var/log/private/": "",
		},
		meta: map[string]Meta{
			"/etc/shadow":          {Mode: 0o640, GID: 42, Type: "file"},
			"/etc/gshadow":         {Mode: 0o640, GID: 65534, Type: "file"},
			"/etc/x":               {Mode: 0o640, GID: 77, Type: "file"},
			"/var/log/syslog":      {Mode: 0o640, UID: 0, Type: "file"},
			"/var/log/private/sec": {Mode: 0o640, UID: 0, Type: "file"},
		},
		deny: map[string]bool{"/var/log/private": true},
	}
	h := f.host()
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/shadow"}, Group: []string{"shadow", "root"}}}), Pass, "")
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/shadow"}, Group: []string{"0"}}}), Fail, "gid 42")
	// The OVAL's ^NAME:\w+:(\w+): cannot match an empty password field.
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/x"}, Group: []string{"nopass"}}}), Error, "no id found")
	// Outside a user namespace 65534 is a real group (nogroup).
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/gshadow"}, Group: []string{"shadow"}}}), Fail, "gid 65534")
	h.UserNS = true
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/gshadow"}, Group: []string{"shadow"}}}), Unknown, "cannot map")
	// An unreadable directory: unknown when nothing else fails, fail when something does.
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/var/log/"}, FileRegex: ".*", Recursive: true, Owner: []string{"root"}}}), Unknown, "/var/log/private")
	f.meta["/var/log/bad"] = Meta{Mode: 0o644, UID: 1000, Type: "file"}
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/var/log/"}, FileRegex: ".*", Recursive: true, Owner: []string{"root"}}}), Fail, "uid 1000")
}

func TestFileExists(t *testing.T) {
	h := (&fake{files: map[string]string{"/etc/cron.deny": ""}}).host()
	yes, no := true, false
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/cron.deny"}, Exists: &no}}), Fail, "exists")
	want(t, run(t, h, Check{File: &FileCheck{Paths: []string{"/etc/cron.allow"}, Exists: &yes}}), Fail, "does not exist")
}

func sysctl(key string, vals ...string) *SysctlCheck {
	return &SysctlCheck{Key: key, Values: vals, Datatype: "int", Runtime: true,
		UserFiles: []string{"/etc/sysctl.conf"}, UserDirs: []string{"/etc/sysctl.d"}}
}

func TestSysctl(t *testing.T) {
	f := &fake{files: map[string]string{
		"/proc/sys/net/ipv4/ip_forward": "0\n",
		"/proc/sys/kernel/x":            "1\n",
		"/usr/lib/sysctl.d/":            "",
		"/usr/lib/sysctl.d/50-pkg.conf": "net.ipv4.ip_forward = 0\nkernel.x=1\n",
		"/etc/sysctl.d/":                "",
		"/etc/sysctl.conf":              "# net.ipv4.ip_forward = 1\n",
	}}
	h := f.host()
	// Set only in the vendor directory: the vendor value decides.
	want(t, run(t, h, Check{Sysctl: sysctl("net.ipv4.ip_forward", "0")}), Pass, "50-pkg.conf")
	// A user file overrides the vendor files, and every user line must be right.
	f.files["/etc/sysctl.d/90-a.conf"] = "net.ipv4.ip_forward=0\n"
	f.files["/etc/sysctl.d/99-b.conf"] = "  net/ipv4/ip_forward = 1\n"
	want(t, run(t, h, Check{Sysctl: sysctl("net.ipv4.ip_forward", "0")}), Fail, "99-b.conf: 1")
	delete(f.files, "/etc/sysctl.d/99-b.conf")
	want(t, run(t, h, Check{Sysctl: sysctl("net.ipv4.ip_forward", "0")}), Pass, "at run time")
	// Run time differs from configuration.
	f.files["/proc/sys/net/ipv4/ip_forward"] = "1\n"
	want(t, run(t, h, Check{Sysctl: sysctl("net.ipv4.ip_forward", "0")}), Fail, "is 1 at run time")
	// Not set anywhere: fail, unless MissingPass.
	s := sysctl("kernel.y", "0")
	f.files["/proc/sys/kernel/y"] = "0"
	want(t, run(t, h, Check{Sysctl: s}), Fail, "not set")
	s.MissingPass = true
	want(t, run(t, h, Check{Sysctl: s}), Pass, "")
	// Any of several values.
	want(t, run(t, h, Check{Sysctl: sysctl("kernel.x", "2", "1")}), Pass, "")
}

func TestSysctlIPv6Disabled(t *testing.T) {
	f := &fake{files: map[string]string{
		"/etc/sysctl.conf":                         "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.all.accept_ra = 1\n",
		"/proc/sys/net/ipv6/conf/all/disable_ipv6": "1",
		"/proc/sys/net/ipv6/conf/all/accept_ra":    "1",
	}}
	s := sysctl("net.ipv6.conf.all.accept_ra", "0")
	want(t, run(t, f.host(), Check{Sysctl: s}), Fail, "")
	s.IPv6 = true
	want(t, run(t, f.host(), Check{Sysctl: s}), Pass, "IPv6 is disabled")
}

func unit(load, active string) map[string]string {
	return map[string]string{"LoadState": load, "ActiveState": active}
}

func TestService(t *testing.T) {
	h := (&fake{}).host()
	h.Packages["avahi-daemon"] = []string{"1"}
	h.Packages["cron"] = []string{"1"}
	dis := &ServiceCheck{Name: "avahi-daemon", State: "disabled", Package: "avahi-daemon"}
	h.Units["avahi-daemon.service"] = unit("loaded", "inactive")
	h.Units["avahi-daemon.socket"] = unit("not-found", "inactive")
	want(t, run(t, h, Check{Service: dis}), Fail, "want masked")
	h.Units["avahi-daemon.service"] = unit("masked", "inactive")
	want(t, run(t, h, Check{Service: dis}), Pass, "masked")
	h.Units["avahi-daemon.service"] = unit("masked", "active")
	want(t, run(t, h, Check{Service: dis}), Fail, "")
	delete(h.Packages, "avahi-daemon")
	want(t, run(t, h, Check{Service: dis}), Pass, "not installed")

	en := &ServiceCheck{Name: "cron", State: "enabled", Package: "cron"}
	h.Units["cron.service"] = unit("loaded", "active")
	h.Units["cron.socket"] = unit("not-found", "inactive")
	want(t, run(t, h, Check{Service: en}), Unknown, "multi-user.target")
	h.Wanted = []string{"multi-user.target", "ssh.service"}
	want(t, run(t, h, Check{Service: en}), Fail, "does not start")
	h.Wanted = append(h.Wanted, "cron.service")
	want(t, run(t, h, Check{Service: en}), Pass, "")
	h.Units["cron.service"] = unit("loaded", "inactive")
	want(t, run(t, h, Check{Service: en}), Fail, "not active")

	sock := &ServiceCheck{Name: "systemd-journal-remote", State: "socket_masked"}
	h.Units["systemd-journal-remote.socket"] = unit("not-found", "inactive")
	want(t, run(t, h, Check{Service: sock}), Pass, "no unit file")
}

func TestSSHD(t *testing.T) {
	f := &fake{files: map[string]string{
		"/etc/ssh/sshd_config":    "Include /etc/ssh/sshd_config.d/*.conf\n#PermitRootLogin yes\npermitrootlogin no # local\nUsePAM=yes\nBanner /etc/issue.net\n",
		"/etc/ssh/sshd_config.d/": "",
	}}
	h := f.host()
	h.Packages["openssh-server"] = nil
	c := func(kw, v string) Check {
		return Check{SSHD: &SSHDCheck{Keyword: kw, Value: v, Match: "regex", Package: "openssh-server", DropIns: true}}
	}
	want(t, run(t, h, c("PermitRootLogin", "no")), Pass, "")
	// "Keyword=value" does not count, and the value is case-sensitive.
	want(t, run(t, h, c("UsePAM", "yes")), Fail, "not set")
	want(t, run(t, h, c("PermitRootLogin", "No")), Fail, "want No")
	// Every occurrence counts, drop-ins too, whatever the order.
	f.files["/etc/ssh/sshd_config.d/50-cloud.conf"] = "PermitRootLogin prohibit-password\n"
	want(t, run(t, h, c("PermitRootLogin", "no")), Fail, "50-cloud.conf")
	num := Check{SSHD: &SSHDCheck{Keyword: "ClientAliveCountMax", Value: "3", Match: "equals", Datatype: "int", Package: "openssh-server"}}
	f.files["/etc/ssh/sshd_config"] += "ClientAliveCountMax 03\n"
	want(t, run(t, h, num), Pass, "")
	delete(h.Packages, "openssh-server")
	want(t, run(t, h, c("PermitRootLogin", "no")), Pass, "not installed")
	h.Packages["openssh-server"] = nil
	f.deny = map[string]bool{"/etc/ssh/sshd_config": true}
	want(t, run(t, h, c("PermitRootLogin", "no")), Unknown, "without privilege")
}

func TestMount(t *testing.T) {
	f := &fake{files: map[string]string{
		"/etc/fstab": "# /home was on /dev/sda3 during installation\nUUID=x / ext4 defaults 0 1\nUUID=y /var/log ext4 defaults,nodev 0 2\n",
	}}
	h := f.host()
	h.Units["dev-shm.mount"] = unit("not-found", "inactive")
	h.Units["var-log.mount"] = map[string]string{"LoadState": "loaded", "ActiveState": "active", "Where": "/var/log", "Options": "rw,nodev,relatime", "Type": "ext4"}
	h.Units["tmp.mount"] = unit("not-found", "inactive")
	h.Units["home.mount"] = unit("not-found", "inactive")
	h.Sandboxed = true
	h.Mounts = []Mount{
		{Root: "/", Target: "/dev/shm", FSType: "tmpfs", Options: []string{"rw", "nosuid", "nodev"}},
		{Root: "/tmp/systemd-private-abc/tmp", Target: "/tmp", FSType: "ext4", Options: []string{"rw", "nosuid"}},
	}
	// /dev/shm rules need an fstab line (mount_has_to_exist false).
	want(t, run(t, h, Check{Mount: &MountCheck{Path: "/dev/shm", Option: "nodev"}}), Fail, "no /etc/fstab line")
	f.files["/etc/fstab"] += "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0\n"
	// The sandbox shows nosuid, which systemd may have added: unknown.
	want(t, run(t, h, Check{Mount: &MountCheck{Path: "/dev/shm", Option: "nosuid"}}), Unknown, "sandbox")
	// noexec is absent in the sandbox, so absent on the host.
	want(t, run(t, h, Check{Mount: &MountCheck{Path: "/dev/shm", Option: "noexec"}}), Fail, "without noexec")
	// systemd's unit is the host's view.
	want(t, run(t, h, Check{Mount: &MountCheck{Path: "/var/log", Option: "nodev", MustExist: true}}), Pass, "mounted with nodev")
	want(t, run(t, h, Check{Mount: &MountCheck{Path: "/var/log", Option: "noexec", MustExist: true}}), Fail, "/etc/fstab mounts /var/log")
	// The PrivateTmp bind is not the host's /tmp.
	tmp := Check{When: []Condition{{Mounted: "/tmp"}}, Mount: &MountCheck{Path: "/tmp", Option: "nodev", MustExist: true}}
	want(t, run(t, h, tmp), NotApplicable, "not a separate mount")
	// mount[home]: a commented fstab line counts, as in the OVAL.
	home := Check{When: []Condition{{Mounted: "/home"}}, Mount: &MountCheck{Path: "/home", Option: "nodev", MustExist: true}}
	want(t, run(t, h, home), Pass, "not mounted")
}

func TestKmod(t *testing.T) {
	f := &fake{files: map[string]string{
		"/etc/modprobe.d/":         "",
		"/etc/modprobe.d/cis.conf": "install cramfs /bin/false\n  blacklist cramfs\ninstall hfs /usr/bin/false\nblacklist hfs\n",
	}}
	h := f.host()
	want(t, run(t, h, Check{KernelModule: &KmodCheck{Name: "cramfs"}}), Pass, "cis.conf")
	// blacklist must start the line.
	want(t, run(t, h, Check{KernelModule: &KmodCheck{Name: "cramfs", Blacklist: true}}), Fail, "no blacklist")
	// /usr/bin/false does not count.
	want(t, run(t, h, Check{KernelModule: &KmodCheck{Name: "hfs", Blacklist: true}}), Fail, "no install")
}

func TestConditions(t *testing.T) {
	h := (&fake{files: map[string]string{"/etc/default/grub": `GRUB_CMDLINE_LINUX="quiet ipv6.disable=1"` + "\n"}}).host()
	c := Check{When: []Condition{{Package: "linux-base"}}, Package: &PackageCheck{Names: []string{"telnet"}, State: "absent"}}
	want(t, run(t, h, c), NotApplicable, "linux-base")
	h.Packages["linux-base"] = nil
	want(t, run(t, h, c), Pass, "not installed")
	h.Packages["telnet"] = nil
	want(t, run(t, h, c), Fail, "installed: telnet")
	c.When = append(c.When, Condition{IPv6Enabled: true})
	want(t, run(t, h, c), NotApplicable, "IPv6 is disabled")
	c.When = []Condition{{Not: &Condition{Any: []Condition{{FileExists: "/.dockerenv"}, {FileExists: "/run/.containerenv"}}}}}
	want(t, run(t, h, c), Fail, "")
}

func TestScoreAndExceptions(t *testing.T) {
	res := []Result{{ID: "a", Status: Pass}, {ID: "b", Status: Fail}, {ID: "c", Status: Unknown}, {ID: "d", Status: NotApplicable}}
	for i := 0; i < 17; i++ {
		res = append(res, Result{ID: "p", Status: Pass})
	}
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	s := score(res, 3, DefaultTarget)
	if s.Percent != 94.7 || s.Met || s.Passed != 18 || s.Failed != 1 || s.Unknown != 1 || s.NotCovered != 3 ||
		s.Rules != 24 || s.Coverage != 87.5 {
		t.Errorf("score %+v", s)
	}
	applyExceptions(res, []Exception{{Check: "b", Reason: "r", Owner: "o", Expires: "2026-10-16"}}, now)
	if res[1].Status != Excepted || res[1].Found != Fail {
		t.Errorf("exception not applied: %+v", res[1])
	}
	if s := score(res, 0, DefaultTarget); s.Percent != 100 || !s.Met || s.Excepted != 1 {
		t.Errorf("score with exception %+v", s)
	}
	res[1].Status = Fail
	applyExceptions(res, []Exception{{Check: "b", Reason: "r", Owner: "o", Expires: "2026-10-15"}}, now)
	if res[1].Status != Fail {
		t.Error("expired exception applied")
	}
}

func TestLoadIsStrict(t *testing.T) {
	head := "version: 1\nname: x\napplies: [{id: ubuntu, version_id: \"24.04\"}]\nchecks:\n"
	for name, body := range map[string]string{
		"unknown field": "  - id: a\n    packages: {names: [x], state: absent}\n",
		"two probes":    "  - id: a\n    package: {names: [x], state: absent}\n    kernel_module: {name: x}\n",
		"no probe":      "  - id: a\n",
		"bad state":     "  - id: a\n    package: {names: [x], state: gone}\n",
		"duplicate":     "  - id: a\n    kernel_module: {name: x}\n  - id: a\n    kernel_module: {name: y}\n",
		"bad regex":     "  - id: a\n    file: {paths: [/etc/], file_regex: \"(\", mode: \"0600\"}\n",
		"relative path": "  - id: a\n    file: {paths: [etc/passwd], mode: \"0600\"}\n",
	} {
		if _, err := Load(strings.NewReader(head + body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Load(strings.NewReader(head + "  - id: a\n    kernel_module: {name: cramfs}\n")); err != nil {
		t.Errorf("valid baseline: %v", err)
	}
}

func TestExceptionsFile(t *testing.T) {
	ok := "version: 1\nexceptions:\n  - check: a\n    reason: legacy app\n    owner: ops\n    expires: 2027-01-31\n"
	if e, err := LoadExceptions(strings.NewReader(ok)); err != nil || len(e) != 1 {
		t.Errorf("valid file: %v %v", e, err)
	}
	for _, bad := range []string{
		"version: 1\nexceptions:\n  - check: a\n    owner: ops\n    expires: 2027-01-31\n",
		"version: 1\nexceptions:\n  - check: a\n    reason: r\n    owner: ops\n    expires: soon\n",
		"version: 2\nexceptions: []\n",
	} {
		if _, err := LoadExceptions(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// The presets carry no CIS data (inbox item 1.1, option A) and load.
func TestPresets(t *testing.T) {
	ps, err := Presets()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) == 0 {
		t.Fatal("no presets")
	}
	for _, b := range ps {
		if strings.Contains(strings.ToLower(b.Name+b.Title), "cis") {
			t.Errorf("%s: name or title names CIS", b.Name)
		}
		for _, c := range b.Checks {
			for k := range c.Refs {
				if dropRefKey(k) {
					t.Errorf("%s/%s: reference %s", b.Name, c.ID, k)
				}
			}
		}
		for _, u := range b.NotCovered {
			for k := range u.Refs {
				if dropRefKey(k) {
					t.Errorf("%s/%s: reference %s", b.Name, u.ID, k)
				}
			}
		}
	}
	for _, rel := range [][2]string{{"ubuntu", "24.04"}, {"debian", "12"}, {"almalinux", "9.6"}} {
		if _, err := PresetFor(rel[0], rel[1]); err != nil {
			t.Error(err)
		}
	}
	if _, err := PresetFor("ubuntu", "22.04"); err == nil {
		t.Error("ubuntu 22.04 has a preset without a lab comparison")
	}
}

func dropRefKey(k string) bool { return k == "cis" || k == "cis-csc" || strings.HasPrefix(k, "cis@") }

func TestMountUnit(t *testing.T) {
	for in, out := range map[string]string{"/": "-.mount", "/var/log/audit": "var-log-audit.mount",
		"/dev/shm": "dev-shm.mount", "/var/lib/x-y": `var-lib-x\x2dy.mount`, "/srv/.hidden": `srv-.hidden.mount`} {
		if got := mountUnit(in); got != out {
			t.Errorf("%s: %s, want %s", in, got, out)
		}
	}
}

func TestParseMountinfo(t *testing.T) {
	m := parseMountinfo([]byte("36 35 98:0 /mnt1 /mnt\\040x rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n"))
	if len(m) != 1 || m[0].Target != "/mnt x" || m[0].Root != "/mnt1" || !slices.Contains(m[0].Options, "noatime") || !slices.Contains(m[0].Options, "errors=continue") {
		t.Errorf("%+v", m)
	}
}

// Fable review, 2026-10-16: a sysctl key is quoted, never a raw regex.
func TestSysctlKeyIsNotARegex(t *testing.T) {
	for _, k := range []string{"net.a**", "net.(x", "net.a|b", "kernel.x*"} {
		if err := sysctl(k, "0").validate(); err == nil {
			t.Errorf("%q accepted", k)
		}
	}
	re := sysctlLineRE("net.ipv4.ip_forward")
	for line, ok := range map[string]bool{"net.ipv4.ip_forward=0": true, "net/ipv4/ip_forward = 0": true, "netXipv4.ip_forward=0": true, "net.ipv4.ip_forwardx=0": false} {
		if re.MatchString(line) != ok {
			t.Errorf("%q: match %v", line, !ok)
		}
	}
}

func TestWalkBounds(t *testing.T) {
	f := &fake{files: map[string]string{"/var/": "", "/var/log/": "", "/var/log/nfs/": "", "/var/log/x/": ""},
		meta: map[string]Meta{"/var/log/nfs/bad": {Mode: 0o777, Type: "file"}, "/var/log/x/ok": {Mode: 0o600, Type: "file"}}}
	h := f.host()
	h.Mounts = []Mount{{Root: "/", Target: "/var/log/nfs", FSType: "nfs4"}}
	c := Check{File: &FileCheck{Paths: []string{"/var/log/"}, FileRegex: ".*", Recursive: true, Mode: "0640"}}
	// The walk does not enter a network file system (recurse_file_system="local").
	want(t, run(t, h, c), Pass, "1 file")
	h.Mounts[0].FSType = "ext4"
	want(t, run(t, h, c), Fail, "/var/log/nfs/bad")
	// A tree deeper than the bound is unknown, not pass.
	deep := &fake{files: map[string]string{}}
	p := "/d"
	for i := 0; i <= maxWalkDepth+1; i++ {
		deep.files[p+"/"] = ""
		p += "/d"
	}
	want(t, run(t, deep.host(), Check{File: &FileCheck{Paths: []string{"/d/"}, FileRegex: ".*", Recursive: true, Mode: "0644"}}), Unknown, "deeper than")
}

func TestUnitNamesFailAtLoad(t *testing.T) {
	for _, n := range []string{"@foo", "foo@", "a\\x2d", strings.Repeat("a", 201), "-x"} {
		if err := (&ServiceCheck{Name: n, State: "socket_masked"}).validate(); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

// Mark, 2026-10-16 (old inbox item 3.4, option A): a note when the rule
// is stricter than the system; the verdict does not change.
func TestStricterNotes(t *testing.T) {
	note := func(t *testing.T, r Result, s Status, has string) {
		t.Helper()
		if r.Status != s || (has == "") != (r.Note == "") || !strings.Contains(r.Note, has) {
			t.Errorf("got %s, note %q; want %s, note with %q", r.Status, r.Note, s, has)
		}
	}
	t.Run("service", func(t *testing.T) {
		h := (&fake{}).host()
		h.Packages["rsync"] = nil
		h.Wanted = []string{"multi-user.target"}
		c := Check{Service: &ServiceCheck{Name: "rsync", State: "disabled", Package: "rsync"}}
		h.Units["rsync.service"] = map[string]string{"LoadState": "loaded", "ActiveState": "inactive", "UnitFileState": "disabled"}
		h.Units["rsync.socket"] = unit("not-found", "inactive")
		note(t, run(t, h, c), Fail, "masked")
		h.Wanted = append(h.Wanted, "rsync.service")
		note(t, run(t, h, c), Fail, "")
		h.Wanted = h.Wanted[:1]
		h.Units["rsync.service"]["UnitFileState"] = "enabled"
		note(t, run(t, h, c), Fail, "")
		h.Units["rsync.service"]["UnitFileState"] = "disabled"
		h.Units["rsync.service"]["ActiveState"] = "active"
		note(t, run(t, h, c), Fail, "")
	})
	t.Run("mount", func(t *testing.T) {
		h := (&fake{files: map[string]string{"/etc/fstab": "UUID=x / ext4 defaults 0 1\n"}}).host()
		c := Check{Mount: &MountCheck{Path: "/dev/shm", Option: "nodev"}}
		h.Mounts = []Mount{{Root: "/", Target: "/dev/shm", FSType: "tmpfs", Options: []string{"rw", "nosuid", "nodev"}}}
		note(t, run(t, h, c), Fail, "fstab")
		h.Mounts[0].Options = []string{"rw"}
		note(t, run(t, h, c), Fail, "")
		h.Mounts[0].Options = []string{"rw", "nodev"}
		h.Sandboxed = true
		note(t, run(t, h, c), Fail, "")
	})
	t.Run("sshd", func(t *testing.T) {
		f := &fake{files: map[string]string{
			"/etc/ssh/sshd_config":                 "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMatch User x\nPermitRootLogin no\n",
			"/etc/ssh/sshd_config.d/":              "",
			"/etc/ssh/sshd_config.d/10-local.conf": "PermitRootLogin no\n",
		}}
		h := f.host()
		h.Packages["openssh-server"] = nil
		c := func(dropIns bool) Check {
			return Check{SSHD: &SSHDCheck{Keyword: "PermitRootLogin", Value: "no", Match: "regex", Package: "openssh-server", DropIns: dropIns}}
		}
		// sshd reads the drop-in first: its value wins; the later
		// "yes" fails the rule.
		note(t, run(t, h, c(true)), Fail, "first value it reads")
		// Without DropIns the rule reads only sshd_config.
		note(t, run(t, h, c(false)), Fail, "reads only /etc/ssh/sshd_config")
		// The value sshd uses is the bad one: no note.
		f.files["/etc/ssh/sshd_config.d/10-local.conf"] = "PermitRootLogin yes\n"
		f.files["/etc/ssh/sshd_config"] = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n"
		note(t, run(t, h, c(true)), Fail, "")
		// An Include the agent does not follow: no note.
		f.files["/etc/ssh/sshd_config"] = "Include /etc/ssh/other.conf\nPermitRootLogin no\nPermitRootLogin yes\n"
		note(t, run(t, h, c(true)), Fail, "")
	})
	t.Run("sysctl", func(t *testing.T) {
		f := &fake{files: map[string]string{
			"/proc/sys/net/ipv4/ip_forward":    "0\n",
			"/etc/sysctl.d/":                   "",
			"/etc/sysctl.d/10-a.conf":          "net.ipv4.ip_forward = 1\n",
			"/etc/sysctl.d/90-b.conf":          "net.ipv4.ip_forward = 0\n",
			"/etc/sysctl.d/99-sysctl.conf":     "# link to /etc/sysctl.conf\n",
			"/usr/lib/sysctl.d/":               "",
			"/usr/lib/sysctl.d/90-b.conf":      "net.ipv4.ip_forward = 1\n",
			"/usr/lib/sysctl.d/50-vendor.conf": "net.ipv4.ip_forward = 1\n",
		}}
		h := f.host()
		c := Check{Sysctl: sysctl("net.ipv4.ip_forward", "0")}
		// 90-b.conf in /etc hides the one in /usr/lib, and it is last.
		note(t, run(t, h, c), Fail, "0 in /etc/sysctl.d/90-b.conf")
		f.files["/proc/sys/net/ipv4/ip_forward"] = "1\n"
		note(t, run(t, h, c), Fail, "")
		f.files["/proc/sys/net/ipv4/ip_forward"] = "0\n"
		f.files["/etc/sysctl.d/95-c.conf"] = "net.ipv4.ip_forward = 1\n"
		note(t, run(t, h, c), Fail, "")
	})
}

func TestBenchmarkCoverage(t *testing.T) {
	bm := &Benchmark{Level: "l1_server", Automated: 5, Recommendations: [][]string{{"a"}, {"a", "b"}, {"c"}, {"d", "x"}}}
	res := []Result{
		{ID: "a", Status: Pass}, {ID: "b", Status: Unknown}, {ID: "c", Status: Excepted, Found: Fail}, {ID: "d", Status: Fail},
	}
	got := benchmarkCoverage(bm, res)
	want := BenchmarkCoverage{Level: "l1_server", Automated: 5, Checked: 3, Partly: 1, Percent: 60, Evaluated: 2}
	if *got != want {
		t.Errorf("got %+v, want %+v", *got, want)
	}
}

// The coverage checkpoint measured these counts with
// tycana-hq tools/research/baseline_coverage.py (2026-10-16, F1); the
// converter must reproduce them.
func TestPresetBenchmarkCoverage(t *testing.T) {
	want := map[string][3]int{ // automated, checked, partly
		"ubuntu2404-level1-server": {232, 110, 5},
		"debian12-level1-server":   {230, 113, 6},
		"almalinux9-level1-server": {219, 103, 4},
	}
	ps, err := Presets()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		var res []Result
		for _, c := range p.Checks {
			res = append(res, Result{ID: c.ID, Status: Pass})
		}
		c := benchmarkCoverage(p.Benchmark, res)
		if c == nil {
			t.Errorf("%s: no benchmark data", p.Name)
			continue
		}
		if got := [3]int{c.Automated, c.Checked, c.Partly}; got != want[p.Name] {
			t.Errorf("%s: automated, checked, partly = %v, want %v", p.Name, got, want[p.Name])
		}
	}
}
