package updates

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"tycana.ai/agent/internal/hostexec"
)

// TestUnattendedUbuntu replays the Ubuntu lab VM before its own
// unattended-upgrades run on 2026-10-16 and compares the prediction with
// what that run did (testdata/lab/ubuntu2404/restart: u-u.log lists the
// upgrades, dpkg-log-run.txt the new packages and versions).
//
// apt-config-dump.txt and apt-cache-policy-global.txt were captured after
// the run; the configuration and the sources did not change. The timer
// file restates the morning's state (enabled, due at 14:33:49 UTC) in the
// format systemctl prints under TZ=UTC.
func TestUnattendedUbuntu(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "lab", "ubuntu2404", "updates")
	q, err := os.ReadFile(filepath.Join(dir, "apt-cache-policy-query.txt"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := collectApt(context.Background(), fixtureRunner(t, dir, strings.Fields(string(q))), "amd64", []string{"nano"})
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "unattended-upgrade")
	if err := os.WriteFile(bin, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(old string) { unattendedUpgradeBin = old }(unattendedUpgradeBin)
	unattendedUpgradeBin = bin

	if err := predictAutopilot(context.Background(), autopilotFixtures(t, dir), &r, "Ubuntu", "noble"); err != nil {
		t.Fatal(err)
	}
	a := r.Autopilot
	if !a.Runs || a.Reboot != "never" || !a.NextRun.Equal(time.Date(2026, 10, 16, 14, 33, 49, 0, time.UTC)) {
		t.Errorf("runs %v, reboot %q, next %v, why %q", a.Runs, a.Reboot, a.NextRun, a.Why)
	}

	gt := filepath.Join("..", "..", "testdata", "lab", "ubuntu2404", "restart")
	log, err := os.ReadFile(filepath.Join(gt, "u-u.log"))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, line := range strings.Split(string(log), "\n") {
		if _, list, ok := strings.Cut(line, "Packages that will be upgraded: "); ok {
			want = strings.Fields(list)
		}
	}
	dpkg, err := os.ReadFile(filepath.Join(gt, "dpkg-log-run.txt"))
	if err != nil {
		t.Fatal(err)
	}
	installed := map[string]string{} // name -> version dpkg installed
	for _, line := range strings.Split(string(dpkg), "\n") {
		f := strings.Fields(line)
		if len(f) == 6 && (f[2] == "install" || f[2] == "upgrade") {
			name, _, _ := strings.Cut(f[3], ":")
			installed[name] = f[5]
			if f[2] == "install" {
				want = append(want, name)
			}
		}
	}
	var got []string
	for _, p := range a.Install {
		got = append(got, p.Name)
		if installed[p.Name] != p.To {
			t.Errorf("%s: predicted %s, dpkg installed %s", p.Name, p.To, installed[p.Name])
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("predicted %d: %q\nran %d: %q", len(got), got, len(want), want)
	}
	reasons := map[string]int{}
	for _, s := range a.Skip {
		reasons[s.Reason]++
	}
	t.Logf("install %d, skip %v", len(a.Install), reasons)
}

// TestUnattendedDebian compares the prediction on the Debian lab VM with
// "unattended-upgrade --dry-run -d" run as root on the same state
// (unattended-upgrade-dry-run.txt). The updates fixture was captured with
// openssl held, so the agent leaves openssl that the dry run (no hold)
// lists.
func TestUnattendedDebian(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "lab", "debian12", "updates")
	q, err := os.ReadFile(filepath.Join(dir, "apt-cache-policy-query.txt"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := collectApt(context.Background(), fixtureRunner(t, dir, strings.Fields(string(q))), "amd64", []string{"curl", "openssl"})
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "unattended-upgrade")
	if err := os.WriteFile(bin, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(old string) { unattendedUpgradeBin = old }(unattendedUpgradeBin)
	unattendedUpgradeBin = bin
	if err := predictAutopilot(context.Background(), autopilotFixtures(t, dir), &r, "Debian", "bookworm"); err != nil {
		t.Fatal(err)
	}
	a := r.Autopilot
	if a.Runs || !slices.Equal(a.Why, []string{"apt-daily-upgrade.timer is masked"}) {
		t.Errorf("runs %v why %q", a.Runs, a.Why)
	}
	dry, err := os.ReadFile(filepath.Join(dir, "unattended-upgrade-dry-run.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, line := range strings.Split(string(dry), "\n") {
		if _, list, ok := strings.Cut(line, "Packages that will be upgraded: "); ok {
			want = strings.Fields(list)
		}
		if _, list, ok := strings.Cut(line, "Allowed origins are: "); ok && strings.Join(a.Origins, ", ") != list {
			t.Errorf("origins %q, dry run %q", a.Origins, list)
		}
	}
	want = slices.DeleteFunc(want, func(n string) bool { return n == "openssl" })
	var got []string
	for _, p := range a.Install {
		got = append(got, p.Name)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("predicted %q\ndry run   %q", got, want)
	}
	if len(a.Skip) != 1 || a.Skip[0].Name != "openssl" || a.Skip[0].Reason != "held" {
		t.Errorf("skip %+v", a.Skip)
	}
}

// autopilotFixtures answers the autopilot's commands from a lab directory.
func autopilotFixtures(t *testing.T, dir string) runner {
	return func(_ context.Context, id hostexec.ID, extra ...string) (hostexec.Result, error) {
		files := map[hostexec.ID]string{
			hostexec.SystemctlShowUpdaterTimers: "systemctl-show-updater-timers.txt",
			hostexec.AptConfigDump:              "apt-config-dump.txt",
			hostexec.AptCachePolicy:             "apt-cache-policy-global.txt",
		}
		if len(extra) > 0 {
			t.Errorf("%s with arguments %q", id, extra)
		}
		b, err := os.ReadFile(filepath.Join(dir, files[id]))
		return hostexec.Result{Stdout: b}, err
	}
}

func TestUnattendedTimerMasked(t *testing.T) {
	r := &Report{Manager: "apt"}
	ts := parseTimers([]byte("Id=apt-daily-upgrade.timer\nLoadState=masked\nActiveState=inactive\nUnitFileState=masked\n"))
	a := predictUnattended(r, parseAptConfig([]byte(`APT::Periodic::Unattended-Upgrade "1";`+"\n")), nil, ts, "Ubuntu", "noble")
	if a.Runs || !slices.Contains(a.Why, "apt-daily-upgrade.timer is masked") {
		t.Errorf("%+v", a)
	}
	a = predictUnattended(r, parseAptConfig([]byte(`APT::Periodic::Unattended-Upgrade "0";`+"\n")), nil, ts, "Ubuntu", "noble")
	if a.Runs || !slices.Contains(a.Why, "APT::Periodic::Unattended-Upgrade is off") {
		t.Errorf("%+v", a)
	}
}

func TestUnattendedRules(t *testing.T) {
	c := parseAptConfig([]byte(`Unattended-Upgrade::Origins-Pattern "";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
Unattended-Upgrade::Origins-Pattern:: "site=*.example.com";
Unattended-Upgrade::Package-Blacklist:: "linux-";
Unattended-Upgrade::Package-Blacklist:: "(unclosed";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
`))
	rules, shown := newUURules(c, "Debian", "bookworm")
	if !slices.Equal(shown, []string{"origin=Debian,codename=bookworm-security,label=Debian-Security", "site=*.example.com"}) {
		t.Errorf("shown %q", shown)
	}
	sec := release{Origin: "Debian", Codename: "bookworm-security", Label: "Debian-Security", Archive: "oldstable-security"}
	if !rules.allows(sec) || rules.allows(release{Origin: "Debian", Codename: "bookworm", Label: "Debian"}) {
		t.Error("pattern match")
	}
	if !rules.allows(release{Site: "apt.example.com"}) || rules.allows(release{Site: "example.org"}) {
		t.Error("site glob")
	}
	if len(rules.blacklist) != 1 || !rules.blacklist[0].MatchString("linux-image-6") || rules.blacklist[0].MatchString("xlinux-") {
		t.Error("blacklist anchoring")
	}
	if len(rules.badBlack) != 1 {
		t.Error("an invalid entry must be reported, not dropped silently")
	}
	a := predictUnattended(&Report{}, c, nil, nil, "Debian", "bookworm")
	if a.Reboot != "when /run/reboot-required exists, at 02:00" || len(a.Why) == 0 {
		t.Errorf("%+v", a)
	}
}

func TestDnfAutomatic(t *testing.T) {
	r := &Report{Manager: "dnf", Updates: []Update{
		{Name: "openssl-libs", Arch: "x86_64", Installed: "1:3.5.1-1.el9", Candidate: "1:3.5.8-2.el9", Security: true},
		{Name: "tzdata", Arch: "noarch", Installed: "2025a-1.el9", Candidate: "2026a-1.el9"},
		{Name: "kernel", Arch: "x86_64", Candidate: "5.14.0-687.57.1.el9_8", Security: true},
	}}
	conf := parseINI([]byte("[commands]\nupgrade_type = security\napply_updates = yes\nreboot = when-needed\n[base]\n# comment\n"))
	main := parseINI([]byte("[main]\nexclude=kernel*\n"))
	ts := parseTimers([]byte("Id=dnf-automatic.timer\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nNextElapseUSecRealtime=Sat 2026-10-17 06:12:00 UTC\n"))
	a := predictDnfAutomatic(r, conf, main, ts)
	if !a.Runs || a.Timer != "dnf-automatic.timer" || a.Reboot != "when needs-restarting -r asks for it" {
		t.Errorf("%+v", a)
	}
	if len(a.Install) != 1 || a.Install[0].Name != "openssl-libs" || len(a.Skip) != 2 {
		t.Errorf("install %+v skip %+v", a.Install, a.Skip)
	}
	// apply_updates off: the plain timer only downloads.
	conf = parseINI([]byte("[commands]\napply_updates = no\n"))
	if a := predictDnfAutomatic(r, conf, nil, ts); a.Runs || len(a.Why) == 0 {
		t.Errorf("download only: %+v", a)
	}
	// The install timer installs regardless of apply_updates.
	ts = parseTimers([]byte("Id=dnf-automatic-install.timer\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n"))
	if a := predictDnfAutomatic(r, conf, nil, ts); !a.Runs || len(a.Install) != 3 {
		t.Errorf("install timer: %+v", a)
	}
}

// TestDnfAutomaticAlma compares the prediction on the AlmaLinux lab VM,
// with dnf-automatic installed, upgrade_type = security and
// dnf-automatic-install.timer enabled, against
// "dnf upgrade --security --assumeno" as root on the same state. dnf also
// installs one new weak dependency (gawk-all-langpacks) that no pending
// update names; the agent does not resolve new dependencies.
func TestDnfAutomaticAlma(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "lab", "alma9", "updates")
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	run := func(_ context.Context, id hostexec.ID, _ ...string) (hostexec.Result, error) {
		switch id {
		case hostexec.DnfCheckUpdate:
			return hostexec.Result{Stdout: read("dnf-check-update.txt"), ExitCode: 100}, nil
		case hostexec.DnfUpdateinfo:
			return hostexec.Result{Stdout: read("dnf-updateinfo.txt")}, nil
		}
		t.Fatalf("unexpected command %s", id)
		return hostexec.Result{}, nil
	}
	installed := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(read("installed.tsv"))), "\n") {
		k, v, _ := strings.Cut(line, "\t")
		installed[k] = v
	}
	r, err := collectDnf(context.Background(), run, installed)
	if err != nil {
		t.Fatal(err)
	}
	a := predictDnfAutomatic(&r, parseINI(read("dnf-automatic.conf")), parseINI(read("dnf.conf")),
		parseTimers(read("systemctl-show-updater-timers.txt")))
	if !a.Runs || a.Timer != "dnf-automatic-install.timer" || a.UpgradeType != "security" || a.Reboot != "never" || a.NextRun.IsZero() {
		t.Errorf("%+v", a)
	}

	// The packages dnf lists under Upgrading and Installing, as name.arch.
	var want []string
	in := false
	for _, line := range strings.Split(string(read("dnf-upgrade-security-assumeno.txt")), "\n") {
		switch {
		case strings.HasPrefix(line, "Upgrading:"), strings.HasPrefix(line, "Installing:"), strings.HasPrefix(line, "Installing weak"), strings.HasPrefix(line, "Installing dependencies:"):
			in = true
		case strings.HasPrefix(line, "Transaction Summary"):
			in = false
		case in:
			f := strings.Fields(line)
			if len(f) >= 5 && f[0] != "replacing" {
				want = append(want, f[0]+"."+f[1])
			}
		}
	}
	want = slices.DeleteFunc(want, func(n string) bool { return n == "gawk-all-langpacks.x86_64" })
	var got []string
	for _, p := range a.Install {
		got = append(got, p.Name+"."+p.Arch)
	}
	slices.Sort(got)
	slices.Sort(want)
	want = slices.Compact(want)
	if !slices.Equal(got, want) {
		t.Errorf("predicted %d %q\ndnf       %d %q", len(got), got, len(want), want)
	}
}
