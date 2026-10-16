package updates

import (
	"bufio"
	"bytes"
	"path"
	"strings"
)

// ini is a parsed INI file: section -> key -> value. Keys are lower case.
type ini map[string]map[string]string

// parseINI parses dnf's configuration format: [section], key = value,
// "#" and ";" comments.
func parseINI(b []byte) ini {
	out := ini{}
	sec := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case line[0] == '[' && strings.HasSuffix(line, "]"):
			sec = strings.TrimSpace(line[1 : len(line)-1])
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			if out[sec] == nil {
				out[sec] = map[string]string{}
			}
			out[sec][strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return out
}

func (c ini) get(sec, key, def string) string {
	if v, ok := c[sec][key]; ok {
		return v
	}
	return def
}

// dnfBool follows dnf's boolean values.
func dnfBool(v string) bool {
	switch strings.ToLower(v) {
	case "1", "yes", "true", "on":
		return true
	}
	return false
}

// predictDnfAutomatic applies dnf-automatic's rules (dnf 4, automatic.conf):
// dnf-automatic.timer installs when apply_updates is on;
// dnf-automatic-install.timer always installs; the download and
// notifyonly timers never do. upgrade_type "security" limits the install
// to updates with a security advisory. Excludes come from automatic.conf
// [base] and dnf.conf [main].
func predictDnfAutomatic(r *Report, conf, main ini, ts map[string]timer) *Autopilot {
	a := &Autopilot{Tool: "dnf-automatic", Installed: true, Install: []Planned{}}
	a.UpgradeType = conf.get("commands", "upgrade_type", "default")
	apply := dnfBool(conf.get("commands", "apply_updates", "no"))

	plain, install := ts["dnf-automatic.timer"], ts["dnf-automatic-install.timer"]
	switch {
	case install.active():
		a.Runs, a.Timer, a.NextRun, a.LastRun = true, install.ID, install.Next, install.Last
	case plain.active() && apply:
		a.Runs, a.Timer, a.NextRun, a.LastRun = true, plain.ID, plain.Next, plain.Last
	case plain.active():
		a.Timer, a.NextRun, a.LastRun = plain.ID, plain.Next, plain.Last
		a.Why = append(a.Why, "dnf-automatic.timer is active but apply_updates is off: it only downloads or notifies")
	default:
		a.Why = append(a.Why, "dnf-automatic.timer is "+plain.state()+" and dnf-automatic-install.timer is "+install.state())
	}

	switch reboot := conf.get("commands", "reboot", "never"); reboot {
	case "never":
		a.Reboot = "never"
	case "when-changed":
		a.Reboot = "when any package changed"
	case "when-needed":
		a.Reboot = "when needs-restarting -r asks for it"
	default:
		a.Reboot = reboot
	}

	excludes := make([]string, 0, 8)
	for _, v := range []string{
		conf.get("base", "exclude", ""), conf.get("base", "excludepkgs", ""),
		main.get("main", "exclude", ""), main.get("main", "excludepkgs", ""),
	} {
		excludes = append(excludes, strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })...)
	}

	for _, u := range r.Updates {
		skip := func(reason string) {
			a.Skip = append(a.Skip, Skipped{Name: u.Name, Arch: u.Arch, Candidate: u.Candidate, Reason: reason})
		}
		if excluded(u.Name, u.Arch, excludes) {
			skip("excluded in dnf configuration")
			continue
		}
		if a.UpgradeType == "security" && !u.Security {
			skip("no security advisory (upgrade_type = security)")
			continue
		}
		a.Install = append(a.Install, Planned{Name: u.Name, Arch: u.Arch, From: u.Installed, To: u.Candidate, Security: u.Security})
	}
	return a
}

// excluded matches dnf exclude globs against name and name.arch.
func excluded(name, arch string, globs []string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
		if ok, _ := path.Match(g, name+"."+arch); ok {
			return true
		}
	}
	return false
}
