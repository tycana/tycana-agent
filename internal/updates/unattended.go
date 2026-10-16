package updates

import (
	"bufio"
	"bytes"
	"path"
	"regexp"
	"slices"
	"strings"
)

// aptData keeps apt's version tables from CollectApt for the autopilot
// prediction.
type aptData struct {
	policies   map[string]policyPkg // by policyName
	nativeArch string
}

// aptConfig is "apt-config dump": each key with its values. A list item
// ("Key:: value") adds a value to Key.
type aptConfig map[string][]string

// parseAptConfig parses lines like
//
//	Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";
//	APT::Periodic::Unattended-Upgrade "1";
func parseAptConfig(b []byte) aptConfig {
	c := aptConfig{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), " ")
		if !ok || !strings.HasPrefix(val, `"`) || !strings.HasSuffix(val, `";`) {
			continue
		}
		val = strings.TrimSuffix(strings.TrimPrefix(val, `"`), `";`)
		key = strings.TrimSuffix(key, "::")
		if val != "" {
			c[key] = append(c[key], val)
		}
	}
	return c
}

func (c aptConfig) value(key string) string {
	if v := c[key]; len(v) > 0 {
		return v[len(v)-1]
	}
	return ""
}

// truthy follows apt's boolean parsing: "1", "true", "yes", "on".
func truthy(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on", "with", "enable":
		return true
	}
	return false
}

// release is the Release file of one package source, from the global
// "apt-cache policy" table.
type release struct {
	Origin, Label, Archive, Codename, Component, Site string
}

var (
	// " 500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages"
	globalSourceLine = regexp.MustCompile(`^ -?\d+ (\S+) (\S+) (\S+)(?: Packages)?$`)
	// "     release v=24.04,o=Ubuntu,a=noble-security,n=noble,l=Ubuntu,c=main,b=amd64"
	releaseLine = regexp.MustCompile(`^ +release (.*)$`)
	// "     origin security.ubuntu.com"
	originLine = regexp.MustCompile(`^ +origin (\S*)$`)
)

// parseReleases parses the "Package files:" table of "apt-cache policy"
// into source key ("URL dist/component arch") -> release.
func parseReleases(b []byte) map[string]release {
	out := map[string]release{}
	key := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if m := globalSourceLine.FindStringSubmatch(line); m != nil {
			key = m[1] + " " + m[2] + " " + m[3]
			out[key] = release{}
			continue
		}
		if key == "" {
			continue
		}
		rel := out[key]
		if m := releaseLine.FindStringSubmatch(line); m != nil {
			for _, f := range strings.Split(m[1], ",") {
				k, v, _ := strings.Cut(f, "=")
				switch k {
				case "o":
					rel.Origin = v
				case "l":
					rel.Label = v
				case "a":
					rel.Archive = v
				case "n":
					rel.Codename = v
				case "c":
					rel.Component = v
				}
			}
		} else if m := originLine.FindStringSubmatch(line); m != nil {
			rel.Site = m[1]
		} else if !strings.HasPrefix(line, "     ") {
			key = ""
			continue
		}
		out[key] = rel
	}
	return out
}

// uuRules are the settings of unattended-upgrades that select packages.
type uuRules struct {
	allowed   [][2]string // origin, archive
	patterns  []map[string]string
	blacklist []*regexp.Regexp
	badBlack  []string // blacklist entries Go cannot compile
	whitelist []*regexp.Regexp
	strict    bool
}

// expand replaces unattended-upgrades' variables.
func expand(s, distroID, codename string) string {
	return strings.NewReplacer("${distro_id}", distroID, "${distro_codename}", codename).Replace(s)
}

func newUURules(c aptConfig, distroID, codename string) (uuRules, []string) {
	var r uuRules
	shown := make([]string, 0, len(c["Unattended-Upgrade::Allowed-Origins"])+len(c["Unattended-Upgrade::Origins-Pattern"]))
	for _, a := range c["Unattended-Upgrade::Allowed-Origins"] {
		a = expand(a, distroID, codename)
		shown = append(shown, a)
		// "origin:archive"; the origin itself may hold no colon.
		if i := strings.LastIndex(a, ":"); i > 0 {
			r.allowed = append(r.allowed, [2]string{a[:i], a[i+1:]})
		}
	}
	for _, p := range c["Unattended-Upgrade::Origins-Pattern"] {
		p = expand(p, distroID, codename)
		shown = append(shown, p)
		r.patterns = append(r.patterns, parsePattern(p))
	}
	for _, b := range c["Unattended-Upgrade::Package-Blacklist"] {
		// unattended-upgrades applies Python's re.match: anchored at the
		// start only.
		if re, err := regexp.Compile("^(?:" + b + ")"); err == nil {
			r.blacklist = append(r.blacklist, re)
		} else {
			r.badBlack = append(r.badBlack, b)
		}
	}
	for _, w := range c["Unattended-Upgrade::Package-Whitelist"] {
		if re, err := regexp.Compile("^(?:" + w + ")"); err == nil {
			r.whitelist = append(r.whitelist, re)
		}
	}
	r.strict = truthy(c.value("Unattended-Upgrade::Package-Whitelist-Strict"))
	return r, shown
}

// parsePattern splits "origin=Debian,codename=bookworm,label=Debian-Security"
// on commas not escaped as "\,".
func parsePattern(p string) map[string]string {
	m := map[string]string{}
	var parts []string
	cur := ""
	for i := 0; i < len(p); i++ {
		switch {
		case p[i] == '\\' && i+1 < len(p) && p[i+1] == ',':
			cur += ","
			i++
		case p[i] == ',':
			parts = append(parts, cur)
			cur = ""
		default:
			cur += string(p[i])
		}
	}
	parts = append(parts, cur)
	for _, part := range parts {
		k, v, _ := strings.Cut(part, "=")
		m[strings.TrimSpace(k)] = v
	}
	return m
}

// allows reports whether a package file's release matches an allowed
// origin or pattern.
func (r uuRules) allows(rel release) bool {
	for _, a := range r.allowed {
		if rel.Origin == a[0] && rel.Archive == a[1] {
			return true
		}
	}
	for _, p := range r.patterns {
		if matchPattern(p, rel) {
			return true
		}
	}
	return false
}

func matchPattern(p map[string]string, rel release) bool {
	if len(p) == 0 {
		return false
	}
	for k, v := range p {
		var have string
		switch k {
		case "o", "origin":
			have = rel.Origin
		case "l", "label":
			have = rel.Label
		case "a", "suite", "archive":
			have = rel.Archive
		case "c", "component":
			have = rel.Component
		case "n", "codename":
			have = rel.Codename
		case "site":
			have = rel.Site
		default:
			return false
		}
		if ok, err := path.Match(v, have); err != nil || !ok {
			return false
		}
	}
	return true
}

// predictUnattended applies unattended-upgrades' rules to the pending
// updates: a package is upgraded to the newest version, above the
// installed one, that comes from an allowed origin. That can be older
// than apt's candidate (tzdata on the Ubuntu lab VM: 2026c from -security,
// not 2026e from -updates).
func predictUnattended(r *Report, c aptConfig, rels map[string]release, ts map[string]timer, distroID, codename string) *Autopilot {
	a := &Autopilot{Tool: "unattended-upgrades", Installed: true, Install: []Planned{}}
	rules, shown := newUURules(c, distroID, codename)
	a.Origins = shown
	for _, b := range rules.badBlack {
		a.Why = append(a.Why, "blacklist entry "+quote(b)+" is not understood; the prediction ignores it")
	}

	t := ts["apt-daily-upgrade.timer"]
	a.Timer, a.NextRun, a.LastRun = t.ID, t.Next, t.Last
	runs := true
	if !truthy(c.value("APT::Periodic::Unattended-Upgrade")) {
		runs = false
		a.Why = append(a.Why, "APT::Periodic::Unattended-Upgrade is off")
	}
	if !t.active() {
		runs = false
		a.Why = append(a.Why, "apt-daily-upgrade.timer is "+t.state())
	}
	a.Runs = runs

	a.Reboot = "never"
	if truthy(c.value("Unattended-Upgrade::Automatic-Reboot")) {
		when := c.value("Unattended-Upgrade::Automatic-Reboot-Time")
		if when == "" || when == "now" {
			when = "right after the run"
		} else {
			when = "at " + when
		}
		a.Reboot = "when /run/reboot-required exists, " + when
		if !truthy(c.value("Unattended-Upgrade::Automatic-Reboot-WithUsers")) && c.value("Unattended-Upgrade::Automatic-Reboot-WithUsers") != "" {
			a.Reboot += ", unless users are logged in"
		}
	}

	if r.apt == nil {
		return a
	}
	for _, u := range r.Updates {
		skip := func(reason string) {
			a.Skip = append(a.Skip, Skipped{Name: u.Name, Arch: u.Arch, Candidate: u.Candidate, Reason: reason})
		}
		if u.State == Held {
			skip("held")
			continue
		}
		if slices.ContainsFunc(rules.blacklist, func(re *regexp.Regexp) bool { return re.MatchString(u.Name) }) {
			skip("blacklisted")
			continue
		}
		if rules.strict && !slices.ContainsFunc(rules.whitelist, func(re *regexp.Regexp) bool { return re.MatchString(u.Name) }) {
			skip("not in the strict whitelist")
			continue
		}
		p, ok := r.apt.policies[policyName(u, r.apt.nativeArch)]
		if !ok {
			skip("no version table")
			continue
		}
		target := ""
		for _, v := range p.Versions {
			if v.Installed || (p.Installed != "" && v.Version == p.Installed) {
				break
			}
			if slices.ContainsFunc(v.Sources, func(s string) bool { return rules.allows(rels[s]) }) {
				target = v.Version
				break
			}
		}
		switch {
		case target == "":
			skip("no newer version from an allowed origin")
		case u.State == Phased && target == u.Candidate:
			skip("deferred by phasing")
		default:
			a.Install = append(a.Install, Planned{Name: u.Name, Arch: u.Arch, From: u.Installed, To: target, Security: p.securityFix(target)})
		}
	}
	return a
}

func quote(s string) string { return `"` + s + `"` }
