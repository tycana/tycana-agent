package updates

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"tycana.ai/agent/internal/hostexec"
)

// CollectApt asks apt what an upgrade would do. held names the packages
// the operator put on hold (from the dpkg database); apt leaves them out
// of its simulation, so their candidates come from apt-cache policy, as do
// the updates apt defers by phasing. nativeArch is dpkg's architecture,
// for packages apt names without one.
func CollectApt(ctx context.Context, nativeArch string, held []string) (Report, error) {
	return collectApt(ctx, hostexec.Run, nativeArch, held)
}

func collectApt(ctx context.Context, run runner, nativeArch string, held []string) (Report, error) {
	full, err := run(ctx, hostexec.AptSimulateDistUpgrade)
	if err != nil {
		return Report{}, err
	}
	plain, err := run(ctx, hostexec.AptSimulateUpgrade)
	if err != nil {
		return Report{}, err
	}
	fs, err := parseSimulation(full.Stdout)
	if err != nil {
		return Report{}, fmt.Errorf("apt-get --simulate dist-upgrade: %w", err)
	}
	ps, err := parseSimulation(plain.Stdout)
	if err != nil {
		return Report{}, fmt.Errorf("apt-get --simulate upgrade: %w", err)
	}

	r := Report{Schema: Schema, Manager: "apt", Removals: fs.removals}
	inPlain := map[string]bool{}
	for _, in := range ps.installs {
		inPlain[in.Name+":"+in.Arch] = true
	}
	for _, in := range fs.installs {
		switch {
		case in.Installed == "":
			in.State = New
		case inPlain[in.Name+":"+in.Arch]:
			in.State = Upgrade
		default:
			in.State = DistUpgrade
		}
		r.Updates = append(r.Updates, in)
	}

	// The policy gives the candidates of phased and held packages, which
	// the simulation leaves out, and the version tables that decide which
	// updates carry a security fix.
	phased := map[string]bool{}
	for _, n := range fs.lists[headPhased] {
		phased[n] = true
	}
	query := slices.Concat(fs.lists[headPhased], held)
	for _, u := range r.Updates {
		query = append(query, policyName(u, nativeArch))
	}
	pkgs, err := policy(ctx, run, query)
	if err != nil {
		return Report{}, err
	}
	byName := map[string]policyPkg{}
	for _, p := range pkgs {
		byName[p.query] = p
	}
	for i, u := range r.Updates {
		if p, ok := byName[policyName(u, nativeArch)]; ok {
			r.Updates[i].Security = p.securityFix(u.Candidate)
			r.Updates[i].Origins = p.origins(u.Candidate)
		}
	}
	for _, q := range slices.Concat(fs.lists[headPhased], held) {
		p, ok := byName[q]
		if !ok || p.Candidate == "" || p.Candidate == p.Installed {
			continue // a hold with nothing newer
		}
		u := Update{Name: p.Name, Arch: p.Arch, Installed: p.Installed, Candidate: p.Candidate, State: Held}
		if u.Arch == "" {
			u.Arch = nativeArch
		}
		if phased[q] {
			u.State = Phased
		}
		for _, v := range p.Versions {
			if v.Version == p.Candidate {
				u.PhasedPercent = v.PhasedPercent
			}
		}
		u.Origins = p.origins(p.Candidate)
		u.Security = p.securityFix(p.Candidate)
		r.Updates = append(r.Updates, u)
	}
	slices.SortFunc(r.Updates, func(a, b Update) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Arch, b.Arch))
	})
	return r, nil
}

// Headings of the package lists in apt-get's simulation output (LC_ALL=C).
const (
	headPhased = "The following upgrades have been deferred due to phasing:"
)

type simulation struct {
	installs []Update
	removals []Removal
	// lists maps a heading line to the package names listed under it.
	lists map[string][]string
}

// Inst name [installed] (candidate origin, origin [arch]) [...]
// The installed version is absent for a new package; the origin list can
// be empty for a repository without a Release file.
var (
	instLine = regexp.MustCompile(`^Inst (\S+) (?:\[([^\]]+)\] )?\((\S+)(?: (.*?))? \[([^\]]+)\]\)`)
	remvLine = regexp.MustCompile(`^Remv (\S+) \[([^\]]+)\]`)
)

func parseSimulation(out []byte) (simulation, error) {
	s := simulation{lists: map[string][]string{}}
	var heading string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "  ") && heading != "":
			s.lists[heading] = append(s.lists[heading], strings.Fields(line)...)
			continue
		case strings.HasPrefix(line, "The following ") && strings.HasSuffix(line, ":"):
			heading = line
			continue
		}
		heading = ""
		switch {
		case strings.HasPrefix(line, "Inst "):
			m := instLine.FindStringSubmatch(line)
			if m == nil {
				return s, fmt.Errorf("unrecognized line %q", line)
			}
			name, _, _ := strings.Cut(m[1], ":")
			u := Update{Name: name, Arch: m[5], Installed: m[2], Candidate: m[3], Origins: parseInstOrigins(m[4])}
			u.Security = slices.ContainsFunc(u.Origins, func(o Origin) bool { return isSecuritySuite(o.Suite) })
			s.installs = append(s.installs, u)
		case strings.HasPrefix(line, "Remv "):
			m := remvLine.FindStringSubmatch(line)
			if m == nil {
				return s, fmt.Errorf("unrecognized line %q", line)
			}
			name, arch, _ := strings.Cut(m[1], ":")
			s.removals = append(s.removals, Removal{Name: name, Arch: arch, Installed: m[2]})
		}
	}
	return s, sc.Err()
}

// parseInstOrigins splits "Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security"
// into archive names. apt-cache policy replaces them with suite names when
// it knows the package.
func parseInstOrigins(s string) []Origin {
	var out []Origin
	for _, part := range strings.Split(s, ", ") {
		if part == "" {
			continue
		}
		_, rest, _ := strings.Cut(part, ":")
		_, suite, ok := strings.Cut(rest, "/")
		if !ok {
			suite = rest
		}
		out = append(out, Origin{Suite: suite})
	}
	return out
}

// AptName is how apt names a package in a query and in apt-cache policy
// output: bare for the native architecture and "all", qualified for a
// foreign one ("libc6:i386").
func AptName(name, arch, nativeArch string) string {
	if arch == nativeArch || arch == "all" || arch == "" {
		return name
	}
	return name + ":" + arch
}

func policyName(u Update, nativeArch string) string { return AptName(u.Name, u.Arch, nativeArch) }

// policy runs apt-cache policy in batches of at most hostexec's limit.
func policy(ctx context.Context, run runner, names []string) ([]policyPkg, error) {
	var out []policyPkg
	for batch := range slices.Chunk(names, 1000) {
		res, err := run(ctx, hostexec.AptCachePolicy, batch...)
		if err != nil {
			return nil, err
		}
		pkgs, err := parsePolicy(res.Stdout)
		if err != nil {
			return nil, fmt.Errorf("apt-cache policy: %w", err)
		}
		out = append(out, pkgs...)
	}
	return out, nil
}

// securityFix reports whether upgrading to candidate brings a version
// published in a security pocket: the candidate itself, or any version
// between the installed one and the candidate. This is the rule of
// Ubuntu's apt-check. tzdata on the lab VM: the candidate 2026e is in
// noble-updates only, but 2026c, between it and the installed 2024a, is in
// noble-security. apt-cache lists versions newest first, so the versions
// that count are those from the candidate down to the installed one.
func (p policyPkg) securityFix(candidate string) bool {
	counting := false
	for _, v := range p.Versions {
		if v.Version == candidate {
			counting = true
		}
		if v.Installed || (p.Installed != "" && v.Version == p.Installed) {
			break
		}
		if counting && slices.ContainsFunc(v.Origins, func(o Origin) bool { return isSecuritySuite(o.Suite) }) {
			return true
		}
	}
	return false
}

// origins are the suites that offer version, as sources.list names them
// ("bookworm-security"; the simulation would say "oldstable-security").
func (p policyPkg) origins(version string) []Origin {
	for _, v := range p.Versions {
		if v.Version == version {
			return v.Origins
		}
	}
	return nil
}

type policyPkg struct {
	query      string // the name as asked, with ":arch" if given
	Name, Arch string
	Installed  string
	Candidate  string
	Versions   []policyVersion
}

type policyVersion struct {
	Version       string
	Priority      int
	Installed     bool
	PhasedPercent int
	Origins       []Origin
}

// "     2.77.1+ubuntu24.04 500 (phased 30%)" and " *** 2.76.3 100"
var (
	policyVersionLine = regexp.MustCompile(`^ (\*\*\*|   ) (\S+) (-?\d+)(?: \(phased (\d+)%\))?$`)
	// "        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages"
	policySourceLine = regexp.MustCompile(`^ {8}-?\d+ (\S+)(?: (\S+) (\S+)(?: Packages)?)?`)
)

func parsePolicy(out []byte) ([]policyPkg, error) {
	var pkgs []policyPkg
	var cur *policyPkg
	var ver *policyVersion
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
		case !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":"):
			q := strings.TrimSuffix(line, ":")
			name, arch, _ := strings.Cut(q, ":")
			pkgs = append(pkgs, policyPkg{query: q, Name: name, Arch: arch})
			cur, ver = &pkgs[len(pkgs)-1], nil
		case cur == nil:
			return nil, fmt.Errorf("unrecognized line %q", line)
		case strings.HasPrefix(line, "  Installed: "):
			cur.Installed = none(strings.TrimPrefix(line, "  Installed: "))
		case strings.HasPrefix(line, "  Candidate: "):
			cur.Candidate = none(strings.TrimPrefix(line, "  Candidate: "))
		case line == "  Version table:":
		case policyVersionLine.MatchString(line):
			m := policyVersionLine.FindStringSubmatch(line)
			prio, _ := strconv.Atoi(m[3])
			pct, _ := strconv.Atoi(m[4])
			cur.Versions = append(cur.Versions, policyVersion{Version: m[2], Priority: prio, Installed: m[1] == "***", PhasedPercent: pct})
			ver = &cur.Versions[len(cur.Versions)-1]
		case ver != nil && policySourceLine.MatchString(line):
			m := policySourceLine.FindStringSubmatch(line)
			if m[2] == "" {
				continue // "100 /var/lib/dpkg/status"
			}
			suite, _, _ := strings.Cut(m[2], "/")
			if !slices.Contains(ver.Origins, Origin{Suite: suite}) {
				ver.Origins = append(ver.Origins, Origin{Suite: suite})
			}
		default:
			return nil, fmt.Errorf("unrecognized line %q", line)
		}
	}
	return pkgs, sc.Err()
}

func none(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}
