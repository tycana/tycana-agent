package baseline

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// SysctlCheck is ComplianceAsCode's sysctl template. It passes when the
// configuration files set the key to an allowed value and, with Runtime,
// the running kernel has an allowed value.
//
// Configuration, as the OVAL computes it:
//   - "user" files are UserFiles and every *.conf in UserDirs. When at
//     least one line in them sets the key, every such line must have an
//     allowed value.
//   - When none sets it, every line in /usr/lib/sysctl.d/*.conf that sets
//     it must have an allowed value, and at least one must exist (or none
//     need exist, with MissingPass).
//
// A line sets the key when it matches ^\s*KEY\s*=\s*(.*\S)\s*$ with KEY
// used as a regular expression, as the OVAL does ("." matches "/").
type SysctlCheck struct {
	Key      string   `yaml:"key"`
	Values   []string `yaml:"values"`
	Datatype string   `yaml:"datatype"` // "int" or "string"
	Runtime  bool     `yaml:"runtime"`
	// UserFiles and UserDirs are the product's "user" configuration
	// (ComplianceAsCode lists them per product).
	UserFiles   []string `yaml:"user_files"`
	UserDirs    []string `yaml:"user_dirs"`
	MissingPass bool     `yaml:"missing_pass,omitempty"`
	// IPv6 makes the check pass also when IPv6 is disabled: the key
	// net.ipv6.conf.all.disable_ipv6 is 1 in configuration and at run
	// time.
	IPv6 bool `yaml:"ipv6,omitempty"`
}

const vendorSysctlDir = "/usr/lib/sysctl.d"

var sysctlKeyRE = regexp.MustCompile(`^[a-z0-9_]+(\.[a-zA-Z0-9_-]+)+$`)

func (s *SysctlCheck) validate() error {
	if !sysctlKeyRE.MatchString(s.Key) {
		return fmt.Errorf("sysctl: key %q is not valid", s.Key)
	}
	if len(s.Values) == 0 {
		return errors.New("sysctl: values is empty")
	}
	if s.Datatype != "int" && s.Datatype != "string" {
		return fmt.Errorf("sysctl: datatype %q, want int or string", s.Datatype)
	}
	if s.Datatype == "int" {
		for _, v := range s.Values {
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				return fmt.Errorf("sysctl: value %q is not an int", v)
			}
		}
	}
	for _, p := range slices.Concat(s.UserFiles, s.UserDirs) {
		if !path.IsAbs(p) {
			return fmt.Errorf("sysctl: %q is not absolute", p)
		}
	}
	return nil
}

func (s *SysctlCheck) eval(h *Host) (bool, string, error) {
	pass, why, err := s.evalOne(h)
	if err != nil || pass || !s.IPv6 {
		return pass, why, err
	}
	off := *s
	off.Key, off.Values, off.Datatype, off.IPv6, off.MissingPass = "net.ipv6.conf.all.disable_ipv6", []string{"1"}, "int", false, false
	off.Runtime = true
	if ok, _, err := off.evalOne(h); err == nil && ok {
		return true, "IPv6 is disabled", nil
	}
	return false, why, nil
}

func (s *SysctlCheck) evalOne(h *Host) (bool, string, error) {
	re := sysctlLineRE(s.Key)
	user, err := s.lines(h, re, s.userFiles(h))
	if err != nil {
		return false, "", err
	}
	var static bool
	var where string
	if len(user) > 0 {
		static, where = s.allAllowed(user), "in "+files(user)
	} else {
		vendor, err := s.lines(h, re, confFiles(h, vendorSysctlDir))
		if err != nil {
			return false, "", err
		}
		switch {
		case len(vendor) == 0 && s.MissingPass:
			static, where = true, "not set in any configuration file"
		case len(vendor) == 0:
			static, where = false, "not set in any configuration file"
		default:
			static, where = s.allAllowed(vendor), "in "+files(vendor)
		}
	}
	if !static {
		return false, fmt.Sprintf("%s: configuration %s, want %s", s.Key, describe(user, where), strings.Join(s.Values, " or ")), nil
	}
	if !s.Runtime {
		return true, fmt.Sprintf("%s set %s", s.Key, where), nil
	}
	b, err := h.ReadFile("/proc/sys/" + strings.ReplaceAll(s.Key, ".", "/"))
	if errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Sprintf("%s does not exist in the running kernel", s.Key), nil
	}
	if err != nil {
		return false, "", err
	}
	v := strings.TrimSpace(string(b))
	if !s.allowed(v) {
		return false, fmt.Sprintf("%s is %s at run time, want %s", s.Key, v, strings.Join(s.Values, " or ")), nil
	}
	return true, fmt.Sprintf("%s is %s at run time and set %s", s.Key, v, where), nil
}

// sysctlLineRE is the OVAL's line pattern for a key. The key is quoted;
// only its dots stay wildcards, as in the OVAL, so "net/ipv4/ip_forward"
// matches "net.ipv4.ip_forward". validate restricts keys to a grammar
// without other metacharacters.
func sysctlLineRE(key string) *regexp.Regexp {
	k := strings.ReplaceAll(regexp.QuoteMeta(key), `\.`, ".")
	return regexp.MustCompile(`(?m)^[\s]*` + k + `[\s]*=[\s]*(.*\S)[\s]*$`)
}

type sysctlLine struct{ file, value string }

func (s *SysctlCheck) userFiles(h *Host) []string {
	out := slices.Clone(s.UserFiles)
	for _, d := range s.UserDirs {
		out = append(out, confFiles(h, d)...)
	}
	return out
}

// confFiles lists *.conf in dir, sorted. A missing directory is empty.
func confFiles(h *Host, dir string) []string {
	ents, err := h.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".conf") {
			out = append(out, path.Join(dir, e.Name()))
		}
	}
	return out
}

func (s *SysctlCheck) lines(h *Host, re *regexp.Regexp, paths []string) ([]sysctlLine, error) {
	var out []sysctlLine
	for _, p := range paths {
		b, err := h.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, m := range re.FindAllSubmatch(b, -1) {
			out = append(out, sysctlLine{p, string(m[1])})
		}
	}
	return out, nil
}

func (s *SysctlCheck) allAllowed(ls []sysctlLine) bool {
	for _, l := range ls {
		if !s.allowed(l.value) {
			return false
		}
	}
	return true
}

func (s *SysctlCheck) allowed(v string) bool {
	if s.Datatype == "int" {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			return false
		}
		for _, w := range s.Values {
			if m, _ := strconv.ParseInt(w, 10, 64); m == n {
				return true
			}
		}
		return false
	}
	return slices.Contains(s.Values, v)
}

func files(ls []sysctlLine) string {
	var fs []string
	for _, l := range ls {
		if !slices.Contains(fs, l.file) {
			fs = append(fs, l.file)
		}
	}
	return summarize(fs)
}

func describe(ls []sysctlLine, where string) string {
	if len(ls) == 0 {
		return where
	}
	var vs []string
	for _, l := range ls {
		vs = append(vs, l.file+": "+l.value)
	}
	return summarize(vs)
}
