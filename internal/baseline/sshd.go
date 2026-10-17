package baseline

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
)

// SSHDCheck is ComplianceAsCode's sshd_lineinfile template. It is not
// sshd's own rule: the OVAL reads every line that sets Keyword in
// /etc/ssh/sshd_config and, with DropIns, in /etc/ssh/sshd_config.d/*.conf,
// ignores Include and Match, and requires every one of them to have an
// allowed value and at least one to exist (unless MissingPass). The check
// passes when Package (openssh-server) is not installed.
//
// A line sets the keyword when it matches
// ^[ \t]*(?i)KEYWORD(?-i)[ \t]+(.+?)[ \t]*(?:$|#): the keyword is
// case-insensitive, and "Keyword=value" does not count.
type SSHDCheck struct {
	Keyword string `yaml:"keyword"`
	// Value is compared by Match: "regex" (^Value$, case-sensitive) or
	// "equals" (as Datatype: int or string).
	Value       string `yaml:"value"`
	Match       string `yaml:"match"`
	Datatype    string `yaml:"datatype,omitempty"`
	DropIns     bool   `yaml:"drop_ins,omitempty"`
	MissingPass bool   `yaml:"missing_pass,omitempty"`
	Package     string `yaml:"package"`
}

const (
	sshdConfig = "/etc/ssh/sshd_config"
	sshdDropIn = "/etc/ssh/sshd_config.d"
)

var sshKeywordRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

func (s *SSHDCheck) validate() error {
	if !sshKeywordRE.MatchString(s.Keyword) {
		return fmt.Errorf("sshd: keyword %q is not valid", s.Keyword)
	}
	switch s.Match {
	case "regex":
		if _, err := regexp.Compile("^" + s.Value + "$"); err != nil {
			return fmt.Errorf("sshd: value: %w", err)
		}
	case "equals":
		if s.Datatype == "int" {
			if _, err := strconv.ParseInt(s.Value, 10, 64); err != nil {
				return fmt.Errorf("sshd: value %q is not an int", s.Value)
			}
		} else if s.Datatype != "string" {
			return fmt.Errorf("sshd: datatype %q, want int or string", s.Datatype)
		}
	default:
		return fmt.Errorf("sshd: match %q, want regex or equals", s.Match)
	}
	if s.Package == "" {
		return errors.New("sshd: package is necessary")
	}
	return nil
}

func (s *SSHDCheck) eval(h *Host) (bool, string, error) {
	if h.Packages == nil {
		return false, "", unknownf("package database not read")
	}
	if _, ok := h.Packages[s.Package]; !ok {
		return true, "package " + s.Package + " is not installed", nil
	}
	re := regexp.MustCompile(`(?m)^[ \t]*(?i)` + s.Keyword + `(?-i)[ \t]+(.+?)[ \t]*(?:$|#)`)
	paths := []string{sshdConfig}
	if s.DropIns {
		paths = append(paths, confFiles(h, sshdDropIn)...)
		if _, err := h.ReadDir(sshdDropIn); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, "", err
		}
	}
	var found, bad []string
	for _, p := range paths {
		b, err := h.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, "", err
		}
		for _, m := range re.FindAllSubmatch(b, -1) {
			v := string(m[1])
			found = append(found, p+": "+v)
			if !s.allowed(v) {
				bad = append(bad, p+": "+s.Keyword+" "+v)
			}
		}
	}
	switch {
	case len(bad) > 0:
		return false, summarize(bad) + ", want " + s.Value, nil
	case len(found) == 0 && !s.MissingPass:
		return false, s.Keyword + " is not set", nil
	case len(found) == 0:
		return true, s.Keyword + " is not set (allowed)", nil
	}
	return true, summarize(found), nil
}

func (s *SSHDCheck) allowed(v string) bool {
	if s.Match == "regex" {
		return regexp.MustCompile("^" + s.Value + "$").MatchString(v)
	}
	if s.Datatype == "int" {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		m, _ := strconv.ParseInt(s.Value, 10, 64)
		return err == nil && n == m
	}
	return v == s.Value
}

// stricter notes a check that fails although sshd itself gets an allowed
// value. sshd uses the first value it reads for a keyword, and it reads
// an Include at the place of the Include line; the rule wants every line
// to have an allowed value, and without DropIns it reads only
// sshd_config. The note is given only when the first value sshd reads,
// before any Match block, is allowed.
func (s *SSHDCheck) stricter(h *Host) string {
	if _, ok := h.Packages[s.Package]; !ok {
		return ""
	}
	v, from, ok := s.sshdValue(h)
	if !ok || !s.allowed(v) {
		return ""
	}
	if !s.DropIns && from != sshdConfig {
		return "The rule reads only " + sshdConfig + ". sshd gets " + s.Keyword + " " + v + " from " + from + ", which the rule does not read."
	}
	return "sshd uses the first value it reads, " + s.Keyword + " " + v + " from " + from + ". The rule wants every line that sets " + s.Keyword + " to have an allowed value."
}

// sshdValue is the value sshd uses for s.Keyword outside Match blocks:
// the first one in sshd_config, with each "Include" of sshd_config.d
// read in its place, in lexical order. It reports false when it cannot
// tell (an unreadable file, or an Include of other files).
func (s *SSHDCheck) sshdValue(h *Host) (value, from string, ok bool) {
	b, err := h.ReadFile(sshdConfig)
	if err != nil {
		return "", "", false
	}
	key := regexp.MustCompile(`^(?i)` + s.Keyword + `(?-i)[ \t]+(.+?)[ \t]*(?:$|#)`)
	var walk func(path string, data []byte, depth int) (string, string, bool, bool)
	// walk returns value, file, found, and stop (a Match line or an
	// Include the agent cannot follow ends the search).
	walk = func(path string, data []byte, depth int) (string, string, bool, bool) {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimLeft(line, " \t")
			f := strings.Fields(line)
			if len(f) == 0 || strings.HasPrefix(f[0], "#") {
				continue
			}
			switch strings.ToLower(f[0]) {
			case "match":
				return "", "", false, true
			case "include":
				if depth > 0 || len(f) != 2 || f[1] != sshdDropIn+"/*.conf" {
					return "", "", false, true
				}
				for _, p := range confFiles(h, sshdDropIn) {
					d, err := h.ReadFile(p)
					if err != nil {
						return "", "", false, true
					}
					if v, from, found, stop := walk(p, d, depth+1); found || stop {
						return v, from, found, stop
					}
				}
				continue
			}
			if m := key.FindStringSubmatch(line); m != nil {
				return m[1], path, true, false
			}
		}
		return "", "", false, false
	}
	v, from, found, _ := walk(sshdConfig, b, 0)
	return v, from, found
}
