package baseline

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// ServiceCheck is ComplianceAsCode's service_enabled, service_disabled,
// and socket_disabled templates, as their OVAL 5.11 systemd tests compute
// them. A unit "exists" when systemd has a unit file for it (LoadState is
// not "not-found").
//
//   - disabled: passes when Package is not installed, or when every
//     existing Name.service and Name.socket is masked and not active
//     (ActiveState inactive or failed). A unit that is only disabled
//     fails: the content asks for "masked".
//   - enabled: passes when Package is installed, at least one existing
//     Name.service or Name.socket is active, and multi-user.target
//     depends on one of them (systemctl list-dependencies --all).
//   - socket_masked: passes when Name.socket does not exist or is masked.
type ServiceCheck struct {
	Name    string `yaml:"name"`
	State   string `yaml:"state"`
	Package string `yaml:"package,omitempty"`
}

// serviceNameRE is a systemd unit prefix: no "@" template forms, no
// escapes, at most 200 characters, so every unit name built from it passes
// hostexec's check and one bad name cannot fail the systemctl batch.
var serviceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_:.-]{0,199}$`)

func (s *ServiceCheck) validate() error {
	if !serviceNameRE.MatchString(s.Name) {
		return fmt.Errorf("service: name %q is not valid", s.Name)
	}
	switch s.State {
	case "enabled", "disabled":
		if s.Package == "" {
			return errors.New("service: package is necessary")
		}
	case "socket_masked":
	default:
		return fmt.Errorf("service: state %q, want enabled, disabled, or socket_masked", s.State)
	}
	return nil
}

func (s *ServiceCheck) units() []string {
	if s.State == "socket_masked" {
		return []string{s.Name + ".socket"}
	}
	return []string{s.Name + ".service", s.Name + ".socket"}
}

func (s *ServiceCheck) eval(h *Host) (bool, string, error) {
	if s.State != "socket_masked" && h.Packages == nil {
		return false, "", unknownf("package database not read")
	}
	var exist []map[string]string
	for _, u := range s.units() {
		p, ok := h.Units[u]
		if !ok {
			return false, "", unknownf("systemd state of %s not read", u)
		}
		if p["LoadState"] != "not-found" {
			exist = append(exist, p)
		}
	}
	_, installed := h.Packages[s.Package]
	switch s.State {
	case "disabled", "socket_masked":
		if s.State == "disabled" && !installed {
			return true, "package " + s.Package + " is not installed", nil
		}
		var bad []string
		for _, p := range exist {
			if p["LoadState"] != "masked" || !strings.Contains(p["ActiveState"], "inactive") && !strings.Contains(p["ActiveState"], "failed") {
				bad = append(bad, fmt.Sprintf("%s is %s and %s", p["Id"], p["LoadState"], p["ActiveState"]))
			}
		}
		if len(bad) > 0 {
			return false, strings.Join(bad, "; ") + " (want masked and inactive)", nil
		}
		if len(exist) == 0 {
			return true, "no unit file for " + strings.Join(s.units(), " or "), nil
		}
		return true, "masked and inactive", nil
	default:
		if !installed {
			return false, "package " + s.Package + " is not installed", nil
		}
		if h.Wanted == nil {
			return false, "", unknownf("dependencies of multi-user.target not read")
		}
		active := slices.ContainsFunc(exist, func(p map[string]string) bool { return p["ActiveState"] == "active" })
		wanted := slices.Contains(h.Wanted, s.Name+".service") || slices.Contains(h.Wanted, s.Name+".socket")
		switch {
		case !active:
			return false, s.Name + " is not active", nil
		case !wanted:
			return false, "multi-user.target does not start " + s.Name, nil
		}
		return true, s.Name + " is active and started by multi-user.target", nil
	}
}

// stricter notes a "disabled" check that fails only because a unit is
// disabled, not masked: every existing unit is disabled, inactive, and
// not in multi-user.target's dependencies, so systemd does not start it
// at boot, and the rule still wants "masked".
func (s *ServiceCheck) stricter(h *Host) string {
	if s.State != "disabled" {
		return ""
	}
	n := 0
	for _, u := range s.units() {
		p := h.Units[u]
		if p == nil || p["LoadState"] == "not-found" {
			continue
		}
		n++
		if p["LoadState"] == "masked" {
			continue
		}
		active := !strings.Contains(p["ActiveState"], "inactive") && !strings.Contains(p["ActiveState"], "failed")
		if p["UnitFileState"] != "disabled" || active || h.Wanted == nil || slices.Contains(h.Wanted, u) {
			return ""
		}
	}
	if n == 0 {
		return ""
	}
	return "The rule wants the unit masked. Disabled is not enough for the rule, although systemd does not start a disabled unit at boot."
}
