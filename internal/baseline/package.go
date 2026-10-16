package baseline

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// PackageCheck is ComplianceAsCode's package_installed and package_removed
// templates: OVAL's rpminfo or dpkginfo object by exact name, any
// architecture, any version.
type PackageCheck struct {
	// Names are the packages. For "absent", every one must be absent; for
	// "present", every one must be installed.
	Names []string `yaml:"names"`
	State string   `yaml:"state"` // "present" or "absent"
}

var pkgNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)

func (p *PackageCheck) validate() error {
	if len(p.Names) == 0 {
		return errors.New("package: names is empty")
	}
	for _, n := range p.Names {
		if !pkgNameRE.MatchString(n) {
			return fmt.Errorf("package: name %q is not valid", n)
		}
	}
	if p.State != "present" && p.State != "absent" {
		return fmt.Errorf("package: state %q, want present or absent", p.State)
	}
	return nil
}

func (p *PackageCheck) eval(h *Host) (bool, string, error) {
	if h.Packages == nil {
		return false, "", unknownf("package database not read")
	}
	var have, missing []string
	for _, n := range p.Names {
		if _, ok := h.Packages[n]; ok {
			have = append(have, n)
		} else {
			missing = append(missing, n)
		}
	}
	if p.State == "absent" {
		if len(have) > 0 {
			return false, "installed: " + strings.Join(have, ", "), nil
		}
		return true, "not installed: " + strings.Join(p.Names, ", "), nil
	}
	if len(missing) > 0 {
		return false, "not installed: " + strings.Join(missing, ", "), nil
	}
	return true, "installed: " + strings.Join(p.Names, ", "), nil
}
