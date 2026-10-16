package baseline

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

// Condition is one applicability test. Exactly one field is set. They
// reproduce ComplianceAsCode's platform checks (CPE OVAL):
//
//   - package: the package is installed (system_with_kernel is the
//     product's kernel package; grub2 is grub2-common).
//   - file_exists: the path exists (the container tests).
//   - mounted: the path is a mount point, or /etc/fstab has a line for it,
//     even a commented one (mount[...]).
//   - service_disabled: the service_disabled test (service_disabled[...]).
//   - ipv6_enabled: GRUB_CMDLINE_LINUX in /etc/default/grub does not set
//     ipv6.disable=1 (ipv6[enabled]).
//   - not, any: negation and disjunction.
type Condition struct {
	Package         string        `yaml:"package,omitempty"`
	FileExists      string        `yaml:"file_exists,omitempty"`
	Mounted         string        `yaml:"mounted,omitempty"`
	ServiceDisabled *ServiceCheck `yaml:"service_disabled,omitempty"`
	IPv6Enabled     bool          `yaml:"ipv6_enabled,omitempty"`
	Not             *Condition    `yaml:"not,omitempty"`
	Any             []Condition   `yaml:"any,omitempty"`
}

func (c *Condition) validate() error {
	n := 0
	for _, set := range []bool{c.Package != "", c.FileExists != "", c.Mounted != "",
		c.ServiceDisabled != nil, c.IPv6Enabled, c.Not != nil, len(c.Any) > 0} {
		if set {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("condition has %d tests, want exactly 1", n)
	}
	switch {
	case c.Package != "" && !pkgNameRE.MatchString(c.Package):
		return fmt.Errorf("condition: package %q is not valid", c.Package)
	case c.FileExists != "" && !path.IsAbs(c.FileExists),
		c.Mounted != "" && (!path.IsAbs(c.Mounted) || path.Clean(c.Mounted) != c.Mounted || len(c.Mounted) > 120):
		return errors.New("condition: path is not a clean absolute path")
	case c.ServiceDisabled != nil:
		return c.ServiceDisabled.validate()
	case c.Not != nil:
		return c.Not.validate()
	}
	for i := range c.Any {
		if err := c.Any[i].validate(); err != nil {
			return err
		}
	}
	return nil
}

var grubIPv6RE = regexp.MustCompile(`(?m)^\s*GRUB_CMDLINE_LINUX=".*ipv6\.disable=(\d).*$`)

// holds evaluates the condition. why describes a false result.
func (c *Condition) holds(h *Host) (bool, string, error) {
	switch {
	case c.Package != "":
		if h.Packages == nil {
			return false, "", unknownf("package database not read")
		}
		_, ok := h.Packages[c.Package]
		return ok, "package " + c.Package + " is not installed", nil
	case c.FileExists != "":
		_, err := h.Stat(c.FileExists)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, "", err
		}
		return err == nil, c.FileExists + " does not exist", nil
	case c.Mounted != "":
		l, err := fstabLine(h, c.Mounted, false, "")
		if err != nil {
			return false, "", err
		}
		if l != nil {
			return true, "", nil
		}
		return hostMount(h, c.Mounted).mounted, c.Mounted + " is not a separate mount and not in /etc/fstab", nil
	case c.ServiceDisabled != nil:
		ok, why, err := c.ServiceDisabled.eval(h)
		return ok, c.ServiceDisabled.Name + " is not disabled: " + why, err
	case c.IPv6Enabled:
		b, err := h.ReadFile("/etc/default/grub")
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, "", err
		}
		ms := grubIPv6RE.FindAllSubmatch(b, -1)
		disabled := len(ms) > 0
		for _, m := range ms {
			if string(m[1]) != "1" {
				disabled = false
			}
		}
		return !disabled, "IPv6 is disabled on the kernel command line", nil
	case c.Not != nil:
		ok, why, err := c.Not.holds(h)
		if err != nil {
			return false, "", err
		}
		if ok {
			return false, "not: " + c.Not.describe(), nil
		}
		return true, why, nil
	default:
		var whys []string
		for i := range c.Any {
			ok, why, err := c.Any[i].holds(h)
			if err != nil {
				return false, "", err
			}
			if ok {
				return true, "", nil
			}
			whys = append(whys, why)
		}
		return false, strings.Join(whys, "; "), nil
	}
}

func (c *Condition) describe() string {
	switch {
	case c.Package != "":
		return "package " + c.Package + " is installed"
	case c.FileExists != "":
		return c.FileExists + " exists"
	case c.Mounted != "":
		return c.Mounted + " is mounted"
	case c.ServiceDisabled != nil:
		return c.ServiceDisabled.Name + " is disabled"
	case c.IPv6Enabled:
		return "IPv6 is enabled"
	case c.Not != nil:
		return "not " + c.Not.describe()
	default:
		return "one of several conditions"
	}
}

// unitsRead lists the systemd units a check and its conditions read.
func (c *Check) unitsRead() []string {
	var out []string
	var cond func(*Condition)
	cond = func(w *Condition) {
		switch {
		case w.ServiceDisabled != nil:
			out = append(out, w.ServiceDisabled.units()...)
		case w.Mounted != "":
			out = append(out, mountUnit(w.Mounted))
		case w.Not != nil:
			cond(w.Not)
		}
		for i := range w.Any {
			cond(&w.Any[i])
		}
	}
	for i := range c.When {
		cond(&c.When[i])
	}
	switch {
	case c.Service != nil:
		out = append(out, c.Service.units()...)
	case c.Mount != nil:
		out = append(out, mountUnit(c.Mount.Path))
	}
	return out
}

// needsDeps reports whether any check reads multi-user.target's
// dependencies.
func (b *Baseline) needsDeps() bool {
	for i := range b.Checks {
		if s := b.Checks[i].Service; s != nil && s.State == "enabled" {
			return true
		}
	}
	return false
}
