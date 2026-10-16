// Package baseline evaluates configuration baselines on a host: file
// modes and owners, kernel parameters, packages, services, the SSH
// server's configuration, mount options, and kernel modules.
//
// A baseline is a small YAML document (DSL version 1). The presets in
// presets/ are generated offline from ComplianceAsCode content by
// tools/cacconv; each check keeps the ComplianceAsCode rule id. Every
// check type reproduces the verdict of the ComplianceAsCode template it
// comes from, as OpenSCAP computes it; the lab comparison against
// OpenSCAP is in testdata/lab/*/baseline*.
//
// The agent reads as an unprivileged user inside a sandbox (ADR 0009).
// What it cannot read is "unknown", never "fail" (Mark, operator answer
// 5, 2026-10-15).
package baseline

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"go.yaml.in/yaml/v3"
)

const maxFile = 4 << 20

// Baseline is a named set of checks for one operating system release.
type Baseline struct {
	Version int    `yaml:"version"`
	Name    string `yaml:"name"`
	Title   string `yaml:"title"`
	Source  Source `yaml:"source"`
	// Applies names the os-release ID and VERSION_ID values the baseline
	// is for. A baseline is never run on another release.
	Applies    []Release   `yaml:"applies"`
	Checks     []Check     `yaml:"checks"`
	NotCovered []Uncovered `yaml:"not_covered,omitempty"`
}

// Source records where generated content came from.
type Source struct {
	Project string `yaml:"project" json:"project"`
	URL     string `yaml:"url" json:"url"`
	Commit  string `yaml:"commit" json:"commit"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
	Product string `yaml:"product" json:"product"`
	Profile string `yaml:"profile" json:"profile"`
	License string `yaml:"license" json:"license"`
}

// Release is one os-release ID and VERSION_ID pair.
type Release struct {
	ID        string `yaml:"id"`
	VersionID string `yaml:"version_id"`
}

// Uncovered is a source rule the baseline does not evaluate, and why.
type Uncovered struct {
	ID     string              `yaml:"id" json:"id"`
	Title  string              `yaml:"title" json:"title"`
	Refs   map[string][]string `yaml:"refs,omitempty" json:"refs,omitempty"`
	Reason string              `yaml:"reason" json:"reason"`
}

// Check is one rule. Exactly one probe field is set.
type Check struct {
	ID       string              `yaml:"id"`
	Title    string              `yaml:"title"`
	Severity string              `yaml:"severity,omitempty"`
	Refs     map[string][]string `yaml:"refs,omitempty"`
	// When lists the conditions under which the check applies. All must
	// hold; otherwise the result is NotApplicable.
	When []Condition `yaml:"when,omitempty"`

	File         *FileCheck    `yaml:"file,omitempty"`
	Sysctl       *SysctlCheck  `yaml:"sysctl,omitempty"`
	Package      *PackageCheck `yaml:"package,omitempty"`
	Service      *ServiceCheck `yaml:"service,omitempty"`
	SSHD         *SSHDCheck    `yaml:"sshd,omitempty"`
	Mount        *MountCheck   `yaml:"mount,omitempty"`
	KernelModule *KmodCheck    `yaml:"kernel_module,omitempty"`
}

var (
	idRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	severities = []string{"", "unknown", "info", "low", "medium", "high"}
)

// Load reads and validates a baseline. Unknown fields are errors, so a
// typing mistake in a hand-written baseline cannot silently drop a check.
func Load(r io.Reader) (*Baseline, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, errors.New("baseline larger than 4 MiB")
	}
	var bl Baseline
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&bl); err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	if err := bl.validate(); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", bl.Name, err)
	}
	return &bl, nil
}

func (b *Baseline) validate() error {
	if b.Version != 1 {
		return fmt.Errorf("version %d not supported (want 1)", b.Version)
	}
	if !idRE.MatchString(b.Name) {
		return fmt.Errorf("name %q is not a valid name", b.Name)
	}
	if len(b.Applies) == 0 {
		return errors.New("applies is empty")
	}
	seen := map[string]bool{}
	for i := range b.Checks {
		c := &b.Checks[i]
		if !idRE.MatchString(c.ID) {
			return fmt.Errorf("check %d: id %q is not valid", i+1, c.ID)
		}
		if seen[c.ID] {
			return fmt.Errorf("check %s is listed twice", c.ID)
		}
		seen[c.ID] = true
		if !slices.Contains(severities, c.Severity) {
			return fmt.Errorf("check %s: severity %q is not valid", c.ID, c.Severity)
		}
		if err := c.validate(); err != nil {
			return fmt.Errorf("check %s: %w", c.ID, err)
		}
	}
	return nil
}

func (c *Check) validate() error {
	n := 0
	for _, set := range []bool{c.File != nil, c.Sysctl != nil, c.Package != nil,
		c.Service != nil, c.SSHD != nil, c.Mount != nil, c.KernelModule != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("has %d probes, want exactly 1", n)
	}
	for i := range c.When {
		if err := c.When[i].validate(); err != nil {
			return fmt.Errorf("when %d: %w", i+1, err)
		}
	}
	switch {
	case c.File != nil:
		return c.File.validate()
	case c.Sysctl != nil:
		return c.Sysctl.validate()
	case c.Package != nil:
		return c.Package.validate()
	case c.Service != nil:
		return c.Service.validate()
	case c.SSHD != nil:
		return c.SSHD.validate()
	case c.Mount != nil:
		return c.Mount.validate()
	default:
		return c.KernelModule.validate()
	}
}

// For reports whether the baseline applies to an os-release ID and
// VERSION_ID.
func (b *Baseline) For(id, versionID string) bool {
	return slices.Contains(b.Applies, Release{ID: id, VersionID: versionID})
}
