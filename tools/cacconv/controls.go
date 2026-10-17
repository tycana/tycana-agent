package main

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"tycana.ai/agent/internal/baseline"
)

// controlsFile is a ComplianceAsCode controls file (controls/*.yml), the
// fields cacconv reads.
type controlsFile struct {
	Levels []struct {
		ID           string   `yaml:"id"`
		InheritsFrom []string `yaml:"inherits_from"`
	} `yaml:"levels"`
	Controls []control `yaml:"controls"`
}

type control struct {
	Title    string    `yaml:"title"`
	Levels   []string  `yaml:"levels"`
	Rules    []string  `yaml:"rules"`
	Controls []control `yaml:"controls"`
}

// benchmark counts the automated recommendations at level, with the
// method of the coverage checkpoint (tycana-hq
// docs/research/2026-10-16-baseline-coverage-checkpoint.md, F1): leaf
// controls at the level or a level it inherits, whose title contains
// "(Automated)". Only rule ids leave this function; recommendation
// numbers and titles are CIS data and stay out of the preset.
func benchmark(path, level string) (*baseline.Benchmark, error) {
	b, err := os.ReadFile(path) //nolint:gosec // developer-supplied checkout
	if err != nil {
		return nil, err
	}
	var cf controlsFile
	if err := yaml.Unmarshal(b, &cf); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	inherits := map[string][]string{}
	for _, l := range cf.Levels {
		inherits[l.ID] = l.InheritsFrom
	}
	if _, ok := inherits[level]; !ok {
		return nil, fmt.Errorf("%s has no level %q", path, level)
	}
	want := map[string]bool{}
	var add func(string)
	add = func(l string) {
		if want[l] {
			return
		}
		want[l] = true
		for _, i := range inherits[l] {
			add(i)
		}
	}
	add(level)
	bm := &baseline.Benchmark{Level: level}
	var walk func([]control)
	walk = func(cs []control) {
		for _, c := range cs {
			if len(c.Controls) > 0 {
				walk(c.Controls)
				continue
			}
			if c.Title == "" || !strings.Contains(c.Title, "(Automated)") ||
				!slices.ContainsFunc(c.Levels, func(l string) bool { return want[l] }) {
				continue
			}
			bm.Automated++
			var rules []string
			for _, r := range c.Rules {
				if !strings.Contains(r, "=") && !slices.Contains(rules, r) {
					rules = append(rules, r)
				}
			}
			if len(rules) > 0 {
				slices.Sort(rules)
				bm.Recommendations = append(bm.Recommendations, rules)
			}
		}
	}
	walk(cf.Controls)
	return bm, nil
}
