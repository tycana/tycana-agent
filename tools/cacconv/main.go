// Command cacconv converts ComplianceAsCode content into a Tycana
// baseline (DSL version 1). It runs offline, on a developer machine, never
// on a host.
//
// Input is one product's compiled content: the directory that
// ComplianceAsCode's build-scripts/compile_all.py writes (--resolved-base),
// with profiles/, rules/, and values/. The rule JSON there has its Jinja
// expanded, its template variables set for the product, and its
// references merged from the controls files. Output is the baseline on
// stdout:
//
//	go run ./tools/cacconv -in BUILD/ubuntu2404 -product ubuntu2404 \
//	    -profile cis_level1_server -name ubuntu2404-level1-server \
//	    -commit SHA > internal/baseline/presets/ubuntu2404-level1-server.yaml
//
// Rules whose template has no Tycana probe, or whose check is custom
// OVAL, go to not_covered with the reason. No CIS data is copied
// (docs: tycana-hq research 2026-10-16-cis-references-licensing.md,
// inbox item 1.1, option A): references keyed cis, cis@*, and cis-csc are
// dropped, and titles are ComplianceAsCode's own rule titles.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"tycana.ai/agent/internal/baseline"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "cacconv: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	in, product, profile, name, title, commit, version string
	releases                                           []baseline.Release
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("cacconv", flag.ContinueOnError)
	var o options
	var applies string
	fs.StringVar(&o.in, "in", "", "compiled product directory (compile_all.py --resolved-base)")
	fs.StringVar(&o.product, "product", "", "ComplianceAsCode product id, for example ubuntu2404")
	fs.StringVar(&o.profile, "profile", "", "profile id, for example cis_level1_server")
	fs.StringVar(&o.name, "name", "", "baseline name")
	fs.StringVar(&o.title, "title", "", "baseline title")
	fs.StringVar(&o.commit, "commit", "", "ComplianceAsCode commit")
	fs.StringVar(&o.version, "version", "", "ComplianceAsCode version")
	fs.StringVar(&applies, "applies", "", "os-release ID:VERSION_ID pairs, comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.in == "" || o.product == "" || o.profile == "" || o.name == "" || o.commit == "" || applies == "" {
		return fmt.Errorf("-in, -product, -profile, -name, -commit, and -applies are necessary")
	}
	for _, a := range strings.Split(applies, ",") {
		id, ver, ok := strings.Cut(a, ":")
		if !ok {
			return fmt.Errorf("-applies %q: want ID:VERSION_ID", a)
		}
		o.releases = append(o.releases, baseline.Release{ID: id, VersionID: ver})
	}
	b, err := convert(o)
	if err != nil {
		return err
	}
	return write(out, b)
}

// profile is the compiled profile JSON (the fields cacconv reads).
type profile struct {
	Title      string   `json:"title"`
	Selections []string `json:"selections"`
}

// rule is the compiled rule JSON (the fields cacconv reads).
type rule struct {
	Title              string              `json:"title"`
	DefinitionLocation string              `json:"definition_location"`
	Severity           string              `json:"severity"`
	References         map[string][]string `json:"references"`
	ControlReferences  map[string][]string `json:"control_references"`
	Platforms          []string            `json:"platforms"`
	InheritedPlatforms []string            `json:"inherited_platforms"`
	Template           *struct {
		Name     string            `json:"name"`
		Vars     map[string]any    `json:"vars"`
		Backends map[string]string `json:"backends"`
	} `json:"template"`
}

// value is a compiled XCCDF value.
type value struct {
	Type    string         `json:"type"`
	Options map[string]any `json:"options"`
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path) //nolint:gosec // developer-supplied build directory
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func convert(o options) (*baseline.Baseline, error) {
	var p profile
	if err := readJSON(filepath.Join(o.in, "profiles", o.profile+".profile"), &p); err != nil {
		return nil, err
	}
	// Selections are rule ids and "variable=option" refinements.
	vars := map[string]string{}
	var ids []string
	for _, s := range p.Selections {
		if k, v, ok := strings.Cut(s, "="); ok {
			vars[k] = v
			continue
		}
		ids = append(ids, s)
	}
	sort.Strings(ids)
	c := &converter{dir: o.in, product: o.product, refine: vars, values: map[string]*value{}}
	b := &baseline.Baseline{
		Version: 1,
		Name:    o.name,
		Title:   o.title,
		Source: baseline.Source{
			Project: "ComplianceAsCode",
			URL:     "https://github.com/ComplianceAsCode/content",
			Commit:  o.commit,
			Version: o.version,
			Product: o.product,
			Profile: o.profile,
			License: "BSD-3-Clause",
		},
		Applies: o.releases,
	}
	for _, id := range ids {
		var r rule
		if err := readJSON(filepath.Join(o.in, "rules", id+".json"), &r); err != nil {
			return nil, err
		}
		chk, reason := c.check(id, &r)
		if reason != "" {
			b.NotCovered = append(b.NotCovered, baseline.Uncovered{
				ID: id, Title: r.Title, Refs: refs(&r), Reason: reason,
			})
			continue
		}
		b.Checks = append(b.Checks, *chk)
	}
	return b, nil
}

// dropRef reports whether a reference key carries CIS data (option A).
func dropRef(k string) bool {
	return k == "cis" || k == "cis-csc" || strings.HasPrefix(k, "cis@")
}

// keptRefs are the reference keys copied into a baseline.
var keptRefs = []string{"nist", "stigid", "pcidss4", "hipaa", "ism"}

func refs(r *rule) map[string][]string {
	out := map[string][]string{}
	for _, src := range []map[string][]string{r.References, r.ControlReferences} {
		for k, v := range src {
			k, _, _ = strings.Cut(k, "@")
			if dropRef(k) || !slices.Contains(keptRefs, k) {
				continue
			}
			for _, x := range v {
				if !slices.Contains(out[k], x) {
					out[k] = append(out[k], x)
				}
			}
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func write(w io.Writer, b *baseline.Baseline) error {
	fmt.Fprintf(w, "# Generated by tools/cacconv from ComplianceAsCode %s (%s, profile %s).\n"+
		"# Do not edit; regenerate with scripts/gen-presets.sh. Content: BSD-3-Clause.\n",
		b.Source.Commit, b.Source.Product, b.Source.Profile)
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(b); err != nil {
		return err
	}
	return enc.Close()
}
