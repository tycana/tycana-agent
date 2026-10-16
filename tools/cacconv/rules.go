package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"tycana.ai/agent/internal/baseline"
)

// converter maps one product's compiled rules to checks. The semantics
// of each template are in internal/baseline (one probe per template
// family); here are only the per-product facts the templates' Jinja
// decides.
type converter struct {
	dir, product string
	// refine holds the profile's "variable=option" selections.
	refine map[string]string
	values map[string]*value
}

func (c *converter) deb() bool {
	return strings.HasPrefix(c.product, "ubuntu") || strings.HasPrefix(c.product, "debian")
}

// kernelPackage is the package system_with_kernel tests.
func (c *converter) kernelPackage() string {
	switch {
	case c.deb():
		return "linux-base"
	case strings.HasPrefix(c.product, "rhel"):
		return "kernel-core"
	default:
		return "kernel"
	}
}

// value resolves an XCCDF value: the profile's selected option, else the
// default option.
func (c *converter) value(id string) (string, error) {
	v, ok := c.values[id]
	if !ok {
		v = &value{}
		if err := readJSON(filepath.Join(c.dir, "values", id+".json"), v); err != nil {
			return "", fmt.Errorf("value %s: %w", id, err)
		}
		c.values[id] = v
	}
	sel := c.refine[id]
	if sel == "" {
		sel = "default"
	}
	o, ok := v.Options[sel]
	if !ok {
		o, ok = v.Options["default"]
	}
	if !ok {
		return "", fmt.Errorf("value %s has no option %q and no default", id, sel)
	}
	switch x := o.(type) {
	case string:
		return x, nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(x), nil
	}
	return "", fmt.Errorf("value %s: option %q has type %T", id, sel, o)
}

// check converts one rule. A non-empty reason means not covered.
func (c *converter) check(id string, r *rule) (*baseline.Check, string) {
	if r.Template == nil {
		return nil, "custom OVAL check (no template)"
	}
	if r.Template.Backends["oval"] == "off" || varString(r.Template.Vars, "backends") == "off" {
		return nil, "custom OVAL check (template OVAL is off)"
	}
	if hasRuleOVAL(r.DefinitionLocation) {
		return nil, "custom OVAL check (the rule's own OVAL replaces its template)"
	}
	chk := &baseline.Check{ID: id, Title: r.Title, Severity: r.Severity, Refs: refs(r)}
	for _, expr := range slices.Concat(r.InheritedPlatforms, r.Platforms) {
		conds, reason := c.platform(expr)
		if reason != "" {
			return nil, "platform " + strconv.Quote(expr) + ": " + reason
		}
		chk.When = append(chk.When, conds...)
	}
	v := r.Template.Vars
	var reason string
	switch t := r.Template.Name; t {
	case "file_permissions", "file_owner", "file_groupowner":
		chk.File, reason = c.file(t, v)
	case "file_existence":
		p, _ := v["filepath"].(string)
		ex := boolVar(v, "exists", false)
		chk.File = &baseline.FileCheck{Paths: []string{p}, Exists: &ex}
	case "sysctl":
		chk.Sysctl, reason = c.sysctl(id, v)
	case "package_installed", "package_removed":
		if varString(v, "evr") != "" {
			return nil, "package version comparison is not implemented"
		}
		state := map[string]string{"package_installed": "present", "package_removed": "absent"}[t]
		chk.Package = &baseline.PackageCheck{Names: stringList(v["pkgname"]), State: state}
	case "package_installed_guard_var":
		if varString(v, "evr") != "" {
			return nil, "package version comparison is not implemented"
		}
		match, err := c.guard(v)
		if err != nil {
			return nil, err.Error()
		}
		if !match {
			return nil, vacuous(v)
		}
		chk.Package = &baseline.PackageCheck{Names: stringList(v["pkgname"]), State: "present"}
	case "service_enabled", "service_disabled":
		chk.Service = c.service(v, strings.TrimPrefix(t, "service_"))
	case "service_enabled_guard_var":
		match, err := c.guard(v)
		if err != nil {
			return nil, err.Error()
		}
		if !match {
			return nil, vacuous(v)
		}
		chk.Service = c.service(v, "enabled")
	case "service_disabled_guard_var":
		match, err := c.guard(v)
		if err != nil {
			return nil, err.Error()
		}
		if match {
			return nil, vacuous(v)
		}
		chk.Service = c.service(v, "disabled")
	case "socket_disabled":
		chk.Service = &baseline.ServiceCheck{Name: varString(v, "socketname"), State: "socket_masked"}
	case "sshd_lineinfile":
		chk.SSHD, reason = c.sshd(v)
	case "mount_option":
		if varString(v, "mountoption_arg_var") != "" {
			return nil, "mount option with an argument variable is not implemented"
		}
		chk.Mount = &baseline.MountCheck{
			Path: varString(v, "mountpoint"), Option: varString(v, "mountoption"),
			MustExist: boolVar(v, "mount_has_to_exist", true), ExcludeFSType: varString(v, "exclude_filesystem_type"),
		}
	case "kernel_module_disabled":
		chk.KernelModule = &baseline.KmodCheck{
			Name:      varString(v, "kernmodule"),
			Blacklist: strings.HasPrefix(c.product, "ubuntu") || strings.HasPrefix(c.product, "rhel"),
		}
	default:
		return nil, "template " + t + " has no Tycana probe"
	}
	if reason != "" {
		return nil, reason
	}
	return chk, ""
}

// hasRuleOVAL reports whether the rule directory carries its own OVAL.
// Some files render empty for some products; treating every one as an
// override only loses coverage, never correctness.
func hasRuleOVAL(ruleYML string) bool {
	if ruleYML == "" {
		return false
	}
	m, _ := filepath.Glob(filepath.Join(filepath.Dir(ruleYML), "oval", "*.xml"))
	return len(m) > 0
}

func vacuous(v map[string]any) string {
	return fmt.Sprintf("OpenSCAP passes this without reading the host: the profile sets %s, not %s",
		varString(v, "variable"), varString(v, "value"))
}

// guard evaluates a *_guard_var template's variable test, which depends
// only on the profile.
func (c *converter) guard(v map[string]any) (bool, error) {
	got, err := c.value(varString(v, "variable"))
	if err != nil {
		return false, err
	}
	want := varString(v, "value")
	switch op := varString(v, "operation"); op {
	case "", "equals":
		return got == want, nil
	case "pattern match":
		re, err := regexp.Compile(want)
		if err != nil {
			return false, err
		}
		return re.MatchString(got), nil
	default:
		return false, fmt.Errorf("guard operation %q is not implemented", op)
	}
}

func (c *converter) service(v map[string]any, state string) *baseline.ServiceCheck {
	name := varString(v, "servicename")
	pkg := varString(v, "packagename")
	if pkg == "" {
		pkg = name
	}
	return &baseline.ServiceCheck{Name: name, State: state, Package: pkg}
}

func (c *converter) file(t string, v map[string]any) (*baseline.FileCheck, string) {
	if varString(v, "filepath_is_regex") != "" {
		return nil, "file path patterns are not implemented"
	}
	f := &baseline.FileCheck{Paths: stringList(v["filepath"]), Recursive: boolVar(v, "recursive", false)}
	if rx := stringList(v["file_regex"]); len(rx) > 0 {
		for _, x := range rx[1:] {
			if x != rx[0] {
				return nil, "different file patterns for each path are not implemented"
			}
		}
		f.FileRegex = rx[0]
	}
	switch t {
	case "file_permissions":
		f.Mode = varString(v, "filemode")
		f.ExactMode = !boolVar(v, "allow_stricter_permissions", true)
		f.Exclude = stringList(v["excluded_files"])
	case "file_owner":
		f.Owner = strings.Split(varString(v, "uid_or_name"), "|")
	default:
		f.Group = strings.Split(varString(v, "gid_or_name"), "|")
	}
	return f, ""
}

func (c *converter) sysctl(id string, v map[string]any) (*baseline.SysctlCheck, string) {
	if op := varString(v, "operation"); op != "" && op != "equals" {
		return nil, "sysctl operation " + op + " is not implemented"
	}
	s := &baseline.SysctlCheck{
		Key: varString(v, "sysctlvar"), Datatype: varString(v, "datatype"),
		Runtime: varString(v, "check_runtime") != "false", MissingPass: varString(v, "missing_parameter_pass") == "true",
	}
	s.IPv6 = strings.Contains(s.Key, "ipv6")
	s.Values = stringList(v["sysctlval"])
	if len(s.Values) == 0 || len(s.Values) == 1 && s.Values[0] == "" {
		x, err := c.value(id + "_value")
		if err != nil {
			return nil, err.Error()
		}
		s.Values = []string{x}
	}
	// The template's file sets per product (sysctl/oval.template).
	s.UserFiles = []string{"/etc/sysctl.conf"}
	if strings.HasPrefix(c.product, "ubuntu") {
		s.UserFiles = append(s.UserFiles, "/etc/ufw/sysctl.conf")
	}
	s.UserDirs = []string{"/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d"}
	if strings.HasPrefix(c.product, "debian") {
		s.UserDirs = append(s.UserDirs, "/lib/sysctl.d")
	}
	return s, ""
}

func (c *converter) sshd(v map[string]any) (*baseline.SSHDCheck, string) {
	req, err := c.value("sshd_required")
	if err != nil {
		return nil, err.Error()
	}
	if req != "0" {
		return nil, "sshd_required " + req + " is not implemented"
	}
	s := &baseline.SSHDCheck{
		Keyword: varString(v, "parameter"), Datatype: varString(v, "datatype"),
		MissingPass: varString(v, "missing_parameter_pass") == "true", Package: "openssh-server",
		// sshd_distributed_config in product.yml.
		DropIns: slices.Contains([]string{"ubuntu2204", "ubuntu2404", "rhel9", "rhel10"}, c.product),
	}
	if x := varString(v, "xccdf_variable"); x != "" {
		val, err := c.value(x)
		if err != nil {
			return nil, err.Error()
		}
		s.Value, s.Match = val, "equals"
	} else {
		s.Value, s.Match, s.Datatype = varString(v, "value"), "regex", ""
	}
	return s, ""
}

// platform converts one CPE-AL expression: atoms joined by "and", each
// optionally negated with "not".
func (c *converter) platform(expr string) ([]baseline.Condition, string) {
	var out []baseline.Condition
	for _, part := range strings.Split(expr, " and ") {
		neg := false
		atom := strings.TrimSpace(part)
		if a, ok := strings.CutPrefix(atom, "not "); ok {
			neg, atom = true, strings.TrimSpace(a)
		}
		cond, reason := c.atom(atom)
		if reason != "" {
			return nil, reason
		}
		if cond == nil {
			// The atom is false on this product.
			if !neg {
				return nil, "never applicable on this product (" + part + ")"
			}
			continue
		}
		if neg {
			cond = &baseline.Condition{Not: cond}
		}
		out = append(out, *cond)
	}
	return out, ""
}

var argRE = regexp.MustCompile(`^([a-z0-9_]+)\[([A-Za-z0-9_.-]+)\]$`)

// atom returns the condition, or nil when the atom is false on every
// host of the product.
func (c *converter) atom(a string) (*baseline.Condition, string) {
	container := &baseline.Condition{Any: []baseline.Condition{{FileExists: "/.dockerenv"}, {FileExists: "/run/.containerenv"}}}
	switch a {
	case "system_with_kernel":
		return &baseline.Condition{Package: c.kernelPackage()}, ""
	case "container":
		return container, ""
	case "machine":
		return &baseline.Condition{Not: container}, ""
	case "bootc":
		// bootc also needs an ostree boot; a host without the bootc
		// package is never bootc.
		if c.deb() {
			return nil, ""
		}
		return &baseline.Condition{Package: "bootc"}, ""
	case "grub2":
		return &baseline.Condition{Package: "grub2-common"}, ""
	case "ipv6[enabled]":
		return &baseline.Condition{IPv6Enabled: true}, ""
	case "rhcos4-rhel9", "rhcos4-rhel10", "rhcos4":
		return nil, ""
	}
	m := argRE.FindStringSubmatch(a)
	if m == nil {
		return nil, "platform " + a + " is not implemented"
	}
	var item struct {
		Template struct {
			Vars map[string]any `json:"vars"`
		} `json:"template"`
	}
	if err := readJSON(filepath.Join(c.dir, "cpe_items", m[1]+"_"+m[2]+".json"), &item); err != nil {
		return nil, err.Error()
	}
	iv := item.Template.Vars
	switch m[1] {
	case "package":
		return &baseline.Condition{Package: varString(iv, "pkgname")}, ""
	case "mount":
		return &baseline.Condition{Mounted: varString(iv, "mountpoint")}, ""
	case "service_disabled":
		return &baseline.Condition{ServiceDisabled: c.service(iv, "disabled")}, ""
	}
	return nil, "platform " + a + " is not implemented"
}

func varString(v map[string]any, k string) string {
	switch x := v[k].(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case map[string]any:
		s, _ := x["oval"].(string)
		return s
	}
	return ""
}

func boolVar(v map[string]any, k string, def bool) bool {
	switch strings.ToLower(varString(v, k)) {
	case "true", "yes", "1":
		return true
	case "false", "no", "0":
		return false
	}
	return def
}

func stringList(x any) []string {
	switch t := x.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}
