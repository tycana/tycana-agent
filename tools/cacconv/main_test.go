package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tycana.ai/agent/internal/baseline"
)

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func tmpl(name string, vars map[string]any) map[string]any {
	return map[string]any{"name": name, "vars": vars, "backends": map[string]any{}}
}

func TestConvert(t *testing.T) {
	dir := t.TempDir()
	src := t.TempDir()
	custom := filepath.Join(src, "own", "rule.yml")
	writeJSON(t, filepath.Join(src, "own", "oval", "shared.xml"), "x")
	writeJSON(t, filepath.Join(dir, "profiles", "p.profile"), map[string]any{
		"title": "P",
		"selections": []string{"sshd_set_keepalive", "sysctl_net_ipv4_conf_all_rp_filter", "package_chrony_installed",
			"own_oval", "no_template", "service_avahi-daemon_disabled", "var_sshd_set_keepalive=3", "var_timesync_service=systemd-timesyncd"},
	})
	writeJSON(t, filepath.Join(dir, "values", "var_sshd_set_keepalive.json"), map[string]any{"options": map[string]any{"3": 3, "default": 0}})
	writeJSON(t, filepath.Join(dir, "values", "sshd_required.json"), map[string]any{"options": map[string]any{"default": "0"}})
	writeJSON(t, filepath.Join(dir, "values", "sysctl_net_ipv4_conf_all_rp_filter_value.json"), map[string]any{"options": map[string]any{"default": 1}})
	writeJSON(t, filepath.Join(dir, "values", "var_timesync_service.json"), map[string]any{"options": map[string]any{"default": "chronyd", "systemd-timesyncd": "systemd-timesyncd"}})
	writeJSON(t, filepath.Join(dir, "cpe_items", "package_avahi.json"), map[string]any{"template": map[string]any{"vars": map[string]any{"pkgname": "avahi-daemon"}}})
	refs := map[string]any{"cis@ubuntu2404": []string{"5.1.1"}, "nist": []string{"CM-6(a)"}, "cis-csc": []string{"1"}}
	writeJSON(t, filepath.Join(dir, "rules", "sshd_set_keepalive.json"), map[string]any{
		"title": "Set SSH Client Alive Count Max", "severity": "medium", "references": refs,
		"control_references": map[string]any{"cis": []string{"5.1.7"}}, "inherited_platforms": []string{"system_with_kernel"},
		"template": tmpl("sshd_lineinfile", map[string]any{"parameter": "ClientAliveCountMax", "xccdf_variable": "var_sshd_set_keepalive", "datatype": "int"}),
	})
	writeJSON(t, filepath.Join(dir, "rules", "sysctl_net_ipv4_conf_all_rp_filter.json"), map[string]any{
		"title": "rp_filter", "severity": "medium",
		"template": tmpl("sysctl", map[string]any{"sysctlvar": "net.ipv4.conf.all.rp_filter", "datatype": "int"}),
	})
	writeJSON(t, filepath.Join(dir, "rules", "package_chrony_installed.json"), map[string]any{
		"title": "chrony", "severity": "medium",
		"template": tmpl("package_installed_guard_var", map[string]any{"pkgname": "chrony", "variable": "var_timesync_service", "value": "chronyd"}),
	})
	writeJSON(t, filepath.Join(dir, "rules", "own_oval.json"), map[string]any{
		"title": "own", "definition_location": custom,
		"template": tmpl("file_permissions", map[string]any{"filepath": "/etc/x", "filemode": "0600"}),
	})
	writeJSON(t, filepath.Join(dir, "rules", "no_template.json"), map[string]any{"title": "none"})
	writeJSON(t, filepath.Join(dir, "rules", "service_avahi-daemon_disabled.json"), map[string]any{
		"title": "avahi", "platforms": []string{"system_with_kernel and package[avahi]"},
		"template": tmpl("service_disabled", map[string]any{"servicename": "avahi-daemon", "packagename": "avahi-daemon"}),
	})

	var out bytes.Buffer
	err := run([]string{"-in", dir, "-product", "ubuntu2404", "-profile", "p", "-name", "ubuntu2404-test",
		"-title", "Test", "-commit", "abc", "-applies", "ubuntu:24.04"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(out.String()), "cis") {
		t.Errorf("output carries CIS data:\n%s", out.String())
	}
	b, err := baseline.Load(&out)
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]baseline.Check{}
	for _, c := range b.Checks {
		checks[c.ID] = c
	}
	if s := checks["sshd_set_keepalive"].SSHD; s == nil || s.Value != "3" || s.Match != "equals" || !s.DropIns || s.Package != "openssh-server" {
		t.Errorf("sshd: %+v", s)
	}
	if w := checks["sshd_set_keepalive"].When; len(w) != 1 || w[0].Package != "linux-base" {
		t.Errorf("sshd when: %+v", w)
	}
	if r := checks["sshd_set_keepalive"].Refs; len(r) != 1 || r["nist"][0] != "CM-6(a)" {
		t.Errorf("refs: %v", r)
	}
	if s := checks["sysctl_net_ipv4_conf_all_rp_filter"].Sysctl; s == nil || s.Values[0] != "1" ||
		!strings.Contains(strings.Join(s.UserFiles, " "), "/etc/ufw/sysctl.conf") {
		t.Errorf("sysctl: %+v", s)
	}
	if w := checks["service_avahi-daemon_disabled"].When; len(w) != 2 || w[1].Package != "avahi-daemon" {
		t.Errorf("service when: %+v", w)
	}
	reasons := map[string]string{}
	for _, u := range b.NotCovered {
		reasons[u.ID] = u.Reason
	}
	for id, want := range map[string]string{
		"package_chrony_installed": "without reading the host",
		"own_oval":                 "own OVAL",
		"no_template":              "no template",
	} {
		if !strings.Contains(reasons[id], want) {
			t.Errorf("%s: reason %q, want %q", id, reasons[id], want)
		}
	}
}
