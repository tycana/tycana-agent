package restart

import (
	"debug/elf"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNSSSources(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/nsswitch.conf", []byte(`# comment
passwd:   files systemd sss
group:    files [SUCCESS=merge] systemd
hosts:    files mdns4_minimal [NOTFOUND=return] dns myhostname
netgroup: nis # trailing
bad:      ../evil Files
`))
	got := (&Resolver{Root: root}).nssSources()
	want := []string{"files", "systemd", "sss", "mdns4_minimal", "dns", "myhostname", "nis"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestModules(t *testing.T) {
	root := debianTree(t)
	writeFile(t, root, "/etc/nsswitch.conf", []byte("passwd: files systemd\n"))
	lib := "/usr/lib/x86_64-linux-gnu/"
	for _, f := range []string{"libnss_systemd.so.2", "libnss_files.so.2", "libnss_unused.so.2",
		"security/pam_systemd.so", "ossl-modules/legacy.so", "sasl2/libplain.so.2", "gconv/UTF-7.so"} {
		writeFile(t, root, lib+f, nil)
	}
	// An Apache module whose own closure (libcap, libc) the host program
	// does not link.
	writeELF(t, root, "/usr/sbin/apache2", elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2", "", "libc.so.6")
	writeELF(t, root, "/usr/lib/apache2/modules/mod_ssl.so", elf.EM_X86_64, "", "", "libcap.so.2")
	r := NewResolver(root)
	got := r.modules(time.Now().Add(-time.Hour))
	var lines []string
	for _, m := range got {
		lines = append(lines, strings.TrimSpace(m.Kind+" "+m.Host+" "+m.Path+" "+m.Via))
	}
	ssl := "/usr/lib/apache2/modules/mod_ssl.so"
	want := []string{
		"apache /usr/sbin/apache2 " + ssl,
		"apache /usr/sbin/apache2 " + lib + "libc.so.6 " + ssl,
		"apache /usr/sbin/apache2 " + lib + "libcap.so.2.66 " + ssl,
		"gconv libc.so.6 " + lib + "gconv/UTF-7.so",
		"nss libc.so.6 " + lib + "libnss_files.so.2",
		"nss libc.so.6 " + lib + "libnss_systemd.so.2",
		"openssl libcrypto.so.3 " + lib + "ossl-modules/legacy.so",
		"pam libpam.so.0 " + lib + "security/pam_systemd.so",
		"sasl libsasl2.so.2 " + lib + "sasl2/libplain.so.2",
	}
	if !slices.Equal(lines, want) {
		t.Errorf("got  %q\nwant %q", lines, want)
	}
	if got := r.modules(time.Now().Add(time.Hour)); len(got) != 0 {
		t.Errorf("modules older than since: %v", got)
	}
}

func TestPossible(t *testing.T) {
	t0 := time.Date(2026, 10, 16, 17, 2, 5, 0, time.UTC)
	old := t0.Add(-time.Hour)
	snap := Snapshot{
		Units: []Unit{
			{ID: "pam.service", MainPID: 1, Start: t0, Exec: "/bin/pam"},
			{ID: "plain.service", MainPID: 2, Start: t0, Exec: "/bin/plain"},
			{ID: "late.service", MainPID: 3, Start: t0.Add(time.Hour), Exec: "/bin/pam"},
		},
		Programs: map[string]Program{
			"/bin/pam":   {Path: "/bin/pam", Closure: []string{"/bin/pam"}, Sonames: []string{"libc.so.6", "libpam.so.0"}},
			"/bin/plain": {Path: "/bin/plain", Closure: []string{"/bin/plain"}, Sonames: []string{"libc.so.6"}},
		},
		Files: map[string]FileTime{"/bin/pam": {Time: old}, "/bin/plain": {Time: old}},
		Modules: []Module{
			{Path: "/lib/security/pam_x.so", Kind: "pam", Host: "libpam.so.0", Created: t0.Add(time.Minute)},
			{Path: "/lib/libssl.so.3", Kind: "apache", Host: "/bin/plain", Via: "/mod/mod_ssl.so", Created: t0.Add(time.Minute)},
		},
	}
	got := map[string]Finding{}
	for _, f := range Analyze(snap).Findings {
		got[f.Unit] = f
	}
	if f := got["pam.service"]; f.Status != Possible || len(f.Modules) != 1 || f.Reason == "" {
		t.Errorf("pam.service: %+v", f)
	}
	if f := got["plain.service"]; f.Status != Possible || len(f.Modules) != 1 || f.Modules[0].Path != "/lib/libssl.so.3" {
		t.Errorf("plain.service is the host program of a module: %+v", f)
	}
	if f := got["late.service"]; f.Status != None {
		t.Errorf("late.service started after the module: %+v", f)
	}
}
