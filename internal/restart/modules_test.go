package restart

import (
	"slices"
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
	r := NewResolver(root)
	got := r.modules(time.Now().Add(-time.Hour))
	var paths []string
	for _, m := range got {
		paths = append(paths, m.Kind+" "+m.Host+" "+m.Path)
	}
	want := []string{
		"gconv libc.so.6 " + lib + "gconv/UTF-7.so",
		"nss libc.so.6 " + lib + "libnss_files.so.2",
		"nss libc.so.6 " + lib + "libnss_systemd.so.2",
		"openssl libcrypto.so.3 " + lib + "ossl-modules/legacy.so",
		"sasl libsasl2.so.2 " + lib + "sasl2/libplain.so.2",
		"pam libpam.so.0 " + lib + "security/pam_systemd.so",
	}
	if !slices.Equal(paths, want) {
		t.Errorf("got  %q\nwant %q", paths, want)
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
		},
	}
	got := map[string]Finding{}
	for _, f := range Analyze(snap).Findings {
		got[f.Unit] = f
	}
	if f := got["pam.service"]; f.Status != Possible || len(f.Modules) != 1 || f.Reason == "" {
		t.Errorf("pam.service: %+v", f)
	}
	if f := got["plain.service"]; f.Status != None {
		t.Errorf("plain.service does not link libpam: %+v", f)
	}
	if f := got["late.service"]; f.Status != None {
		t.Errorf("late.service started after the module: %+v", f)
	}
}
