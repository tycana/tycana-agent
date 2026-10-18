package aptsrc

import (
	"bytes"
	"compress/gzip"
	"reflect"
	"testing"
	"testing/fstest"
)

func TestRead(t *testing.T) {
	d := DefaultDir + "/"
	ubuntu := "archive.ubuntu.com_ubuntu_dists_"
	ppa := "ppa.launchpadcontent.net_ondrej_nginx_ubuntu_dists_noble_"
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("Package: tool\nArchitecture: amd64\nVersion: 2.0\n"))
	_ = zw.Close()
	fsys := fstest.MapFS{
		d + ubuntu + "noble_InRelease":         {Data: []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Ubuntu\nLabel: Ubuntu\nSuite: noble\nCodename: noble\nSHA256:\n abc 1 x\n")},
		d + ubuntu + "noble-updates_InRelease": {Data: []byte("Origin: Ubuntu\nLabel: Ubuntu\nSuite: noble-updates\nCodename: noble\n")},
		d + ubuntu + "noble_main_binary-amd64_Packages": {Data: []byte(
			"Package: openssl\nArchitecture: amd64\nVersion: 3.0.13-0ubuntu3\nDescription: x\n long text\n\n" +
				"Package: nginx\nArchitecture: amd64\nVersion: 1.24.0-2ubuntu7\n\n")},
		d + ubuntu + "noble-updates_main_binary-amd64_Packages": {Data: []byte(
			"Package: openssl\nArchitecture: amd64\nVersion: 3.0.13-0ubuntu3.6\n\n" +
				"Package: linux-image-6.8.0-90-generic\nSource: linux-signed (6.8.0-90.90)\nArchitecture: amd64\nVersion: 6.8.0-90.90\n\n")},
		d + ubuntu + "noble_main_binary-i386_Packages":                 {Data: []byte("Package: openssl\nArchitecture: i386\nVersion: 3.0.13-0ubuntu3\n\n")},
		d + ppa + "InRelease":                                          {Data: []byte("Origin: LP-PPA-ondrej-nginx\nLabel: nginx\nSuite: noble\nCodename: noble\n")},
		d + ppa + "main_binary-amd64_Packages":                         {Data: []byte("Package: nginx\nArchitecture: amd64\nVersion: 1.28.0-1+ubuntu24.04.1+deb.sury.org+1\n")},
		d + "example.com_repo_._Packages.gz":                           {Data: gz.Bytes()},
		d + "example.com_other_dists_x_main_binary-amd64_Packages.lz4": {Data: []byte("x")},
		d + "lock": {},
	}
	want := []Want{
		{Name: "openssl", Arch: "amd64", Version: "3.0.13-0ubuntu3", Source: "openssl"},
		{Name: "nginx", Arch: "amd64", Version: "1.28.0-1+ubuntu24.04.1+deb.sury.org+1", Source: "nginx"},
		{Name: "linux-image-6.8.0-45-generic", Arch: "amd64", Version: "6.8.0-45.45", Source: "linux-signed"},
		{Name: "local-tool", Arch: "amd64", Version: "1.0", Source: "local-tool"},
		{Name: "tool", Arch: "amd64", Version: "2.0"},
	}
	r, err := Read(fsys, DefaultDir, want)
	if err != nil {
		t.Fatal(err)
	}
	src := func(ix []int) []string {
		var out []string
		for _, i := range ix {
			s := r.Sources[i]
			out = append(out, s.Origin+"/"+s.Suite+"/"+s.Component+"/"+s.Arch)
		}
		return out
	}
	for i, w := range []struct{ exact, name []string }{
		{[]string{"Ubuntu/noble/main/amd64"}, nil},
		{[]string{"LP-PPA-ondrej-nginx/noble/main/amd64"}, nil},
		// The old kernel is in no list; its source is, in -updates.
		{nil, []string{"Ubuntu/noble-updates/main/amd64"}},
		{nil, nil},
		{[]string{"///"}, nil},
	} {
		if g := src(r.Exact[i]); !reflect.DeepEqual(g, w.exact) {
			t.Errorf("%s exact %q, want %q", want[i].Name, g, w.exact)
		}
		if g := src(r.SourceName[i]); !reflect.DeepEqual(g, w.name) {
			t.Errorf("%s source name %q, want %q", want[i].Name, g, w.name)
		}
	}
	if len(r.Notes) != 1 {
		t.Errorf("notes %q", r.Notes)
	}
	for _, s := range r.Sources {
		if s.Arch == "i386" {
			t.Error("an architecture with no installed package was read")
		}
	}
	if s := r.Sources[r.Exact[4][0]]; s.Site != "example.com_repo_." {
		t.Errorf("flat repository %+v", s)
	}
}

func TestParseName(t *testing.T) {
	s, ok := parseName("_etc_apt_mirrors_debian-security.list_dists_bookworm-security_main_binary-amd64")
	if !ok || s.Site != "_etc_apt_mirrors_debian-security.list" || s.Dist != "bookworm-security" || s.Component != "main" || s.Arch != "amd64" {
		t.Errorf("%+v %v", s, ok)
	}
	if _, ok := parseName("x_dists_noble_main_source_Sources"); ok {
		t.Error("a Sources list parsed")
	}
}
