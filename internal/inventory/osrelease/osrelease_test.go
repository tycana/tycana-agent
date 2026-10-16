package osrelease

import (
	"reflect"
	"testing"
	"testing/fstest"
)

const ubuntu = `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.1 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
`

func TestReadUbuntu(t *testing.T) {
	fsys := fstest.MapFS{"usr/lib/os-release": {Data: []byte(ubuntu)}}
	got, err := Read(fsys)
	if err != nil {
		t.Fatal(err)
	}
	want := Info{ID: "ubuntu", IDLike: []string{"debian"}, Name: "Ubuntu", PrettyName: "Ubuntu 24.04.1 LTS",
		VersionID: "24.04", Version: "24.04.1 LTS (Noble Numbat)", VersionCodename: "noble", Source: "/usr/lib/os-release"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestEtcWinsAndDefaults(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/os-release":     {Data: []byte("# comment\n\nNAME='Plain'\nnot an assignment\n")},
		"usr/lib/os-release": {Data: []byte(ubuntu)},
	}
	got, err := Read(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "linux" || got.Name != "Plain" || got.Source != "/etc/os-release" {
		t.Errorf("got %+v", got)
	}
}

func TestParseQuoting(t *testing.T) {
	kv, err := Parse([]byte(`A="x \"y\" \$z \\ \q"
B='it''s'
C=bare
ID_LIKE="rhel centos fedora"
lower=ignored
`))
	if err != nil {
		t.Fatal(err)
	}
	if kv["A"] != `x "y" $z \ \q` || kv["C"] != "bare" || kv["ID_LIKE"] != "rhel centos fedora" {
		t.Errorf("got %q", kv)
	}
	if _, ok := kv["lower"]; ok {
		t.Error("lower-case key accepted")
	}
	if _, err := Parse([]byte("A=\"open\n")); err == nil {
		t.Error("unterminated quote accepted")
	}
}

func TestMissing(t *testing.T) {
	if _, err := Read(fstest.MapFS{}); err == nil {
		t.Error("want error")
	}
}
