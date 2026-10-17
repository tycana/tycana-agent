package repos

import (
	"testing"
	"testing/fstest"
)

func TestRead(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/yum.repos.d/oracle-linux-ol9.repo": {Data: []byte(`[ol9_baseos_latest]
name=Oracle Linux 9 BaseOS Latest ($basearch)
baseurl=https://yum$ociregion.$ocidomain/repo/OracleLinux/OL9/baseos/latest/$basearch/
enabled=1

[ol9_u4_baseos_base]
enabled = 0
`)},
		"etc/yum.repos.d/virt-ol9.repo": {Data: []byte("# KVM\n[ol9_kvm_utils]\nenabled=False\n[ol9_noflag]\nname=x\n")},
		"etc/yum.repos.d/README":        {Data: []byte("[not_a_repo]\n")},
	}
	got, err := Read(fsys)
	if err != nil {
		t.Fatal(err)
	}
	want := []Repo{
		{ID: "ol9_baseos_latest", Enabled: true, File: "oracle-linux-ol9.repo"},
		{ID: "ol9_kvm_utils", Enabled: false, File: "virt-ol9.repo"},
		{ID: "ol9_noflag", Enabled: true, File: "virt-ol9.repo"},
		{ID: "ol9_u4_baseos_base", Enabled: false, File: "oracle-linux-ol9.repo"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestReadNoDir(t *testing.T) {
	got, err := Read(fstest.MapFS{})
	if err != nil || got != nil {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestReadBadSection(t *testing.T) {
	if _, err := Read(fstest.MapFS{"etc/yum.repos.d/x.repo": {Data: []byte("[]\n")}}); err == nil {
		t.Error("a section without a name was accepted")
	}
}
