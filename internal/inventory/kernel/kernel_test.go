package kernel

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestDebianRelease(t *testing.T) {
	for name, want := range map[string]string{
		"linux-image-6.8.0-45-generic":          "6.8.0-45-generic",
		"linux-image-unsigned-6.8.0-45-generic": "6.8.0-45-generic",
		"linux-image-6.1.0-25-amd64":            "6.1.0-25-amd64",
		"linux-image-generic":                   "",
		"linux-image-virtual":                   "",
		"linux-image-amd64":                     "",
		"linux-image-cloud-amd64":               "",
		"linux-image-6.1.0-25-amd64-dbg":        "",
		"linux-image-":                          "",
		"linux-headers-6.8.0-45-generic":        "",
		"linux-modules-6.8.0-45-generic":        "",
	} {
		if got := DebianRelease(name); got != want {
			t.Errorf("DebianRelease(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestCollect(t *testing.T) {
	fsys := fstest.MapFS{
		"proc/sys/kernel/osrelease":             {Data: []byte("6.8.0-45-generic\n")},
		"proc/sys/kernel/version":               {Data: []byte("#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024\n")},
		"proc/sys/kernel/random/boot_id":        {Data: []byte("0f6a2f0e-3a61-4f0a-9c55-7f1f1c1f1c1f\n")},
		"boot/vmlinuz-6.8.0-45-generic":         {Data: []byte{}},
		"boot/vmlinuz-6.8.0-100-generic":        {Data: []byte{}},
		"sys/kernel/livepatch/lkp_1/enabled":    {Data: []byte("1\n")},
		"sys/kernel/livepatch/lkp_1/transition": {Data: []byte("0\n")},
		"sys/module/ext4/uevent":                {Data: []byte{}},
	}
	cands := []Candidate{
		{Name: "linux-image-6.8.0-100-generic", Version: "6.8.0-100.100", Release: "6.8.0-100-generic"},
		{Name: "linux-image-generic", Version: "6.8.0.100.100"},
		{Name: "linux-image-6.8.0-45-generic", Version: "6.8.0-45.45", Release: "6.8.0-45-generic"},
		{Name: "linux-image-6.8.0-31-generic", Version: "6.8.0-31.31", Release: "6.8.0-31-generic"},
	}
	rank := map[string]int{"6.8.0-31.31": 1, "6.8.0-45.45": 2, "6.8.0-100.100": 3}
	cmp := func(a, b string) int { return rank[a] - rank[b] }
	info, err := Collect(fsys, cands, cmp)
	if err != nil {
		t.Fatal(err)
	}
	if info.Running.Release != "6.8.0-45-generic" || info.Running.BootID == "" || !strings.HasPrefix(info.Running.Version, "#45") {
		t.Errorf("Running = %+v", info.Running)
	}
	if info.NewestInstalled != "6.8.0-100-generic" {
		t.Errorf("NewestInstalled = %q", info.NewestInstalled)
	}
	if len(info.Installed) != 3 || info.Installed[0].Release != "6.8.0-31-generic" || info.Installed[0].BootImage {
		t.Errorf("Installed = %+v", info.Installed)
	}
	if !info.Installed[1].Running || !info.Installed[1].BootImage {
		t.Errorf("Installed[1] = %+v", info.Installed[1])
	}
	if len(info.LivePatches) != 1 || !info.LivePatches[0].Enabled || info.EffectiveKnown {
		t.Errorf("LivePatches = %+v, EffectiveKnown = %v", info.LivePatches, info.EffectiveKnown)
	}
}

func TestCollectPlain(t *testing.T) {
	fsys := fstest.MapFS{
		"proc/sys/kernel/osrelease":           {Data: []byte("5.14.0-427.el9.x86_64\n")},
		"sys/module/ksplice_abc123_vmlinux/x": {Data: []byte{}},
	}
	info, err := Collect(fsys, nil, strings.Compare)
	if err != nil {
		t.Fatal(err)
	}
	if info.EffectiveKnown || len(info.KspliceModules) != 1 || info.LivePatches == nil {
		t.Errorf("got %+v", info)
	}
	if _, err := Collect(fstest.MapFS{}, nil, nil); err == nil {
		t.Error("missing /proc: want error")
	}
}

func TestRPMRelease(t *testing.T) {
	cases := []struct {
		name, version, release, arch string
		want                         string
		fallback                     bool
	}{
		{"kernel-core", "5.14.0", "687.36.1.el9_8", "x86_64", "5.14.0-687.36.1.el9_8.x86_64", false},
		{"kernel-uek-core", "5.15.0", "310.1.el9uek", "x86_64", "5.15.0-310.1.el9uek.x86_64", false},
		{"kernel-debug-core", "5.14.0", "687.el9", "aarch64", "5.14.0-687.el9.aarch64+debug", false},
		{"kernel", "5.14.0", "687.36.1.el9_8", "x86_64", "5.14.0-687.36.1.el9_8.x86_64", true},
		{"kernel-uek", "5.4.17", "2136.el8uek", "x86_64", "5.4.17-2136.el8uek.x86_64", true},
		{"kernel-modules-core", "5.14.0", "687.36.1.el9_8", "x86_64", "", false},
		{"kernel-headers", "5.14.0", "687.36.1.el9_8", "x86_64", "", false},
		{"kernel-core", "5.14.0", "687.36.1.el9_8", "", "", false},
	}
	for _, c := range cases {
		got, fb := RPMRelease(c.name, c.version, c.release, c.arch)
		if got != c.want || fb != c.fallback {
			t.Errorf("RPMRelease(%s) = %q, %v; want %q, %v", c.name, got, fb, c.want, c.fallback)
		}
	}
}
