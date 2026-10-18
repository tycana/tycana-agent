package dpkg

import (
	"errors"
	"testing"
	"testing/fstest"
)

func TestWalkFiles(t *testing.T) {
	fsys := fstest.MapFS{
		"var/lib/dpkg/info/libc6:amd64.list": {Data: []byte("/.\n/lib\n/lib/x86_64-linux-gnu/libc.so.6\n")},
		"var/lib/dpkg/info/sudo.list":        {Data: []byte("/.\n/usr/bin/sudo\n")},
		"var/lib/dpkg/info/sudo.md5sums":     {Data: []byte("x  usr/bin/sudo\n")},
	}
	var got []File
	if err := WalkFiles(fsys, DefaultAdminDir, func(f File) error { got = append(got, f); return nil }); err != nil {
		t.Fatal(err)
	}
	want := []File{{"libc6", "/lib"}, {"libc6", "/lib/x86_64-linux-gnu/libc.so.6"}, {"sudo", "/usr/bin/sudo"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
	stop := errors.New("stop")
	if err := WalkFiles(fsys, DefaultAdminDir, func(File) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("stop: %v", err)
	}
	if err := WalkFiles(fstest.MapFS{}, DefaultAdminDir, func(File) error { return nil }); err == nil {
		t.Error("no lists must be an error")
	}
}
