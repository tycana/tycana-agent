package agent

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckBinaryDpkg(t *testing.T) {
	root := t.TempDir()
	info := filepath.Join(root, "var/lib/dpkg/info")
	bin := filepath.Join(root, "usr/bin/tycanad")
	for _, d := range []string{info, filepath.Dir(bin)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	content := []byte("agent binary")
	_ = os.WriteFile(bin, content, 0o755)
	sum := md5.Sum(content)
	// The package lists the path as the host sees it; the test root
	// stands in for "/", so the list names the full test path.
	_ = os.WriteFile(filepath.Join(info, "coreutils.list"), []byte("/usr/bin/ls\n"), 0o644)
	_ = os.WriteFile(filepath.Join(info, "tycana.list"), []byte("/usr\n"+bin+"\n"), 0o644)
	md5sums := hex.EncodeToString(sum[:]) + "  " + bin[1:] + "\n"
	_ = os.WriteFile(filepath.Join(info, "tycana.md5sums"), []byte(md5sums), 0o644)

	sc, err := CheckBinary(root, bin)
	if err != nil || sc.Result != CheckDpkg || len(sc.SHA256) != 64 {
		t.Fatalf("match: %+v %v", sc, err)
	}
	_ = os.WriteFile(bin, []byte("changed"), 0o755)
	if _, err := CheckBinary(root, bin); !errors.Is(err, ErrBinaryChanged) {
		t.Errorf("changed binary: %v", err)
	}
	// No md5sums entry: unknown, not fatal.
	_ = os.WriteFile(filepath.Join(info, "tycana.md5sums"), nil, 0o644)
	if sc, err := CheckBinary(root, bin); err != nil || sc.Result != CheckUnknown {
		t.Errorf("no digest: %+v %v", sc, err)
	}
	// Not owned by a package.
	_ = os.WriteFile(filepath.Join(info, "tycana.list"), []byte("/usr\n"), 0o644)
	if sc, err := CheckBinary(root, bin); err != nil || sc.Result != CheckNone {
		t.Errorf("unowned: %+v %v", sc, err)
	}
}
