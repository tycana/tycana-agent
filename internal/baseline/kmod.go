package baseline

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
)

// KmodCheck is ComplianceAsCode's kernel_module_disabled template. It
// reads only configuration, never the loaded modules.
//
// "install NAME /bin/false" (or /bin/true) must appear in a *.conf file in
// the modprobe.d and modules-load.d directories of /etc, /run, and
// /usr/lib. With Blacklist (Ubuntu, RHEL) a "blacklist NAME" line must
// also appear; without it (Debian, AlmaLinux) /etc/modprobe.conf may carry
// the install line instead.
type KmodCheck struct {
	Name      string `yaml:"name"`
	Blacklist bool   `yaml:"blacklist,omitempty"`
}

var kmodDirs = []string{"/etc/modprobe.d", "/etc/modules-load.d", "/run/modprobe.d",
	"/run/modules-load.d", "/usr/lib/modprobe.d", "/usr/lib/modules-load.d"}

var kmodNameRE = regexp.MustCompile(`^[a-z0-9_-]+$`)

func (k *KmodCheck) validate() error {
	if !kmodNameRE.MatchString(k.Name) {
		return fmt.Errorf("kernel_module: name %q is not valid", k.Name)
	}
	return nil
}

func (k *KmodCheck) eval(h *Host) (bool, string, error) {
	install := regexp.MustCompile(`(?m)^\s*install\s+` + k.Name + `\s+(/bin/false|/bin/true)$`)
	blacklist := regexp.MustCompile(`(?m)^blacklist\s+` + k.Name + `$`)
	files := make([]string, 0, 8*len(kmodDirs))
	for _, d := range kmodDirs {
		files = append(files, confFiles(h, d)...)
	}
	var dis, bl string
	for _, f := range files {
		b, err := h.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, "", err
		}
		if dis == "" && install.Match(b) {
			dis = f
		}
		if bl == "" && blacklist.Match(b) {
			bl = f
		}
	}
	if k.Blacklist {
		switch {
		case dis == "" && bl == "":
			return false, "no install " + k.Name + " /bin/false and no blacklist line", nil
		case dis == "":
			return false, "no install " + k.Name + " /bin/false line", nil
		case bl == "":
			return false, "no blacklist " + k.Name + " line", nil
		}
		return true, "install line in " + dis + ", blacklist in " + bl, nil
	}
	if dis != "" {
		return true, "install line in " + dis, nil
	}
	b, err := h.ReadFile("/etc/modprobe.conf")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, "", err
	}
	if install.Match(b) {
		return true, "install line in /etc/modprobe.conf", nil
	}
	return false, "no install " + k.Name + " /bin/false line", nil
}
