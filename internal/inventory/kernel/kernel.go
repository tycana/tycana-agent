// Package kernel reports installed, running, and live-patched kernels.
//
// It reads /proc, /sys, and /boot through an fs.FS rooted at the host's
// root directory. It does not run uname, canonical-livepatch, kpatch, or
// uptrack-uname; anything that needs a command waits for internal/hostexec
// (M2), and until then the "effective" kernel is reported as unknown
// rather than guessed.
package kernel

import (
	"errors"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Running describes the booted kernel.
type Running struct {
	Release string `json:"release"`           // uname -r
	Version string `json:"version,omitempty"` // uname -v: build string, carries the package version on Debian
	BootID  string `json:"boot_id,omitempty"`
}

// Installed is one kernel image package on disk.
type Installed struct {
	Release        string `json:"release"`
	Package        string `json:"package"`
	PackageVersion string `json:"package_version"`
	BootImage      bool   `json:"boot_image"` // /boot/vmlinuz-<release> exists
	Running        bool   `json:"running"`    // release equals the running release
}

// Patch is one kernel live patch registered with the kernel's livepatch
// core (/sys/kernel/livepatch). Canonical Livepatch and kpatch both use it.
type Patch struct {
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Transition bool   `json:"transition"`
}

// Info is the kernel section of an inventory snapshot.
type Info struct {
	Running   Running     `json:"running"`
	Installed []Installed `json:"installed"`
	// NewestInstalled is the release of the installed kernel package with
	// the highest package version, or "" when none is installed.
	NewestInstalled string  `json:"newest_installed,omitempty"`
	LivePatches     []Patch `json:"live_patches"`
	// KspliceModules lists loaded ksplice modules (Oracle Linux). Their
	// effective kernel level needs uptrack-uname, which arrives with
	// internal/hostexec; until then EffectiveKnown is false when this is
	// non-empty.
	KspliceModules []string `json:"ksplice_modules,omitempty"`
	// EffectiveKnown is true when the running release is also the
	// effective patch level: no live patches and no Ksplice. When false,
	// consumers must not treat Running.Release as the patch level.
	EffectiveKnown bool `json:"effective_known"`
}

// Candidate is a package the caller offers as a possible kernel image.
type Candidate struct {
	Name    string
	Version string
	// Release is the kernel release (uname -r form) this package installs;
	// empty means "not a kernel image".
	Release string
}

// Collect gathers kernel facts. cmp orders package versions with the
// host's native rules (dpkg or rpm).
func Collect(fsys fs.FS, candidates []Candidate, cmp func(a, b string) int) (Info, error) {
	var info Info
	var err error
	if info.Running.Release, err = readLine(fsys, "proc/sys/kernel/osrelease"); err != nil {
		return info, err
	}
	info.Running.Version, _ = readLine(fsys, "proc/sys/kernel/version")
	info.Running.BootID, _ = readLine(fsys, "proc/sys/kernel/random/boot_id")

	var newest *Candidate
	for i := range candidates {
		c := &candidates[i]
		if c.Release == "" {
			continue
		}
		_, statErr := fs.Stat(fsys, path.Join("boot", "vmlinuz-"+c.Release))
		info.Installed = append(info.Installed, Installed{
			Release:        c.Release,
			Package:        c.Name,
			PackageVersion: c.Version,
			BootImage:      statErr == nil,
			Running:        c.Release == info.Running.Release,
		})
		if newest == nil || cmp(c.Version, newest.Version) > 0 {
			newest = c
		}
	}
	if newest != nil {
		info.NewestInstalled = newest.Release
	}
	sort.Slice(info.Installed, func(i, j int) bool {
		return cmp(info.Installed[i].PackageVersion, info.Installed[j].PackageVersion) < 0
	})

	info.LivePatches = []Patch{}
	ents, err := fs.ReadDir(fsys, "sys/kernel/livepatch")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return info, err
	}
	for _, e := range ents {
		dir := path.Join("sys/kernel/livepatch", e.Name())
		en, _ := readLine(fsys, path.Join(dir, "enabled"))
		tr, _ := readLine(fsys, path.Join(dir, "transition"))
		info.LivePatches = append(info.LivePatches, Patch{Name: e.Name(), Enabled: en == "1", Transition: tr == "1"})
	}

	// UNVERIFIED: Ksplice module naming (ksplice_*) is from Oracle's docs.
	// tycana-oel9 (Oracle Linux 9.8, 2026-10-16) ships no Ksplice packages
	// or modules; verifying needs a host registered for Ksplice updates.
	mods, err := fs.ReadDir(fsys, "sys/module")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return info, err
	}
	for _, m := range mods {
		if strings.HasPrefix(m.Name(), "ksplice") {
			info.KspliceModules = append(info.KspliceModules, m.Name())
		}
	}
	info.EffectiveKnown = len(info.LivePatches) == 0 && len(info.KspliceModules) == 0
	return info, nil
}

// DebianRelease maps a dpkg kernel image package name to its kernel
// release: linux-image-6.8.0-45-generic and linux-image-unsigned-6.8.0-45-generic
// give 6.8.0-45-generic. Meta packages (linux-image-generic,
// linux-image-amd64) and debug images give "".
func DebianRelease(name string) string {
	rel, ok := strings.CutPrefix(name, "linux-image-")
	if !ok {
		return ""
	}
	rel = strings.TrimPrefix(rel, "unsigned-")
	if rel == "" || rel[0] < '0' || rel[0] > '9' {
		return ""
	}
	if strings.HasSuffix(rel, "-dbg") || strings.HasSuffix(rel, "-dbgsym") {
		return ""
	}
	return rel
}

// rpmKernelImages maps rpm package names that carry a kernel image to the
// suffix uname -r appends for that variant. The empty suffix is the plain
// kernel. kernel-core (AlmaLinux 9) and kernel-uek-core (Oracle Linux 9,
// UEK 8) are verified on the lab VMs, 2026-10-16. UNVERIFIED on a live
// host: kernel-debug-core ("+debug") and the rt/64k variants are from
// Fedora and RHEL packaging, not yet observed in the lab.
var rpmKernelImages = map[string]string{
	"kernel-core":       "",
	"kernel-uek-core":   "",
	"kernel-rt-core":    "",
	"kernel-64k-core":   "",
	"kernel-debug-core": "+debug",
}

// rpmKernelFallbacks are packages that carry the image themselves on
// distributions without a -core subpackage (RHEL 7, Oracle UEK 6). They
// count only when no -core package names the same release.
var rpmKernelFallbacks = map[string]bool{"kernel": true, "kernel-uek": true}

// RPMRelease maps an rpm kernel package to the kernel release it
// installs: kernel-core 5.14.0-687.36.1.el9_8 x86_64 gives
// 5.14.0-687.36.1.el9_8.x86_64. fallback is true for "kernel" and
// "kernel-uek", which carry the image only on older distributions; the
// caller drops them when a -core package names the same release. Other
// packages (kernel-modules, kernel-headers, meta packages) give "".
func RPMRelease(name, version, release, arch string) (rel string, fallback bool) {
	if version == "" || release == "" || arch == "" {
		return "", false
	}
	suffix, ok := rpmKernelImages[name]
	if ok {
		return version + "-" + release + "." + arch + suffix, false
	}
	if rpmKernelFallbacks[name] {
		return version + "-" + release + "." + arch, true
	}
	return "", false
}

func readLine(fsys fs.FS, name string) (string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
