package restart

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LivePatching is the live patching the agent can see on the host from
// sources any user can read (research note
// 2026-10-16-restart-market-and-live-patching.md). Kernel live patches
// make "an older kernel runs" an overstatement for the CVEs they cover;
// Ksplice user space, TuxCare LibCare and SUSE ULP do the same for glibc
// and OpenSSL in running processes. The agent shows them and never marks a
// finding as covered: proof is per process and needs root.
type LivePatching struct {
	Kernel    []string `json:"kernel,omitempty"`
	UserSpace []string `json:"user_space,omitempty"`
}

// PackageInfo is the part of an installed package the detection reads.
type PackageInfo struct {
	Name, Version, Release string
}

// DetectLivePatching reads the kernel's live patches (names from
// /sys/kernel/livepatch, loaded Ksplice modules, both from the inventory),
// KernelCare's /proc/kcare, and the installed packages.
func DetectLivePatching(root string, livepatches, kspliceModules []string, pkgs []PackageInfo) LivePatching {
	var lp LivePatching
	for _, n := range livepatches {
		lp.Kernel = append(lp.Kernel, "kernel live patch "+n+" (/sys/kernel/livepatch)")
	}
	if len(kspliceModules) > 0 {
		lp.Kernel = append(lp.Kernel, fmt.Sprintf("Ksplice: %d modules loaded; the effective kernel needs root (ksplice kernel uname -r)", len(kspliceModules)))
	}
	if _, err := os.Stat(filepath.Join(root, "proc", "kcare")); err == nil {
		if b, err := readSmall(filepath.Join(root, "proc", "kcare", "effective_version")); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			lp.Kernel = append(lp.Kernel, "KernelCare: effective kernel "+firstLineOf(b))
		} else {
			lp.Kernel = append(lp.Kernel, "KernelCare is loaded; its effective kernel is not readable here")
		}
	}
	for _, p := range pkgs {
		switch {
		case strings.Contains(p.Release, "ksplice") || strings.Contains(p.Version, "ksplice"):
			lp.UserSpace = append(lp.UserSpace, fmt.Sprintf("Ksplice-aware %s %s-%s: the Ksplice Enhanced client can patch it in running processes; proof needs root (ksplice user show)", p.Name, p.Version, p.Release))
		case p.Name == "ksplice":
			lp.UserSpace = append(lp.UserSpace, "Ksplice Enhanced client installed")
		case p.Name == "kernelcare":
			lp.UserSpace = append(lp.UserSpace, "KernelCare installed: LibCare can patch glibc and OpenSSL in running processes; proof needs root (kcarectl --lib-info)")
		case p.Name == "libpulp0" || p.Name == "libpulp":
			lp.UserSpace = append(lp.UserSpace, "SUSE libpulp installed: processes started with it preloaded can be patched; proof needs root (ulp patches)")
		}
	}
	return lp
}

func firstLineOf(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
