package restart

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Module is a shared object that programs open at run time (dlopen)
// rather than at start, and that was created after the earliest unit
// started. Its host library loads it; a unit whose closure contains the
// host may have it mapped.
type Module struct {
	Path    string    `json:"path"`
	Kind    string    `json:"kind"` // nss, pam, openssl, sasl, gconv
	Host    string    `json:"host"` // soname of the library that loads it
	Created time.Time `json:"created"`
}

// moduleDirs are the plugin directories, relative to a library directory,
// and the library that loads their modules.
var moduleDirs = []struct{ kind, host, dir string }{
	{"pam", "libpam.so.0", "security"},
	{"openssl", "libcrypto.so.3", "ossl-modules"},
	{"openssl", "libcrypto.so.3", "engines-3"},
	{"sasl", "libsasl2.so.2", "sasl2"},
	{"gconv", "libc.so.6", "gconv"},
}

// maxModules bounds the files one collection times.
const maxModules = 8192

// modules lists the run-time modules created after since. NSS modules are
// limited to the sources /etc/nsswitch.conf names: an unconfigured module
// is never loaded.
func (r *Resolver) modules(since time.Time) []Module {
	var out []Module
	checked := 0
	seen := map[string]bool{}
	add := func(kind, host, p string) {
		canon, err := r.canonical(p)
		if err != nil || seen[canon] || checked >= maxModules {
			return
		}
		seen[canon] = true
		checked++
		ft := fileTime(r.host(canon))
		if ft.Error == "" && ft.Time.After(since) {
			out = append(out, Module{Path: canon, Kind: kind, Host: host, Created: ft.Time})
		}
	}
	nss := r.nssSources()
	for _, lib := range r.libDirs() {
		for _, src := range nss {
			p := path.Join(lib, "libnss_"+src+".so.2")
			if _, err := os.Lstat(r.host(p)); err == nil {
				add("nss", "libc.so.6", p)
			}
		}
		for _, d := range moduleDirs {
			matches, _ := filepath.Glob(r.host(path.Join(lib, d.dir, "*.so*")))
			slices.Sort(matches)
			for _, m := range matches {
				add(d.kind, d.host, path.Join(lib, d.dir, filepath.Base(m)))
			}
		}
	}
	slices.SortFunc(out, func(a, b Module) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// libDirs is the loader's search list without duplicates.
func (r *Resolver) libDirs() []string {
	var out []string
	seen := map[string]bool{}
	for _, d := range slices.Concat(r.dirs, defaultDirs(nativeMachine)) {
		c, err := r.canonical(d)
		if err != nil || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

// nssSources returns the module names /etc/nsswitch.conf uses, such as
// "files", "systemd", "sss". Action items like "[NOTFOUND=return]" are
// skipped.
func (r *Resolver) nssSources() []string {
	f, err := os.Open(r.host("/etc/nsswitch.conf"))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }() // read-only
	var out []string
	sc := bufio.NewScanner(f)
	for n := 0; sc.Scan() && n < maxConfLines; n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		_, srcs, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		for _, w := range strings.Fields(srcs) {
			if strings.HasPrefix(w, "[") || strings.HasSuffix(w, "]") || strings.Contains(w, "=") {
				continue
			}
			if validModuleName(w) && !slices.Contains(out, w) {
				out = append(out, w)
			}
		}
	}
	return out
}

func validModuleName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
