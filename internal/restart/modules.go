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

// Module is a file that programs map only after they open a module at
// run time (dlopen): the module itself, or a library in the module's own
// closure. It was created after the earliest unit started. A unit whose
// program is Host, or whose closure contains Host, may have it mapped.
type Module struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // nss, pam, openssl, sasl, gconv, apache, nginx
	// Host is the soname of the library that opens the module (libc.so.6,
	// libpam.so.0), or the canonical path of the program that does
	// (/usr/sbin/httpd).
	Host string `json:"host"`
	// Via is the module that needs Path, when Path is a dependency of the
	// module rather than the module itself.
	Via     string    `json:"via,omitempty"`
	Created time.Time `json:"created"`
}

// moduleDirs are the plugin directories, relative to a library directory,
// and the library that opens their modules.
var moduleDirs = []struct{ kind, host, dir string }{
	{"pam", "libpam.so.0", "security"},
	{"openssl", "libcrypto.so.3", "ossl-modules"},
	{"openssl", "libcrypto.so.3", "engines-3"},
	{"sasl", "libsasl2.so.2", "sasl2"},
	{"gconv", "libc.so.6", "gconv"},
}

// programDirs are plugin directories of servers that open their modules
// themselves: mod_ssl, not httpd, links libssl.
var programDirs = []struct{ kind, host, dir string }{
	{"apache", "/usr/sbin/httpd", "/usr/lib64/httpd/modules"},
	{"apache", "/usr/sbin/apache2", "/usr/lib/apache2/modules"},
	{"nginx", "/usr/sbin/nginx", "/usr/lib64/nginx/modules"},
	{"nginx", "/usr/sbin/nginx", "/usr/lib/nginx/modules"},
}

// maxModules bounds the modules one collection resolves.
const maxModules = 4096

// modules lists the files of run-time modules, and of the modules' own
// closures, created after since. NSS modules are limited to the sources
// /etc/nsswitch.conf names: an unconfigured module is never loaded.
func (r *Resolver) modules(since time.Time) []Module {
	type cand struct{ kind, host, path string }
	var cands []cand
	for _, lib := range r.libDirs() {
		for _, src := range r.nssSources() {
			p := path.Join(lib, "libnss_"+src+".so.2")
			if _, err := os.Lstat(r.host(p)); err == nil {
				cands = append(cands, cand{"nss", "libc.so.6", p})
			}
		}
		for _, d := range moduleDirs {
			for _, m := range r.glob(path.Join(lib, d.dir)) {
				cands = append(cands, cand{d.kind, d.host, m})
			}
		}
	}
	for _, d := range programDirs {
		host, err := r.canonical(d.host)
		if err != nil {
			continue
		}
		for _, m := range r.glob(d.dir) {
			cands = append(cands, cand{d.kind, host, m})
		}
	}

	var out []Module
	seenMod := map[string]bool{}
	seenOut := map[string]bool{}
	times := map[string]FileTime{}
	for _, c := range cands {
		mod, err := r.canonical(c.path)
		if err != nil || seenMod[c.host+"|"+mod] {
			continue
		}
		seenMod[c.host+"|"+mod] = true
		if len(seenMod) > maxModules {
			break
		}
		closure := []string{mod}
		if p := r.Program(mod); p.Error == "" {
			closure = p.Closure
		}
		for _, f := range closure {
			ft, ok := times[f]
			if !ok {
				ft = fileTime(r.host(f))
				times[f] = ft
			}
			if ft.Error != "" || !ft.Time.After(since) || seenOut[c.host+"|"+f] {
				continue
			}
			seenOut[c.host+"|"+f] = true
			m := Module{Path: f, Kind: c.kind, Host: c.host, Created: ft.Time}
			if f != mod {
				m.Via = mod
			}
			out = append(out, m)
		}
	}
	slices.SortFunc(out, func(a, b Module) int {
		return strings.Compare(a.Host+"|"+a.Path, b.Host+"|"+b.Path)
	})
	return out
}

// glob lists the shared objects in dir, sorted.
func (r *Resolver) glob(dir string) []string {
	matches, _ := filepath.Glob(r.host(path.Join(dir, "*.so*")))
	slices.Sort(matches)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, path.Join(dir, filepath.Base(m)))
	}
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
