package restart

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Limits on what one closure walk reads.
const (
	maxClosure   = 512     // objects in one closure
	maxLinkDepth = 40      // symlinks followed for one path
	maxShebang   = 256     // bytes of a "#!" line
	maxConfLines = 10000   // lines across ld.so.conf and its includes
	maxELFSize   = 1 << 30 // files larger than this are not parsed
)

// errNotELF marks a program that is not an ELF file.
var errNotELF = errors.New("not an ELF file")

// Resolver finds the shared objects the dynamic loader maps when a
// program starts: its PT_INTERP loader and the DT_NEEDED closure. It
// reads files and never executes them. Libraries a program opens later
// with dlopen (PAM and NSS modules, OpenSSL providers, interpreter
// modules) are outside its view.
type Resolver struct {
	// Root is "/" on a host, or a directory tree in tests. Every path
	// is resolved inside it, symlinks included.
	Root string

	dirs  []string // ld.so.conf directories, then the defaults
	cache map[string]*object
}

// object is one parsed ELF file.
type object struct {
	class   elf.Class
	machine elf.Machine
	interp  string
	needed  []string
	runpath []string
	rpath   []string
}

// NewResolver reads the loader configuration under root.
func NewResolver(root string) *Resolver {
	r := &Resolver{Root: root, cache: map[string]*object{}}
	lines := 0
	r.dirs = r.readConf("/etc/ld.so.conf", map[string]bool{}, &lines)
	return r
}

// Program is the closure of one program.
type Program struct {
	// Path is the program's canonical path.
	Path string `json:"path"`
	// Interpreter is the canonical "#!" program when Path is a script;
	// the closure is then the interpreter's.
	Interpreter string `json:"interpreter,omitempty"`
	// Closure lists canonical paths: the program (or interpreter), its
	// loader, and every DT_NEEDED object, recursively.
	Closure []string `json:"closure,omitempty"`
	// Unresolved lists DT_NEEDED names found in no search directory.
	Unresolved []string `json:"unresolved,omitempty"`
	// Error says why the closure is missing or incomplete.
	Error string `json:"error,omitempty"`
}

// Program returns the closure of the program at p.
func (r *Resolver) Program(p string) Program {
	prog := Program{}
	canon, err := r.canonical(p)
	if err != nil {
		prog.Error = err.Error()
		return prog
	}
	prog.Path = canon
	main, err := r.load(canon)
	if errors.Is(err, errNotELF) {
		interp, serr := r.shebang(canon)
		if serr != nil {
			prog.Error = serr.Error()
			return prog
		}
		if canon, err = r.canonical(interp); err != nil {
			prog.Error = fmt.Sprintf("interpreter %s: %v", interp, err)
			return prog
		}
		prog.Interpreter = canon
		main, err = r.load(canon)
	}
	if err != nil {
		prog.Error = err.Error()
		return prog
	}
	prog.Closure, prog.Unresolved, err = r.closure(canon, main)
	if err != nil {
		prog.Error = err.Error()
	}
	return prog
}

// closure walks DT_NEEDED breadth-first from the main object, the way
// glibc's loader searches: RPATH (when the object has no RUNPATH, also
// the main program's), RUNPATH, the ld.so.conf directories, the defaults.
func (r *Resolver) closure(mainPath string, main *object) ([]string, []string, error) {
	seen := map[string]bool{mainPath: true}
	out := []string{mainPath}
	var unresolved []string
	if main.interp != "" {
		if p, err := r.canonical(main.interp); err == nil {
			seen[p] = true
			out = append(out, p)
		} else {
			unresolved = append(unresolved, main.interp)
		}
	}
	type item struct {
		path string
		obj  *object
	}
	queue := []item{{mainPath, main}}
	loaded := map[string]bool{} // sonames already resolved
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		for _, name := range it.obj.needed {
			if loaded[name] {
				continue
			}
			p, obj := r.find(name, it.path, it.obj, mainPath, main)
			if obj == nil {
				if !slices.Contains(unresolved, name) {
					unresolved = append(unresolved, name)
				}
				continue
			}
			loaded[name] = true
			if seen[p] {
				continue
			}
			if len(out) >= maxClosure {
				return out, unresolved, fmt.Errorf("closure larger than %d objects", maxClosure)
			}
			seen[p] = true
			out = append(out, p)
			queue = append(queue, item{p, obj})
		}
	}
	return out, unresolved, nil
}

// find locates the object for a DT_NEEDED name needed by the object at
// from. It returns the canonical path and the parsed object, or nil.
func (r *Resolver) find(name, from string, obj *object, mainPath string, main *object) (string, *object) {
	if strings.Contains(name, "/") {
		return r.candidate(name, obj)
	}
	var dirs []string
	if len(obj.runpath) == 0 {
		dirs = append(dirs, expand(obj.rpath, from)...)
		if from != mainPath {
			dirs = append(dirs, expand(main.rpath, mainPath)...)
		}
	}
	dirs = append(dirs, expand(obj.runpath, from)...)
	dirs = append(dirs, r.dirs...)
	dirs = append(dirs, defaultDirs(obj.machine)...)
	for _, d := range dirs {
		if p, o := r.candidate(path.Join(d, name), obj); o != nil {
			return p, o
		}
	}
	return "", nil
}

// candidate accepts the file at p if it is an ELF object of the same
// class and machine as the object that needs it, as the loader does.
func (r *Resolver) candidate(p string, need *object) (string, *object) {
	canon, err := r.canonical(p)
	if err != nil {
		return "", nil
	}
	o, err := r.load(canon)
	if err != nil || o.class != need.class || o.machine != need.machine {
		return "", nil
	}
	return canon, o
}

// expand replaces $ORIGIN in RPATH and RUNPATH entries. Entries with
// other tokens ($LIB, $PLATFORM) are dropped: the closure is then at
// worst incomplete, and the name shows as unresolved.
func expand(dirs []string, from string) []string {
	var out []string
	for _, d := range dirs {
		d = strings.ReplaceAll(d, "${ORIGIN}", "$ORIGIN")
		d = strings.ReplaceAll(d, "$ORIGIN", path.Dir(from))
		if d == "" || strings.Contains(d, "$") || !strings.HasPrefix(d, "/") {
			continue
		}
		out = append(out, d)
	}
	return out
}

// defaultDirs are the loader's built-in directories after ld.so.conf:
// lib64 on rpm systems, the multiarch directory on Debian systems.
func defaultDirs(m elf.Machine) []string {
	var triplet string
	switch m {
	case elf.EM_X86_64:
		triplet = "x86_64-linux-gnu"
	case elf.EM_AARCH64:
		triplet = "aarch64-linux-gnu"
	}
	dirs := []string{"/lib64", "/usr/lib64"}
	if triplet != "" {
		dirs = append(dirs, "/lib/"+triplet, "/usr/lib/"+triplet)
	}
	return append(dirs, "/lib", "/usr/lib")
}

// load parses the ELF file at a canonical path, once.
func (r *Resolver) load(p string) (*object, error) {
	if o, ok := r.cache[p]; ok {
		if o == nil {
			return nil, errNotELF
		}
		return o, nil
	}
	o, err := r.parse(p)
	if errors.Is(err, errNotELF) {
		r.cache[p] = nil
	} else if err == nil {
		r.cache[p] = o
	}
	return o, err
}

func (r *Resolver) parse(p string) (o *object, err error) {
	f, err := os.Open(r.host(p))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if fi.Size() > maxELFSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, maxELFSize)
	}
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil || string(magic[:]) != elf.ELFMAG {
		return nil, errNotELF
	}
	// debug/elf has panicked on malformed input before; a file the
	// loader would reject is reported, not fatal.
	defer func() {
		if x := recover(); x != nil {
			o, err = nil, fmt.Errorf("%s: malformed ELF file", p)
		}
	}()
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	o = &object{class: ef.Class, machine: ef.Machine}
	for _, prog := range ef.Progs {
		if prog.Type == elf.PT_INTERP {
			b, err := io.ReadAll(io.LimitReader(prog.Open(), 4096))
			if err != nil {
				return nil, fmt.Errorf("%s: PT_INTERP: %w", p, err)
			}
			o.interp = string(bytes.TrimRight(b, "\x00"))
		}
	}
	if ef.SectionByType(elf.SHT_DYNAMIC) == nil {
		return o, nil // static
	}
	if o.needed, err = ef.DynString(elf.DT_NEEDED); err != nil {
		return nil, fmt.Errorf("%s: DT_NEEDED: %w", p, err)
	}
	rp, _ := ef.DynString(elf.DT_RUNPATH)
	o.runpath = splitPaths(rp)
	rp, _ = ef.DynString(elf.DT_RPATH)
	o.rpath = splitPaths(rp)
	return o, nil
}

func splitPaths(v []string) []string {
	out := make([]string, 0, len(v))
	for _, s := range v {
		out = append(out, strings.Split(s, ":")...)
	}
	return out
}

// shebang returns the interpreter of a "#!" script.
func (r *Resolver) shebang(p string) (string, error) {
	f, err := os.Open(r.host(p))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only
	b := make([]byte, maxShebang)
	n, _ := io.ReadFull(f, b)
	b = b[:n]
	if !bytes.HasPrefix(b, []byte("#!")) {
		return "", fmt.Errorf("%s: %w and not a script", p, errNotELF)
	}
	line, _, _ := bytes.Cut(b[2:], []byte("\n"))
	fields := strings.Fields(string(line))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return "", fmt.Errorf("%s: no interpreter path after the #! marker", p)
	}
	interp := fields[0]
	// "#!/usr/bin/env python3": the program is the argument, found on
	// hostexec's fixed PATH, the PATH a service gets from systemd.
	if path.Base(interp) == "env" && len(fields) > 1 && !strings.HasPrefix(fields[1], "-") {
		for _, d := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
			c := path.Join(d, fields[1])
			if _, err := os.Stat(r.host(c)); err == nil {
				return c, nil
			}
		}
		return "", fmt.Errorf("%s: env program %q not found", p, fields[1])
	}
	return interp, nil
}

// readConf reads an ld.so.conf file and its includes, in order.
func (r *Resolver) readConf(name string, visited map[string]bool, lines *int) []string {
	if visited[name] {
		return nil
	}
	visited[name] = true
	f, err := os.Open(r.host(name))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }() // read-only
	var dirs []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		*lines++
		if *lines > maxConfLines {
			break
		}
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0 || fields[0] == "hwcap":
		case fields[0] == "include":
			for _, pat := range fields[1:] {
				if !strings.HasPrefix(pat, "/") {
					pat = path.Join(path.Dir(name), pat)
				}
				matches, _ := filepath.Glob(r.host(pat))
				slices.Sort(matches)
				for _, m := range matches {
					rel := "/" + strings.TrimPrefix(strings.TrimPrefix(m, r.Root), "/")
					dirs = append(dirs, r.readConf(rel, visited, lines)...)
				}
			}
		default:
			for _, d := range fields {
				if strings.HasPrefix(d, "/") {
					dirs = append(dirs, path.Clean(d))
				}
			}
		}
	}
	return dirs
}

// host maps a path inside Root to the path on this machine.
func (r *Resolver) host(p string) string {
	return filepath.Join(r.Root, filepath.FromSlash(p))
}

// canonical resolves every symlink in p inside Root, the way the kernel
// would with Root as "/". Absolute link targets restart at Root.
func (r *Resolver) canonical(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("%q is not an absolute path", p)
	}
	links := 0
	done := "/"
	rest := strings.Split(strings.Trim(path.Clean(p), "/"), "/")
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			done = path.Dir(done)
			continue
		}
		next := path.Join(done, c)
		fi, err := os.Lstat(r.host(next))
		if err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			done = next
			continue
		}
		if links++; links > maxLinkDepth {
			return "", fmt.Errorf("%s: too many levels of symbolic links", p)
		}
		target, err := os.Readlink(r.host(next))
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(target, "/") {
			done = "/"
		}
		rest = append(strings.Split(strings.Trim(target, "/"), "/"), rest...)
	}
	return done, nil
}
