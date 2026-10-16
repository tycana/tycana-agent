package restart

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeELF writes a minimal ELF64 shared object with the given PT_INTERP,
// DT_NEEDED and DT_RUNPATH, enough for debug/elf and the Resolver.
func writeELF(t *testing.T, root, p string, m elf.Machine, interp, runpath string, needed ...string) {
	t.Helper()
	dynstr := []byte{0}
	str := func(s string) uint64 {
		off := uint64(len(dynstr))
		dynstr = append(append(dynstr, s...), 0)
		return off
	}
	var dyn []elf.Dyn64
	for _, n := range needed {
		dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_NEEDED), Val: str(n)})
	}
	if runpath != "" {
		dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_RUNPATH), Val: str(runpath)})
	}
	dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_NULL)})
	shstr := []byte("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")

	const ehsize, phsize, shsize = 64, 56, 64
	phnum := 0
	if interp != "" {
		phnum = 1
	}
	off := uint64(ehsize + phnum*phsize)
	interpOff := off
	off += uint64(len(interp) + 1)
	dynstrOff := off
	off += uint64(len(dynstr))
	dynOff := off
	off += uint64(len(dyn) * 16)
	shstrOff := off
	off += uint64(len(shstr))
	shoff := off

	var b bytes.Buffer
	h := elf.Header64{
		Type: uint16(elf.ET_DYN), Machine: uint16(m), Version: 1,
		Ehsize: ehsize, Phentsize: phsize, Phnum: uint16(phnum),
		Shoff: shoff, Shentsize: shsize, Shnum: 4, Shstrndx: 3,
	}
	copy(h.Ident[:], elf.ELFMAG)
	h.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	h.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	h.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	if phnum > 0 {
		h.Phoff = ehsize
	}
	le := binary.LittleEndian
	must(t, binary.Write(&b, le, h))
	if phnum > 0 {
		n := uint64(len(interp) + 1)
		must(t, binary.Write(&b, le, elf.Prog64{Type: uint32(elf.PT_INTERP), Flags: uint32(elf.PF_R),
			Off: interpOff, Vaddr: interpOff, Paddr: interpOff, Filesz: n, Memsz: n, Align: 1}))
	}
	b.WriteString(interp + "\x00")
	b.Write(dynstr)
	must(t, binary.Write(&b, le, dyn))
	b.Write(shstr)
	for _, s := range []elf.Section64{
		{},
		{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: dynstrOff, Size: uint64(len(dynstr)), Addralign: 1},
		{Name: 9, Type: uint32(elf.SHT_DYNAMIC), Off: dynOff, Size: uint64(len(dyn) * 16), Link: 1, Entsize: 16, Addralign: 8},
		{Name: 18, Type: uint32(elf.SHT_STRTAB), Off: shstrOff, Size: uint64(len(shstr)), Addralign: 1},
	} {
		must(t, binary.Write(&b, le, s))
	}
	writeFile(t, root, p, b.Bytes())
}

func writeFile(t *testing.T, root, p string, data []byte) {
	t.Helper()
	full := filepath.Join(root, p)
	must(t, os.MkdirAll(filepath.Dir(full), 0o755))
	must(t, os.WriteFile(full, data, 0o755))
}

func symlink(t *testing.T, root, target, p string) {
	t.Helper()
	full := filepath.Join(root, p)
	must(t, os.MkdirAll(filepath.Dir(full), 0o755))
	must(t, os.Symlink(target, full))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// debianTree is a merged-/usr multiarch layout: /lib -> usr/lib, the
// loader configured through an include, and soname symlinks.
func debianTree(t *testing.T) string {
	root := t.TempDir()
	x := elf.EM_X86_64
	const ld = "/lib64/ld-linux-x86-64.so.2"
	symlink(t, root, "usr/lib", "/lib")
	symlink(t, root, "usr/lib64", "/lib64")
	writeFile(t, root, "/etc/ld.so.conf", []byte("include /etc/ld.so.conf.d/*.conf\n"))
	writeFile(t, root, "/etc/ld.so.conf.d/x86_64-linux-gnu.conf", []byte("# multiarch\n/usr/local/lib/x86_64-linux-gnu\n/lib/x86_64-linux-gnu\n/usr/lib/x86_64-linux-gnu\n"))
	writeELF(t, root, "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", x, "", "")
	symlink(t, root, "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/usr/lib64/ld-linux-x86-64.so.2")
	writeELF(t, root, "/usr/lib/x86_64-linux-gnu/libc.so.6", x, ld, "")
	writeELF(t, root, "/usr/lib/x86_64-linux-gnu/libsystemd.so.0.38.0", x, "", "", "libc.so.6", "libcap.so.2")
	symlink(t, root, "libsystemd.so.0.38.0", "/usr/lib/x86_64-linux-gnu/libsystemd.so.0")
	writeELF(t, root, "/usr/lib/x86_64-linux-gnu/libcap.so.2.66", x, "", "", "libc.so.6")
	symlink(t, root, "libcap.so.2.66", "/usr/lib/x86_64-linux-gnu/libcap.so.2")
	// A 32-bit object of the same name earlier in the path is skipped.
	writeELF(t, root, "/usr/local/lib/x86_64-linux-gnu/libcap.so.2", elf.EM_386, "", "")
	writeELF(t, root, "/usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-255.so", x, "", "", "libc.so.6")
	writeELF(t, root, "/usr/lib/systemd/systemd-logind", x, ld, "$ORIGIN/../x86_64-linux-gnu/systemd",
		"libsystemd-shared-255.so", "libsystemd.so.0", "libc.so.6")
	symlink(t, root, "/usr/lib/systemd/systemd-logind", "/usr/sbin/logind-alias")
	writeELF(t, root, "/usr/bin/python3.12", x, ld, "", "libc.so.6", "libmissing.so.1")
	symlink(t, root, "python3.12", "/usr/bin/python3")
	writeFile(t, root, "/usr/share/u-u/shutdown", []byte("#!/usr/bin/python3\nprint()\n"))
	writeFile(t, root, "/usr/share/u-u/env-script", []byte("#!/usr/bin/env python3 -u\n"))
	writeFile(t, root, "/usr/share/u-u/text", []byte("not a program\n"))
	return root
}

func TestResolverClosure(t *testing.T) {
	r := NewResolver(debianTree(t))
	got := r.Program("/usr/sbin/logind-alias")
	want := Program{
		Path: "/usr/lib/systemd/systemd-logind",
		Closure: []string{
			"/usr/lib/systemd/systemd-logind",
			"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
			"/usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-255.so", // via $ORIGIN RUNPATH
			"/usr/lib/x86_64-linux-gnu/libsystemd.so.0.38.0",
			"/usr/lib/x86_64-linux-gnu/libc.so.6",
			"/usr/lib/x86_64-linux-gnu/libcap.so.2.66", // the 32-bit one is skipped
		},
	}
	if got.Path != want.Path || !slices.Equal(got.Closure, want.Closure) || got.Error != "" || len(got.Unresolved) > 0 {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestResolverScripts(t *testing.T) {
	r := NewResolver(debianTree(t))
	for _, p := range []string{"/usr/share/u-u/shutdown", "/usr/share/u-u/env-script"} {
		got := r.Program(p)
		if got.Interpreter != "/usr/bin/python3.12" || got.Closure[0] != "/usr/bin/python3.12" {
			t.Errorf("%s: %+v", p, got)
		}
		if !slices.Equal(got.Unresolved, []string{"libmissing.so.1"}) {
			t.Errorf("%s: unresolved %v", p, got.Unresolved)
		}
	}
	if got := r.Program("/usr/share/u-u/text"); got.Error == "" || len(got.Closure) > 0 {
		t.Errorf("text file: %+v", got)
	}
	if got := r.Program("/no/such/program"); got.Error == "" {
		t.Errorf("missing program: %+v", got)
	}
}

func TestCanonicalStaysInRoot(t *testing.T) {
	root := t.TempDir()
	r := &Resolver{Root: root}
	symlink(t, root, "/etc/target", "/a/abs")
	symlink(t, root, "../../../../../../etc/target", "/a/rel")
	symlink(t, root, "loop2", "/a/loop1")
	symlink(t, root, "loop1", "/a/loop2")
	writeFile(t, root, "/etc/target", nil)
	for _, p := range []string{"/a/abs", "/a/rel"} {
		if got, err := r.canonical(p); err != nil || got != "/etc/target" {
			t.Errorf("%s: %q %v", p, got, err)
		}
	}
	if _, err := r.canonical("/a/loop1"); err == nil {
		t.Error("symlink loop accepted")
	}
	if _, err := r.canonical("relative"); err == nil {
		t.Error("relative path accepted")
	}
}

func TestMalformedELF(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/bad", append([]byte(elf.ELFMAG), bytes.Repeat([]byte{0xff}, 100)...))
	r := NewResolver(root)
	if got := r.Program("/bad"); got.Error == "" {
		t.Errorf("malformed ELF accepted: %+v", got)
	}
}
