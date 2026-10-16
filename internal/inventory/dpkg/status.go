// Package dpkg reads the dpkg package database without running dpkg.
//
// It parses <admindir>/status and replays the <admindir>/updates journal the
// way dpkg-query does when it opens the database read-only, so the result
// agrees with "dpkg-query -W" and "dpkg -l" on a live host. It never writes,
// never takes the dpkg lock, and never executes anything (ADR 0017).
package dpkg

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// DefaultAdminDir is dpkg's database directory, relative to the root of the
// filesystem passed to ReadDatabase.
const DefaultAdminDir = "var/lib/dpkg"

// maxStanzaFile bounds a single database file. A real status file is a few
// MB; anything far larger is not a dpkg database and is refused rather than
// read into memory.
const maxStanzaFile = 256 << 20

// Package is one entry of the dpkg database.
type Package struct {
	Name         string
	Architecture string
	MultiArch    string // "same", "foreign", "allowed", or ""
	Version      Version
	// SourceName and SourceVersion follow dpkg-query's ${source:Package}
	// and ${source:Version}: they fall back to the binary package's own
	// name and version when the Source field omits them.
	SourceName    string
	SourceVersion Version
	Want          string // unknown, install, hold, deinstall, purge
	Flag          string // ok, reinstreq
	State         string // not-installed, config-files, half-installed, unpacked, half-configured, triggers-awaited, triggers-pending, installed
	Summary       string // first line of Description
	InstalledSize string // as recorded, in KiB
}

// Database is the parsed dpkg database.
type Database struct {
	// NativeArch is the architecture of the installed dpkg package, which
	// is the host's native dpkg architecture.
	NativeArch string
	// Packages holds every entry whose state is not "not-installed", in
	// dpkg-query's order. That is exactly the set "dpkg-query -W" and
	// "dpkg -l" print when given no package patterns.
	Packages []Package
	// UpdatesApplied counts journal files replayed from <admindir>/updates.
	// Non-zero means dpkg was interrupted or is running right now.
	UpdatesApplied int
}

// ReadDatabase reads the dpkg database at admindir inside fsys.
func ReadDatabase(fsys fs.FS, admindir string) (*Database, error) {
	byKey := map[pkgKey]Package{}
	order := 0
	seen := map[pkgKey]int{}
	add := func(p Package) {
		k := pkgKey{p.Name, p.Architecture}
		if _, ok := seen[k]; !ok {
			seen[k] = order
			order++
		}
		byKey[k] = p
	}

	statusPath := path.Join(admindir, "status")
	if err := readStanzaFile(fsys, statusPath, add); err != nil {
		return nil, err
	}
	updates, err := updateFiles(fsys, path.Join(admindir, "updates"))
	if err != nil {
		return nil, err
	}
	for _, u := range updates {
		if err := readStanzaFile(fsys, u, add); err != nil {
			return nil, err
		}
	}

	db := &Database{UpdatesApplied: len(updates)}
	for _, p := range byKey {
		if p.Name == "dpkg" && p.State != "not-installed" {
			db.NativeArch = p.Architecture
		}
	}
	for _, p := range byKey {
		if p.State == "not-installed" {
			continue
		}
		db.Packages = append(db.Packages, p)
	}
	sort.Slice(db.Packages, func(i, j int) bool {
		return lessNonambig(db.Packages[i], db.Packages[j], db.NativeArch)
	})
	return db, nil
}

type pkgKey struct{ name, arch string }

// updateFiles lists the journal files dpkg would replay: entries of the
// updates directory whose names are all digits, in name order. A missing
// directory is normal on hosts that never ran dpkg.
func updateFiles(fsys fs.FS, dir string) ([]string, error) {
	ents, err := fs.ReadDir(fsys, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if n == "" || strings.Trim(n, "0123456789") != "" || e.IsDir() {
			continue
		}
		out = append(out, path.Join(dir, n))
	}
	sort.Strings(out)
	return out, nil
}

func readStanzaFile(fsys fs.FS, name string, add func(Package)) error {
	f, err := fsys.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only; a close error cannot lose data
	data, err := io.ReadAll(io.LimitReader(f, maxStanzaFile+1))
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if len(data) > maxStanzaFile {
		return fmt.Errorf("%s: larger than %d bytes, refusing", name, maxStanzaFile)
	}
	return parseStanzas(data, func(line int, fields map[string]string) error {
		p, err := packageFromFields(fields)
		if err != nil {
			return fmt.Errorf("%s: stanza ending at line %d: %w", name, line, err)
		}
		add(p)
		return nil
	})
}

// parseStanzas splits deb822 data into stanzas of field name (lower-cased)
// to value. Like dpkg (lib/dpkg/parse.c), it strips blanks after the colon
// and whitespace at the very end of a value, but keeps continuation lines
// verbatim, so trailing blanks on the first line of a multi-line field
// survive. dpkg-query's ${binary:Summary} shows them, and so must we.
func parseStanzas(data []byte, emit func(line int, fields map[string]string) error) error {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), maxStanzaFile)
	fields := map[string]string{}
	var last string
	lineNo := 0
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		for k, v := range fields {
			fields[k] = strings.TrimRight(v, " \t\n\r\v\f")
		}
		err := emit(lineNo, fields)
		fields = map[string]string{}
		last = ""
		return err
	}
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		switch {
		case line == "":
			if err := flush(); err != nil {
				return err
			}
		case line[0] == ' ' || line[0] == '\t':
			if last == "" {
				return fmt.Errorf("line %d: continuation line outside a field", lineNo)
			}
			fields[last] += "\n" + line
		default:
			name, value, ok := strings.Cut(line, ":")
			if !ok || name == "" {
				return fmt.Errorf("line %d: not a field", lineNo)
			}
			last = strings.ToLower(name)
			if _, dup := fields[last]; dup {
				return fmt.Errorf("line %d: duplicate field %q", lineNo, name)
			}
			fields[last] = strings.TrimLeft(value, " \t")
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return flush()
}

var (
	wants  = set("unknown", "install", "hold", "deinstall", "purge")
	flags  = set("ok", "reinstreq")
	states = set("not-installed", "config-files", "half-installed", "unpacked",
		"half-configured", "triggers-awaited", "triggers-pending", "installed")
)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func packageFromFields(f map[string]string) (Package, error) {
	p := Package{
		Name:          f["package"],
		Architecture:  f["architecture"],
		MultiArch:     f["multi-arch"],
		InstalledSize: f["installed-size"],
	}
	if p.Name == "" {
		return p, errors.New("missing Package field")
	}
	st := strings.Fields(f["status"])
	if len(st) != 3 {
		return p, fmt.Errorf("package %s: malformed Status %q", p.Name, f["status"])
	}
	p.Want, p.Flag, p.State = st[0], st[1], st[2]
	if !wants[p.Want] || !flags[p.Flag] || !states[p.State] {
		return p, fmt.Errorf("package %s: unknown Status %q", p.Name, f["status"])
	}
	if v, ok := f["version"]; ok && v != "" {
		ver, err := ParseVersion(v)
		if err != nil {
			return p, fmt.Errorf("package %s: %w", p.Name, err)
		}
		p.Version = ver
	}
	p.SourceName, p.SourceVersion = p.Name, p.Version
	if src := f["source"]; src != "" {
		name, rest, _ := strings.Cut(src, " ")
		p.SourceName = name
		if rest = strings.TrimSpace(rest); strings.HasPrefix(rest, "(") && strings.HasSuffix(rest, ")") {
			ver, err := ParseVersion(rest[1 : len(rest)-1])
			if err != nil {
				return p, fmt.Errorf("package %s: Source version: %w", p.Name, err)
			}
			p.SourceVersion = ver
		}
	}
	desc := f["description"]
	p.Summary, _, _ = strings.Cut(desc, "\n")
	return p, nil
}

// needsArch reports whether dpkg shows this package as name:arch in
// ${binary:Package} (lib/dpkg/pkg-show.c, pnaw_nonambig): always for
// Multi-Arch: same, otherwise only for foreign architectures.
func needsArch(p Package, native string) bool {
	if p.Architecture == "" {
		return false
	}
	if p.MultiArch == "same" {
		return true
	}
	return p.Architecture != native && p.Architecture != "all"
}

// BinaryPackage returns the name as dpkg-query prints ${binary:Package}.
func (db *Database) BinaryPackage(p Package) string {
	if needsArch(p, db.NativeArch) {
		return p.Name + ":" + p.Architecture
	}
	return p.Name
}

// lessNonambig is dpkg's pkg_sorter_by_nonambig_name_arch: by name, then
// unqualified entries before arch-qualified ones, then by arch name.
func lessNonambig(a, b Package, native string) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Architecture == b.Architecture {
		return false
	}
	// dpkg puts unqualified names first; ties (both or neither qualified)
	// go by architecture name, which keeps this a strict weak order.
	if qa, qb := needsArch(a, native), needsArch(b, native); qa != qb {
		return qb
	}
	return a.Architecture < b.Architecture
}

// StatusAbbrev returns dpkg-query's ${db:Status-Abbrev}: want, state, and
// error flag as one letter each, the flag being a space when it is "ok".
func (p Package) StatusAbbrev() string {
	return string([]byte{wantAbbrev[p.Want], stateAbbrev[p.State], flagAbbrev[p.Flag]})
}

var (
	wantAbbrev  = map[string]byte{"unknown": 'u', "install": 'i', "hold": 'h', "deinstall": 'r', "purge": 'p'}
	flagAbbrev  = map[string]byte{"ok": ' ', "reinstreq": 'R'}
	stateAbbrev = map[string]byte{
		"not-installed": 'n', "config-files": 'c', "half-installed": 'H', "unpacked": 'U',
		"half-configured": 'F', "triggers-awaited": 'W', "triggers-pending": 't', "installed": 'i',
	}
)
