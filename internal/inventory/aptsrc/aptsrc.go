// Package aptsrc finds, for each installed package of a dpkg host, the
// apt lists that carry it (tycana-hq ADR 0034): the repository a package
// came from, so that a control plane examines only packages from
// repositories with vendor security data, and names the others.
//
// It reads apt's downloaded lists in /var/lib/apt/lists (the Packages
// file of each repository, suite, component, and architecture, and the
// suite's InRelease or Release file), as "apt-cache policy" does, without
// running apt. The lists are world-readable and change only when apt
// updates them. Compressed lists (Acquire::GzipIndexes) are read when
// gzip; other compressions are named in the notes.
package aptsrc

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
)

// DefaultDir is apt's list directory, relative to the root.
const DefaultDir = "var/lib/apt/lists"

// Source is one apt list: a repository's suite, component, and
// architecture, with the Release fields of its suite.
type Source struct {
	// Site is the list file name up to "_dists_": the URI with "/"
	// replaced by "_" ("archive.ubuntu.com_ubuntu").
	Site      string `json:"site"`
	Dist      string `json:"dist,omitempty"`
	Component string `json:"component,omitempty"`
	// Arch is the list's architecture; empty for a flat repository.
	Arch string `json:"arch,omitempty"`
	// Origin, Label, Suite, and Codename are from the suite's InRelease
	// or Release file; empty when it has none.
	Origin   string `json:"origin,omitempty"`
	Label    string `json:"label,omitempty"`
	Suite    string `json:"suite,omitempty"`
	Codename string `json:"codename,omitempty"`
}

// Want is one installed package.
type Want struct {
	Name, Arch, Version, Source string
}

// Result says where each wanted package is.
type Result struct {
	Sources []Source
	// Exact[i] are the indexes of the sources that carry Want i in its
	// installed version; SourceName[i], when Exact[i] is empty, those
	// that carry its source package in another version.
	Exact      [][]int
	SourceName [][]int
	// Notes name lists that were not read.
	Notes []string
}

// maxLine bounds one line of a list (long descriptions).
const maxLine = 4 << 20

// Read reads the lists in dir for the architectures of the wanted
// packages (and "all").
func Read(fsys fs.FS, dir string, want []Want) (*Result, error) {
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	archs := map[string]bool{"all": true}
	byKey := map[[3]string][]int{}
	bySource := map[string][]int{}
	for i, w := range want {
		archs[w.Arch] = true
		byKey[[3]string{w.Name, w.Arch, w.Version}] = append(byKey[[3]string{w.Name, w.Arch, w.Version}], i)
		src := w.Source
		if src == "" {
			src = w.Name
		}
		bySource[src] = append(bySource[src], i)
	}
	r := &Result{Exact: make([][]int, len(want)), SourceName: make([][]int, len(want))}
	nameIn := make([][]int, len(want))
	release := map[string]Source{}
	for _, e := range ents {
		name := e.Name()
		base, comp := name, ""
		switch {
		case strings.HasSuffix(name, "_Packages"):
		case strings.HasSuffix(name, "_Packages.gz"):
			base, comp = strings.TrimSuffix(name, ".gz"), "gz"
		case strings.Contains(name, "_Packages."):
			r.Notes = append(r.Notes, "list not read (compression): "+name)
			continue
		default:
			continue
		}
		src, ok := parseName(base)
		if !ok || (src.Dist != "" && !archs[src.Arch]) {
			continue
		}
		key := src.Site + "\x00" + src.Dist
		rel, seen := release[key]
		if !seen {
			rel = readRelease(fsys, dir, src)
			release[key] = rel
		}
		src.Origin, src.Label, src.Suite, src.Codename = rel.Origin, rel.Label, rel.Suite, rel.Codename
		idx := len(r.Sources)
		r.Sources = append(r.Sources, src)
		if err := scan(fsys, path.Join(dir, name), comp, func(pkg, arch, ver, source string) {
			for _, i := range byKey[[3]string{pkg, arch, ver}] {
				r.Exact[i] = addIdx(r.Exact[i], idx)
			}
			if source == "" {
				source = pkg
			}
			for _, i := range bySource[source] {
				nameIn[i] = addIdx(nameIn[i], idx)
			}
		}); err != nil {
			r.Notes = append(r.Notes, fmt.Sprintf("list not read: %s: %v", name, err))
		}
	}
	for i := range want {
		if len(r.Exact[i]) == 0 {
			r.SourceName[i] = nameIn[i]
		}
	}
	return r, nil
}

func addIdx(list []int, i int) []int {
	if n := len(list); n > 0 && list[n-1] == i {
		return list
	}
	return append(list, i)
}

// parseName splits a list file name,
// "<site>_dists_<dist>_<component>_binary-<arch>_Packages"; a flat
// repository ("deb URI ./") has "<site>_Packages" and no dist.
func parseName(base string) (Source, bool) {
	s := strings.TrimSuffix(base, "_Packages")
	site, rest, ok := strings.Cut(s, "_dists_")
	if !ok {
		return Source{Site: s}, s != ""
	}
	i := strings.LastIndex(rest, "_binary-")
	if i < 0 {
		return Source{}, false
	}
	arch := rest[i+len("_binary-"):]
	dist, comp, _ := strings.Cut(rest[:i], "_")
	return Source{Site: site, Dist: dist, Component: strings.ReplaceAll(comp, "_", "/"), Arch: arch}, dist != "" && arch != ""
}

// readRelease reads Origin, Label, Suite, and Codename of a suite.
func readRelease(fsys fs.FS, dir string, s Source) Source {
	prefix := s.Site + "_"
	if s.Dist != "" {
		prefix = s.Site + "_dists_" + s.Dist + "_"
	}
	for _, n := range []string{"InRelease", "Release"} {
		f, err := fsys.Open(path.Join(dir, prefix+n))
		if err != nil {
			continue
		}
		var out Source
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), maxLine)
		for sc.Scan() {
			l := sc.Text()
			if l == "" && out.Origin+out.Suite != "" {
				break // the end of the first stanza; the rest is checksums
			}
			k, v, ok := strings.Cut(l, ": ")
			if !ok {
				continue
			}
			switch k {
			case "Origin":
				out.Origin = v
			case "Label":
				out.Label = v
			case "Suite":
				out.Suite = v
			case "Codename":
				out.Codename = v
			}
		}
		_ = f.Close()
		return out
	}
	return Source{}
}

// scan calls fn for each stanza of a Packages list.
func scan(fsys fs.FS, name, comp string, fn func(pkg, arch, ver, source string)) error {
	f, err := fsys.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var rd io.Reader = f
	if comp == "gz" {
		z, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer func() { _ = z.Close() }()
		rd = z
	}
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 256<<10), maxLine)
	var pkg, arch, ver, source string
	flush := func() {
		if pkg != "" && ver != "" {
			fn(pkg, arch, ver, source)
		}
		pkg, arch, ver, source = "", "", "", ""
	}
	for sc.Scan() {
		l := sc.Bytes()
		if len(l) == 0 {
			flush()
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			continue
		}
		switch {
		case hasPrefix(l, "Package: "):
			pkg = string(l[len("Package: "):])
		case hasPrefix(l, "Architecture: "):
			arch = string(l[len("Architecture: "):])
		case hasPrefix(l, "Version: "):
			ver = string(l[len("Version: "):])
		case hasPrefix(l, "Source: "):
			// "Source: linux-signed (6.8.0-45.45)": the name only.
			source, _, _ = strings.Cut(string(l[len("Source: "):]), " ")
		}
	}
	flush()
	return sc.Err()
}

func hasPrefix(b []byte, p string) bool { return len(b) >= len(p) && string(b[:len(p)]) == p }
