package dpkg

import (
	"bufio"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// File is one path an installed package owns, from dpkg's file lists.
// dpkg records no file modes; a caller that needs them stats the path.
type File struct {
	// Package is the owner's name, without an architecture qualifier.
	Package string
	// Path is the absolute path as dpkg records it (before the /usr
	// merge, often /lib or /bin for files now under /usr).
	Path string
}

// WalkFiles calls fn for every path in admindir/info/*.list, one package
// at a time in name order. The lists hold directories too. fn's error
// stops the walk.
func WalkFiles(fsys fs.FS, admindir string, fn func(File) error) error {
	lists, err := fs.Glob(fsys, path.Join(admindir, "info", "*.list"))
	if err != nil {
		return err
	}
	if len(lists) == 0 {
		return fmt.Errorf("dpkg: no file lists in %s/info", admindir)
	}
	sort.Strings(lists)
	for _, l := range lists {
		name, _, _ := strings.Cut(strings.TrimSuffix(path.Base(l), ".list"), ":")
		if err := walkList(fsys, l, name, fn); err != nil {
			return err
		}
	}
	return nil
}

func walkList(fsys fs.FS, list, name string, fn func(File) error) error {
	f, err := fsys.Open(list)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		p := sc.Text()
		if !strings.HasPrefix(p, "/") || p == "/." {
			continue
		}
		if err := fn(File{Package: name, Path: p}); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("dpkg: %s: %w", list, err)
	}
	return nil
}
