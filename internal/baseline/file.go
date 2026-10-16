package baseline

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// FileCheck is ComplianceAsCode's file_permissions, file_owner,
// file_groupowner, and file_existence templates.
//
// The objects are OVAL file_objects: Paths are files, or directories when
// they end in "/". A directory with FileRegex selects the entries whose
// name matches (unanchored, as OVAL "pattern match"), in the directory
// and, with Recursive, in every directory below it on the same file
// system. Symlinks are never selected.
//
// Mode, Owner, and Group pass when no selected file violates them, so a
// missing file passes (OVAL check_existence none_exist on the violating
// files). Exists passes when the file exists, or when it does not and
// Exists is false.
type FileCheck struct {
	Paths     []string `yaml:"paths"`
	FileRegex string   `yaml:"file_regex,omitempty"`
	Recursive bool     `yaml:"recursive,omitempty"`
	// Exclude lists name patterns that are not selected (ComplianceAsCode
	// excluded_files: "*" is any text, the rest is a regular expression
	// matched against the whole name).
	Exclude []string `yaml:"exclude,omitempty"`

	// Mode is the most permissive mode allowed (octal, for example
	// "0644"): a selected file fails when it has a bit Mode does not have.
	// With ExactMode the file must have Mode exactly.
	Mode      string `yaml:"mode,omitempty"`
	ExactMode bool   `yaml:"exact_mode,omitempty"`
	// Owner and Group list the allowed owners: one numeric id, or names.
	// Owner names resolve through /etc/passwd; group names through
	// /etc/group and /usr/lib/group, as the OVAL does.
	Owner []string `yaml:"owner,omitempty"`
	Group []string `yaml:"group,omitempty"`
	// Exists, when set, is the existence test alone.
	Exists *bool `yaml:"exists,omitempty"`
}

func (f *FileCheck) validate() error {
	if len(f.Paths) == 0 {
		return errors.New("file: paths is empty")
	}
	for _, p := range f.Paths {
		if p != "/" && (!path.IsAbs(p) || path.Clean(p) != strings.TrimSuffix(p, "/")) {
			return fmt.Errorf("file: path %q is not a clean absolute path", p)
		}
	}
	n := 0
	for _, set := range []bool{f.Mode != "", len(f.Owner) > 0, len(f.Group) > 0, f.Exists != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("file: has %d of mode, owner, group, exists; want exactly 1", n)
	}
	if f.Mode != "" {
		if _, err := strconv.ParseUint(f.Mode, 8, 32); err != nil {
			return fmt.Errorf("file: mode %q is not octal", f.Mode)
		}
	}
	if f.FileRegex != "" {
		if _, err := regexp.Compile(f.FileRegex); err != nil {
			return fmt.Errorf("file: file_regex: %w", err)
		}
	}
	if f.Exists != nil && (f.FileRegex != "" || strings.HasSuffix(f.Paths[0], "/") && len(f.Paths[0]) > 1) {
		return errors.New("file: exists takes plain file paths")
	}
	return nil
}

// selected is one file the object selects.
type selected struct {
	path string
	meta Meta
}

func (f *FileCheck) eval(h *Host) (bool, string, error) {
	if f.Exists != nil {
		return f.evalExists(h)
	}
	files, incomplete, err := f.collect(h)
	if err != nil {
		return false, "", err
	}
	var bad []string
	var unsure []string
	switch {
	case f.Mode != "":
		want, _ := strconv.ParseUint(f.Mode, 8, 32)
		for _, s := range files {
			if f.ExactMode && uint64(s.meta.Mode) != want || !f.ExactMode && uint64(s.meta.Mode)&^want != 0 {
				bad = append(bad, fmt.Sprintf("%s is %04o", s.path, s.meta.Mode))
			}
		}
	case len(f.Owner) > 0:
		ids, err := resolveIDs(h, f.Owner, "/etc/passwd", "")
		if err != nil {
			return false, "", err
		}
		for _, s := range files {
			switch {
			case slices.Contains(ids, s.meta.UID):
			case h.UserNS && s.meta.UID == h.OverflowUID:
				unsure = append(unsure, s.path)
			default:
				bad = append(bad, fmt.Sprintf("%s is owned by uid %d", s.path, s.meta.UID))
			}
		}
	default:
		ids, err := resolveIDs(h, f.Group, "/etc/group", "/usr/lib/group")
		if err != nil {
			return false, "", err
		}
		for _, s := range files {
			switch {
			case slices.Contains(ids, s.meta.GID):
			case h.UserNS && s.meta.GID == h.OverflowGID:
				unsure = append(unsure, s.path)
			default:
				bad = append(bad, fmt.Sprintf("%s has group gid %d", s.path, s.meta.GID))
			}
		}
	}
	if len(bad) > 0 {
		return false, summarize(bad), nil
	}
	if len(unsure) > 0 {
		return false, "", unknownf("the agent's user namespace cannot map the owner of %s", summarize(unsure))
	}
	if incomplete != "" {
		return false, "", unknownf("no violation found, but %s", incomplete)
	}
	if len(files) == 0 {
		return true, "no matching file exists", nil
	}
	return true, fmt.Sprintf("%d file(s) checked", len(files)), nil
}

func (f *FileCheck) evalExists(h *Host) (bool, string, error) {
	p := f.Paths[0]
	_, err := h.Stat(p)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, "", err
	}
	state := "does not exist"
	if exists {
		state = "exists"
	}
	return exists == *f.Exists, p + " " + state, nil
}

// collect returns the files the object selects. incomplete is non-empty
// when part of the tree could not be read.
func (f *FileCheck) collect(h *Host) ([]selected, string, error) {
	var re *regexp.Regexp
	if f.FileRegex != "" {
		re = regexp.MustCompile(f.FileRegex)
	}
	var excl []*regexp.Regexp
	for _, e := range f.Exclude {
		x, err := regexp.Compile("^" + strings.ReplaceAll(e, "*", ".*") + "$")
		if err != nil {
			return nil, "", contentf("exclude %q: %v", e, err)
		}
		excl = append(excl, x)
	}
	var out []selected
	var unread []string
	for _, p := range f.Paths {
		isDir := strings.HasSuffix(p, "/") && p != "/"
		if !isDir {
			m, err := h.Stat(p)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				continue
			case err != nil:
				return nil, "", err
			case m.Type != "symlink":
				out = append(out, selected{p, m})
			}
			continue
		}
		dir := strings.TrimSuffix(p, "/")
		if re == nil {
			// The directory itself.
			m, err := h.Stat(dir)
			switch {
			case errors.Is(err, fs.ErrNotExist):
			case err != nil:
				return nil, "", err
			case m.Type != "symlink":
				out = append(out, selected{dir, m})
			}
			continue
		}
		f.walk(h, dir, re, excl, &out, &unread)
	}
	if len(unread) > 0 {
		return out, "these directories are not readable without privilege: " + summarize(unread), nil
	}
	return out, "", nil
}

func (f *FileCheck) walk(h *Host, dir string, re *regexp.Regexp, excl []*regexp.Regexp, out *[]selected, unread *[]string) {
	ents, err := h.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		*unread = append(*unread, dir)
		return
	}
	for _, e := range ents {
		p := path.Join(dir, e.Name())
		m, err := h.Stat(p)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				*unread = append(*unread, p)
			}
			continue
		}
		if m.Type == "symlink" {
			continue
		}
		// OpenSCAP selects only non-directories when a name pattern is
		// given; directories are walked, not matched.
		if m.Type != "dir" && re.MatchString(e.Name()) && !slices.ContainsFunc(excl, func(x *regexp.Regexp) bool { return x.MatchString(e.Name()) }) {
			*out = append(*out, selected{p, m})
		}
		if f.Recursive && m.Type == "dir" {
			f.walk(h, p, re, excl, out, unread)
		}
	}
}

// resolveIDs turns owner names into ids. A numeric entry is the id. A
// name is looked up in the files, as OVAL's textfilecontent pattern
// "^NAME:\w+:(\w+):" does; names that resolve nowhere are dropped, and
// none resolving is a content error.
func resolveIDs(h *Host, names []string, primary, secondary string) ([]uint32, error) {
	var ids []uint32
	var tables [][]byte
	for _, f := range []string{primary, secondary} {
		if f == "" {
			continue
		}
		b, err := h.ReadFile(f)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		tables = append(tables, b)
	}
	for _, n := range names {
		if id, err := strconv.ParseUint(n, 10, 32); err == nil {
			ids = append(ids, uint32(id))
			continue
		}
		re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(n) + `:\w+:(\w+):`)
		for _, t := range tables {
			if m := re.FindSubmatch(t); m != nil {
				if id, err := strconv.ParseUint(string(m[1]), 10, 32); err == nil {
					ids = append(ids, uint32(id))
				}
			}
		}
	}
	if len(ids) == 0 {
		return nil, contentf("no id found for %s in %s", strings.Join(names, ", "), primary)
	}
	return ids, nil
}

// summarize lists at most five items.
func summarize(items []string) string {
	if len(items) <= 5 {
		return strings.Join(items, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(items[:5], "; "), len(items)-5)
}
