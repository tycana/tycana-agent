// Package repos reads which dnf repositories a host has configured and
// which of them are enabled, from the .repo files in /etc/yum.repos.d.
// A control plane needs this to apply a vendor's advisories the way dnf
// applies them: dnf reads the advisories of enabled repositories only.
//
// Only the section names (repository IDs) and the "enabled" key are
// read. Nothing is written or executed (ADR 0017).
package repos

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// Dir is dnf's default reposdir, relative to the root.
const Dir = "etc/yum.repos.d"

const (
	maxFiles = 256
	maxSize  = 1 << 20
)

// Repo is one configured repository.
type Repo struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	// File is the .repo file, relative to the reposdir.
	File string `json:"file"`
}

// Read returns the repositories in Dir, sorted by ID. A host without the
// directory has none. A file that is too large or a section without a
// name is an error; dnf would refuse it too.
func Read(fsys fs.FS) ([]Repo, error) {
	entries, err := fs.ReadDir(fsys, Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Repo
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".repo") {
			continue
		}
		if n++; n > maxFiles {
			return nil, fmt.Errorf("%s: more than %d .repo files", Dir, maxFiles)
		}
		p := path.Join(Dir, e.Name())
		st, err := fs.Stat(fsys, p)
		if err != nil {
			return nil, err
		}
		if st.Size() > maxSize {
			return nil, fmt.Errorf("%s: larger than %d bytes", p, maxSize)
		}
		raw, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, err
		}
		rs, err := parse(raw, e.Name())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		out = append(out, rs...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// parse reads the sections of one .repo file. dnf enables a repository
// when the key is absent.
func parse(raw []byte, file string) ([]Repo, error) {
	var out []Repo
	cur := -1
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64<<10), maxSize)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
			continue
		case line[0] == '[':
			end := strings.IndexByte(line, ']')
			id := ""
			if end > 0 {
				id = strings.TrimSpace(line[1:end])
			}
			if id == "" {
				return nil, fmt.Errorf("section without a name: %q", line)
			}
			out = append(out, Repo{ID: id, Enabled: true, File: file})
			cur = len(out) - 1
		case cur >= 0:
			k, v, ok := strings.Cut(line, "=")
			if !ok || strings.TrimSpace(k) != "enabled" {
				continue
			}
			if b, ok := boolean(strings.TrimSpace(v)); ok {
				out[cur].Enabled = b
			}
		}
	}
	return out, sc.Err()
}

// boolean accepts the words libdnf accepts.
func boolean(s string) (bool, bool) {
	switch strings.ToLower(s) {
	case "1", "yes", "true", "on":
		return true, true
	case "0", "no", "false", "off":
		return false, true
	}
	return false, false
}
