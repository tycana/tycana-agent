// Package osrelease identifies the distribution from os-release(5).
package osrelease

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

// Paths are probed in this order, relative to the filesystem root, as
// os-release(5) specifies.
var Paths = []string{"etc/os-release", "usr/lib/os-release"}

const maxSize = 64 << 10

// Info is the subset of os-release fields the agent reports.
type Info struct {
	ID              string   `json:"id"`
	IDLike          []string `json:"id_like,omitempty"`
	Name            string   `json:"name,omitempty"`
	PrettyName      string   `json:"pretty_name,omitempty"`
	VersionID       string   `json:"version_id,omitempty"`
	Version         string   `json:"version,omitempty"`
	VersionCodename string   `json:"version_codename,omitempty"`
	// Source is the file the fields came from.
	Source string `json:"source"`
}

// Read returns the first os-release file found in fsys.
func Read(fsys fs.FS) (Info, error) {
	for _, p := range Paths {
		f, err := fsys.Open(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return Info{}, err
		}
		data, err := io.ReadAll(io.LimitReader(f, maxSize))
		_ = f.Close() // read-only
		if err != nil {
			return Info{}, fmt.Errorf("%s: %w", p, err)
		}
		kv, err := Parse(data)
		if err != nil {
			return Info{}, fmt.Errorf("%s: %w", p, err)
		}
		info := Info{
			ID:              kv["ID"],
			IDLike:          strings.Fields(kv["ID_LIKE"]),
			Name:            kv["NAME"],
			PrettyName:      kv["PRETTY_NAME"],
			VersionID:       kv["VERSION_ID"],
			Version:         kv["VERSION"],
			VersionCodename: kv["VERSION_CODENAME"],
			Source:          "/" + p,
		}
		if info.ID == "" {
			info.ID = "linux" // os-release(5) default
		}
		return info, nil
	}
	return Info{}, fmt.Errorf("no os-release file at %v: %w", Paths, fs.ErrNotExist)
}

// Parse reads os-release assignments: KEY=value, where value may be
// single- or double-quoted and uses shell-style backslash escapes inside
// double quotes. Comments and blank lines are skipped. Lines that are not
// assignments are ignored, as os-release(5) tells readers to do.
func Parse(data []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok || !validKey(key) {
			continue
		}
		val, err := unquote(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		out[key] = val
	}
	return out, sc.Err()
}

func validKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		ok := c == '_' || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9' && i > 0)
		if !ok {
			return false
		}
	}
	return true
}

func unquote(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	switch q := s[0]; q {
	case '\'':
		if len(s) < 2 || s[len(s)-1] != '\'' {
			return "", errors.New("unterminated single quote")
		}
		return s[1 : len(s)-1], nil
	case '"':
		if len(s) < 2 || s[len(s)-1] != '"' {
			return "", errors.New("unterminated double quote")
		}
		inner := s[1 : len(s)-1]
		var b strings.Builder
		for i := 0; i < len(inner); i++ {
			c := inner[i]
			if c == '\\' && i+1 < len(inner) && strings.IndexByte("\\$\"`", inner[i+1]) >= 0 {
				i++
				c = inner[i]
			}
			b.WriteByte(c)
		}
		return b.String(), nil
	}
	return s, nil
}
