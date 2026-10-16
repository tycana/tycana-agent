// Package history normalizes the host's package transaction logs: dpkg.log
// for what dpkg actually did, and apt's history.log for who asked and why.
// It reads rotated and gzipped logs, never writes, and never runs anything
// (ADR 0017). dnf's history.sqlite joins this package with the rpm work.
package history

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
)

// maxLogBytes bounds one log file after decompression. Real logs are a few
// MB; the bound stops a corrupt or hostile .gz from exhausting memory.
const maxLogBytes = 64 << 20

// rotated returns base and its logrotate siblings (base.1, base.2.gz, ...)
// that exist in fsys, oldest first.
func rotated(fsys fs.FS, base string) ([]string, error) {
	matches, err := fs.Glob(fsys, base+".*")
	if err != nil {
		return nil, err
	}
	type file struct {
		name string
		n    int
	}
	var files []file
	for _, m := range matches {
		suffix := strings.TrimSuffix(strings.TrimPrefix(m, base+"."), ".gz")
		n, err := strconv.Atoi(suffix)
		if err != nil || n < 1 {
			continue
		}
		files = append(files, file{m, n})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].n > files[j].n })
	out := make([]string, 0, len(files)+1)
	for _, f := range files {
		out = append(out, f.name)
	}
	if _, err := fs.Stat(fsys, base); err == nil {
		out = append(out, base)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return out, nil
}

// readLog returns a log file's contents, decompressing .gz files.
func readLog(fsys fs.FS, name string) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	var r io.Reader = f
	if path.Ext(name) == ".gz" {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		defer func() { _ = zr.Close() }()
		r = zr
	}
	data, err := io.ReadAll(io.LimitReader(r, maxLogBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(data) > maxLogBytes {
		return nil, fmt.Errorf("%s: more than %d bytes, refusing", name, maxLogBytes)
	}
	return data, nil
}

// readAll concatenates base and its rotations, oldest first, and reports
// which files were read.
func readAll(fsys fs.FS, base string) ([]byte, []string, error) {
	names, err := rotated(fsys, base)
	if err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	for _, n := range names {
		data, err := readLog(fsys, n)
		if err != nil {
			return nil, nil, err
		}
		buf.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes(), names, nil
}
