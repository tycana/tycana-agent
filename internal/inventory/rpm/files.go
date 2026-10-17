package rpm

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"path/filepath"

	"tycana.ai/agent/internal/sqlitero"
)

// File tags (rpmtag.h).
const (
	tagFileDigests    = 1035 // FILEDIGESTS, string array
	tagDirIndexes     = 1116 // DIRINDEXES, int32 array
	tagBaseNames      = 1117 // BASENAMES, string array
	tagDirNames       = 1118 // DIRNAMES, string array
	tagFileDigestAlgo = 5011 // FILEDIGESTALGO, int32; absent means MD5
)

// Digest algorithms (PGPHASHALGO_*).
var digestAlgos = map[uint64]string{1: "md5", 2: "sha1", 8: "sha256", 9: "sha384", 10: "sha512", 11: "sha224"}

// FileDigest is what the database records for one installed file.
type FileDigest struct {
	// Package is the owner's NAME-VERSION-RELEASE.ARCH.
	Package string
	// Algorithm is md5, sha1, sha256, sha384, sha512, or sha224.
	Algorithm string
	// Digest is lower-case hex; "" for a file without content (a
	// directory or a ghost file).
	Digest string
}

// ErrNotOwned is returned when no package owns the file.
var ErrNotOwned = errors.New("rpm: no package owns the file")

// LookupFile returns the digest the database in dir under root records
// for the absolute path file. It reads every header, as "rpm -qf" does
// without an index.
func LookupFile(root, dir, file string) (FileDigest, error) {
	db := filepath.Join(root, filepath.FromSlash(dir), DBFile)
	d, err := sqlitero.Open(db)
	if err != nil {
		return FileDigest{}, err
	}
	defer func() { _ = d.Close() }() // read-only
	rows, err := d.QueryContext(context.Background(), "SELECT hnum, blob FROM Packages ORDER BY hnum")
	if err != nil {
		return FileDigest{}, fmt.Errorf("%s: %w", db, err)
	}
	defer func() { _ = rows.Close() }()
	dirName, base := path.Dir(file)+"/", path.Base(file)
	for rows.Next() {
		var hnum int64
		var blob []byte
		if err := rows.Scan(&hnum, &blob); err != nil {
			return FileDigest{}, fmt.Errorf("%s: %w", db, err)
		}
		h, err := parseHeader(blob)
		if err != nil {
			return FileDigest{}, fmt.Errorf("%s: header %d: %w", db, hnum, err)
		}
		if fd, ok := h.file(dirName, base); ok {
			return fd, nil
		}
	}
	if err := rows.Err(); err != nil {
		return FileDigest{}, fmt.Errorf("%s: %w", db, err)
	}
	return FileDigest{}, ErrNotOwned
}

func (h header) file(dirName, base string) (FileDigest, bool) {
	bases := h.strs(tagBaseNames)
	idx := -1
	for i, b := range bases {
		if b == base {
			dirs, ix := h.strs(tagDirNames), h.int32s(tagDirIndexes)
			if i < len(ix) && int(ix[i]) < len(dirs) && dirs[ix[i]] == dirName {
				idx = i
				break
			}
		}
	}
	if idx < 0 {
		return FileDigest{}, false
	}
	p := fromHeader(0, h)
	fd := FileDigest{Package: p.Name + "-" + p.EVR.Version + "-" + p.EVR.Release + "." + p.Arch, Algorithm: "md5"}
	if a, ok := h.num(tagFileDigestAlgo); ok {
		fd.Algorithm = digestAlgos[a]
	}
	if ds := h.strs(tagFileDigests); idx < len(ds) {
		fd.Digest = ds[idx]
	}
	return fd, true
}

// int32s returns every element of an int32 array tag.
func (h header) int32s(tag int32) []uint32 {
	e, ok := h[tag]
	if !ok || e.typ != typeInt32 {
		return nil
	}
	out := make([]uint32, 0, e.count)
	for i := uint32(0); i < e.count && int(i)*4+4 <= len(e.data); i++ {
		out = append(out, binary.BigEndian.Uint32(e.data[i*4:]))
	}
	return out
}
